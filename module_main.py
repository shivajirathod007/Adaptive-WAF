import numpy as np
import json
import time
import logging
import joblib
import os
import pandas as pd
import threading
from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
from datetime import datetime

# Configure logging for dashboard integration (JSON-like format)
logging.basicConfig(
    filename="awaf_proxy.log",
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Dashboard JSON log file
DASHBOARD_LOG_FILE = "awaf_dashboard.json"

# Load models and encoders safely
try:
    autoencoder = load_model("my_model.keras")  # Anomaly Detection (numerical features)
    ml_model = load_model("lstm_model_common_attack.keras")  # SQLi/XSS Detection
    ddos_model = load_model("ddos_lstm_model.keras")  # DDoS Detection
    scaler_anomaly = joblib.load("autoencoder_scaler.pkl")
    scaler_ml = joblib.load("ml_scaler.pkl")
    scaler_ddos = joblib.load("ddos_scaler.pkl")
    le_method_anomaly = joblib.load("AL_method_encoder.pkl")
    le_path_anomaly = joblib.load("AL_path_encoder.pkl")
    le_body_anomaly = joblib.load("AL_body_encoder.pkl")
    le_method_ml = joblib.load("ML_method_encoder.pkl")
    le_path_ml = joblib.load("ML_path_encoder.pkl")
    le_body_ml = joblib.load("ML_body_encoder.pkl")
    le_highest = joblib.load("highest_layer_encoder.pkl")
    le_transport = joblib.load("transport_layer_encoder.pkl")
    le_ip = joblib.load("ip_encoder.pkl")
    anomaly_threshold = joblib.load("anomaly_threshold.pkl")
    ddos_threshold = 0.2

    print("\n[DEBUG] ✅ Models & Encoders loaded successfully.")
    print(f"[DEBUG] Anomaly Threshold: {anomaly_threshold}")
    print(f"[DEBUG] DDoS Threshold: {ddos_threshold}")
    print("Expected Input Shapes:")
    print("Anomaly Model:", autoencoder.input_shape)  # (None, 13)
    print("ML Model:", ml_model.input_shape)         # (None, 10, 19)
    print("DDoS Model:", ddos_model.input_shape)     # (None, 10, 8)
    logging.info('{"event": "models_loaded", "status": "success", "anomaly_threshold": %f, "ddos_threshold": %f}' % (anomaly_threshold, ddos_threshold))
except Exception as e:
    error_msg = '{"event": "models_load_failed", "error": "%s"}' % str(e)
    logging.error(error_msg)
    print(f"\n[DEBUG] ❌ Error loading models: {str(e)}\n")
    exit(1)

app = Flask(__name__)

FEATURES_ANOMALY_SIZE = autoencoder.input_shape[1]  # 13
FEATURES_ML_SIZE = ml_model.input_shape[2]         # 19
FEATURES_DDOS_SIZE = ddos_model.input_shape[2]     # 8
TIME_STEPS = 10

ANOMALY_THRESHOLD = float(anomaly_threshold)
ML_THRESHOLD = 0.998
DDOS_THRESHOLD = ddos_threshold

# Locks for thread safety
anomaly_lock = threading.Lock()
ml_lock = threading.Lock()
ddos_lock = threading.Lock()

# CSV files for self-learning data collection
ANOMALY_CSV = "anomaly_data.csv"
ML_CSV = "ml_data.csv"
DDOS_CSV = "ddos_data.csv"

def handle_unseen_labels(encoder, value, default="unknown"):
    """Handle unseen labels in LabelEncoder by returning a default value (0)."""
    try:
        return encoder.transform([value])[0]
    except ValueError:
        print(f"[DEBUG] ⚠️ Unseen label '{value}' in encoder, using default 0.")
        logging.warning('{"event": "unseen_label", "encoder": "%s", "value": "%s", "default": 0}' % (encoder.__class__.__name__, value))
        return 0

def ip_to_numeric(ip_str):
    """Convert IP address string to a numerical value using LabelEncoder."""
    try:
        if isinstance(ip_str, str):
            return le_ip.transform([ip_str])[0].item()
        return 0
    except Exception as e:
        print(f"[DEBUG] ⚠️ Error converting IP {ip_str}: {str(e)}")
        logging.warning('{"event": "ip_conversion_error", "ip": "%s", "error": "%s"}' % (ip_str, str(e)))
        return 0

def save_to_csv(data, filepath, headers, label=None):
    """Append data to CSV file with optional label."""
    if label is not None:
        data.append(label)
        headers.append("label")
    df = pd.DataFrame([data], columns=headers)
    if not os.path.isfile(filepath):
        df.to_csv(filepath, index=False)
    else:
        df.to_csv(filepath, mode='a', header=False, index=False)

def preprocess_request(data, feature_size, time_steps, model_type):
    """Preprocess request data and return both processed array and raw features."""
    try:
        body_text = data.get("body", "").strip()
        print(f"[DEBUG] 📌 Processing {model_type} - Body Text: '{body_text}'")

        if model_type == "anomaly":
            features = [
                handle_unseen_labels(le_method_anomaly, data.get("method", "GET")),
                handle_unseen_labels(le_path_anomaly, data.get("path", "/")),
                data.get("url_length", 0), data.get("body_length", 0),
                data.get("path_entropy", 0), data.get("body_entropy", 0),
                data.get("header_count", 0), data.get("sql_injection_count", 0),
                data.get("xss_attack_count", 0), data.get("command_injection_count", 0),
                data.get("directory_traversal_count", 0), data.get("csrf_count", 0),
                data.get("base64_count", 0)
            ]
            final_array = scaler_anomaly.transform([features]).astype(np.float32)
            final_array = final_array.reshape(1, feature_size)
            headers = ["method", "path", "url_length", "body_length", "path_entropy", 
                       "body_entropy", "header_count", "sql_injection_count", 
                       "xss_attack_count", "command_injection_count", 
                       "directory_traversal_count", "csrf_count", "base64_count"]
        elif model_type == "ml":
            features = [
                handle_unseen_labels(le_method_ml, data.get("method", "GET")),
                handle_unseen_labels(le_path_ml, data.get("path", "/")),
                data.get("url_length", 0), data.get("body_length", 0),
                data.get("single_q", 0), data.get("double_q", 0), data.get("dashes", 0),
                data.get("braces", 0), data.get("spaces", 0), data.get("path_entropy", 0),
                data.get("body_entropy", 0), data.get("base64_count", 0),
                data.get("header_count", 0), data.get("sql_injection_count", 0),
                data.get("xss_attack_count", 0), data.get("command_injection_count", 0),
                data.get("directory_traversal_count", 0), data.get("csrf_count", 0),
                handle_unseen_labels(le_body_ml, body_text)
            ]
            final_array = scaler_ml.transform([features]).astype(np.float32)
            final_array = np.tile(final_array, (time_steps, 1)).reshape(1, time_steps, feature_size)
            headers = ["method", "path", "url_length", "body_length", "single_q", "double_q", 
                       "dashes", "braces", "spaces", "path_entropy", "body_entropy", 
                       "base64_count", "header_count", "sql_injection_count", "xss_attack_count", 
                       "command_injection_count", "directory_traversal_count", "csrf_count", "body"]
        elif model_type == "ddos":
            features = [
                handle_unseen_labels(le_highest, data.get("highest_layer", "ARP")),
                handle_unseen_labels(le_transport, data.get("transport_layer", "UDP")),
                ip_to_numeric(data.get("source_ip", "192.168.1.10")),
                ip_to_numeric(data.get("dest_ip", "192.168.1.1")),
                data.get("source_port", 0), data.get("dest_port", 0),
                data.get("packet_length", 60), data.get("packets_time", 10.0)
            ]
            final_array = scaler_ddos.transform([features]).astype(np.float32)
            final_array = np.tile(final_array, (time_steps, 1)).reshape(1, time_steps, feature_size)
            headers = ["highest_layer", "transport_layer", "source_ip", "dest_ip", 
                       "source_port", "dest_port", "packet_length", "packets_time"]
        else:
            raise ValueError(f"Unknown model type: {model_type}")

        print(f"[DEBUG] Final {model_type} Data Shape: {final_array.shape}")
        logging.info('{"event": "preprocess_request", "model_type": "%s", "features": %s, "shape": %s}' % (model_type, str(features), str(final_array.shape)))
        return final_array, features, headers
    except Exception as e:
        error_msg = '{"event": "preprocess_error", "model_type": "%s", "error": "%s"}' % (model_type, str(e))
        logging.error(error_msg)
        print(f"[DEBUG] ❌ ERROR in {model_type} feature extraction: {str(e)}")
        return None, None, None

def retrain_model(model_type):
    """Retrain the specified model using collected data."""
    try:
        if model_type == "anomaly" and os.path.isfile(ANOMALY_CSV):
            df = pd.read_csv(ANOMALY_CSV)
            if len(df) >= 1000:
                X = scaler_anomaly.transform(df.values)
                with anomaly_lock:
                    autoencoder.fit(X, X, epochs=5, batch_size=32, verbose=0)
                logging.info(f'{{"event": "retrain_success", "model": "anomaly", "samples": {len(df)}}}')
        
        elif model_type == "ml" and os.path.isfile(ML_CSV):
            df = pd.read_csv(ML_CSV)
            if len(df) >= 1000 and df['label'].nunique() == 2:
                X = scaler_ml.transform(df.iloc[:, :-1].values)
                y = df['label'].values
                X_sequences = np.tile(X[:, np.newaxis, :], (1, TIME_STEPS, 1))
                with ml_lock:
                    ml_model.fit(X_sequences, y, epochs=5, batch_size=32, verbose=0)
                logging.info(f'{{"event": "retrain_success", "model": "ml", "samples": {len(df)}}}')
        
        elif model_type == "ddos" and os.path.isfile(DDOS_CSV):
            df = pd.read_csv(DDOS_CSV)
            if len(df) >= 1000 and df['label'].nunique() == 2:
                X = scaler_ddos.transform(df.iloc[:, :-1].values)
                y = df['label'].values
                X_sequences = np.tile(X[:, np.newaxis, :], (1, TIME_STEPS, 1))
                with ddos_lock:
                    ddos_model.fit(X_sequences, y, epochs=5, batch_size=32, verbose=0)
                logging.info(f'{{"event": "retrain_success", "model": "ddos", "samples": {len(df)}}}')
    except Exception as e:
        logging.error(f'{{"event": "retrain_error", "model": "{model_type}", "error": "{str(e)}"}}')

def schedule_retraining():
    """Schedule retraining every 24 hours."""
    while True:
        time.sleep(24 * 60 * 60)  # 24 hours
        retrain_model("anomaly")
        retrain_model("ml")
        retrain_model("ddos")

# Start retraining thread
threading.Thread(target=schedule_retraining, daemon=True).start()

def detect_attack(request_data):
    """Detect attacks and collect data for self-learning."""
    try:
        start_time = time.time()
        print("\n[DEBUG] 📥 Processing request:", json.dumps(request_data, indent=2))

        # Preprocess and extract features
        anomaly_data, anomaly_features, anomaly_headers = preprocess_request(request_data, FEATURES_ANOMALY_SIZE, 1, "anomaly")
        ml_data, ml_features, ml_headers = preprocess_request(request_data, FEATURES_ML_SIZE, TIME_STEPS, "ml")
        ddos_data, ddos_features, ddos_headers = preprocess_request(request_data, FEATURES_DDOS_SIZE, TIME_STEPS, "ddos")

        if anomaly_data is None or ml_data is None or ddos_data is None:
            raise ValueError("Feature extraction failed for anomaly, ML, or DDoS models.")

        # Predict with thread safety
        with anomaly_lock:
            anomaly_pred = autoencoder.predict(anomaly_data, verbose=0)
        with ml_lock:
            ml_pred = ml_model.predict(ml_data, verbose=0)
        with ddos_lock:
            ddos_pred = ddos_model.predict(ddos_data, verbose=0)

        anomaly_score = np.mean(np.abs(anomaly_data - anomaly_pred))
        ddos_prediction = ddos_pred[0][0] if ddos_pred is not None else 0.0
        attack_probs = ml_pred[0] if ml_pred is not None else [0.0]
        ml_max_prob = max(attack_probs)

        is_anomaly = anomaly_score > ANOMALY_THRESHOLD
        is_attack = ml_max_prob > ML_THRESHOLD
        is_ddos = ddos_prediction > DDOS_THRESHOLD

        # Collect data for self-learning
        if not is_anomaly:  # Only normal requests for anomaly model
            save_to_csv(anomaly_features, ANOMALY_CSV, anomaly_headers)
        save_to_csv(ml_features, ML_CSV, ml_headers, label=int(is_attack))
        save_to_csv(ddos_features, DDOS_CSV, ddos_headers, label=int(is_ddos))

        # Rest of the original detection logic remains unchanged
        anomaly_features = [
            request_data.get("url_length", 0),
            request_data.get("body_length", 0),
            request_data.get("single_q", 0),
            request_data.get("double_q", 0),
            request_data.get("dashes", 0),
            request_data.get("braces", 0),
            request_data.get("spaces", 0),
            request_data.get("sql_injection_count", 0),
            request_data.get("xss_attack_count", 0),
            request_data.get("command_injection_count", 0),
            request_data.get("directory_traversal_count", 0),
            request_data.get("csrf_count", 0)
        ]
        feature_contributions = {f"feature_{i}": float(val) for i, val in enumerate(anomaly_features)}

        print(f"[DEBUG] Anomaly Score Check: {anomaly_score} > {ANOMALY_THRESHOLD} = {is_anomaly}")
        print(f"[DEBUG] ML Prob Check: {ml_max_prob} > {ML_THRESHOLD} = {is_attack}")
        print(f"[DEBUG] DDoS Prob Check: {ddos_prediction} > {DDOS_THRESHOLD} = {is_ddos}")

        response_time = time.time() - start_time
        timestamp = datetime.now().isoformat()
        source_ip = request_data.get("source_ip", "Unknown")
        dest_ip = request_data.get("dest_ip", "Unknown")
        source_port = request_data.get("source_port", 0)
        dest_port = request_data.get("dest_port", 0)
        method = request_data.get("method", "GET")
        path = request_data.get("path", "/")
        query_params = request_data.get("query_params", {})
        user_agent = request_data.get("user_agent", "Unknown")
        referrer = request_data.get("referrer", "Unknown")

        total_requests = 1
        rps = 1.0
        pps = request_data.get("packets_time", 0.0)
        packet_length = request_data.get("packet_length", 60)
        traffic_volume = pps * packet_length

        attack_class = "None"
        if is_attack:
            if request_data.get("sql_injection_count", 0) > 0:
                attack_class = "SQLi"
            elif request_data.get("xss_attack_count", 0) > 0:
                attack_class = "XSS"
            elif request_data.get("directory_traversal_count", 0) > 0:
                attack_class = "Directory Traversal"
            elif request_data.get("command_injection_count", 0) > 0:
                attack_class = "Command Injection"
            elif request_data.get("csrf_count", 0) > 0:
                attack_class = "CSRF"
        elif is_ddos:
            attack_class = "DDoS"

        dashboard_log = {
            "general_request_data": {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "source_port": source_port,
                "dest_port": dest_port,
                "request_method": method,
                "requested_path": path,
                "query_params": query_params,
                "user_agent": user_agent,
                "referrer": referrer,
                "http_status": 403 if (is_anomaly and is_attack) or is_ddos else 200
            },
            "traffic_ddos_monitoring": {
                "total_requests_per_second": rps,
                "packets_per_second": pps,
                "packet_length": packet_length,
                "traffic_volume_bytes_per_second": traffic_volume,
                "unique_ips": [source_ip],
                "flagged_ddos_attacks": int(is_ddos)
            },
            "anomaly_detection_metrics": {
                "path_entropy": request_data.get("path_entropy", 0),
                "body_entropy": request_data.get("body_entropy", 0),
                "url_length": request_data.get("url_length", 0),
                "body_length": request_data.get("body_length", 0),
                "single_quotes_count": request_data.get("single_q", 0),
                "double_quotes_count": request_data.get("double_q", 0),
                "dashes_count": request_data.get("dashes", 0),
                "braces_count": request_data.get("braces", 0),
                "spaces_count": request_data.get("spaces", 0),
                "sql_injection_patterns": request_data.get("sql_injection_count", 0),
                "xss_patterns": request_data.get("xss_attack_count", 0),
                "directory_traversal_attempts": request_data.get("directory_traversal_count", 0),
                "command_injection_count": request_data.get("command_injection_count", 0),
                "csrf_count": request_data.get("csrf_count", 0)
            },
            "ml_attack_detection": {
                "attack_class": attack_class,
                "ml_confidence_score": float(ml_max_prob),
                "anomaly_score": float(anomaly_score),
                "feature_contributions": feature_contributions
            },
            "log_performance_insights": {
                "total_requests_handled": total_requests,
                "normal_requests": int(not (is_anomaly or is_attack or is_ddos)),
                "malicious_requests": int(is_anomaly or is_attack or is_ddos),
                "attack_detection_accuracy": None,
                "average_processing_time": response_time,
                "most_frequent_attack_patterns": [attack_class] if attack_class != "None" else []
            }
        }

        save_to_json_dashboard(dashboard_log)

        result = {
            "anomaly_detected": int(is_anomaly),
            "attack_detected": int(is_attack),
            "ddos_detected": int(is_ddos),
            "response_time": response_time,
            "anomaly_score": float(anomaly_score),
            "ml_max_prob": float(ml_max_prob),
            "ddos_prob": float(ddos_prediction)
        }

        print(f"[DEBUG] 🔍 Detection Result: {result}")
        logging.info('{"event": "detection_result", "request": %s, "result": %s}' % (json.dumps(request_data), json.dumps(result)))

        if (is_anomaly and is_attack) or is_ddos:
            print("[DEBUG] 🚨 Request blocked due to anomaly, attack, or DDoS detection.")
            logging.info('{"event": "request_blocked", "reason": "anomaly" if is_anomaly else "attack" if is_attack else "ddos"}')
            return jsonify({"error": "Blocked", "status": "Blocked"}), 403
        else:
            print("[DEBUG] ✅ Request allowed.")
            logging.info('{"event": "request_allowed", "response_time": %f}' % response_time)
            return jsonify({"status": "Allowed", "response_time": response_time}), 200
    except Exception as e:
        error_msg = '{"event": "detection_error", "error": "%s", "request": %s}' % (str(e), json.dumps(request_data, default=str))
        logging.error(error_msg)
        print(f"[DEBUG] ❌ Error during attack detection: {str(e)}")
        return jsonify({"error": f"Internal processing error: {str(e)}"}), 500

def save_to_json_dashboard(log_entry):
    """Save a log entry to a JSON file for dashboard use."""
    try:
        try:
            with open(DASHBOARD_LOG_FILE, 'r') as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []
        logs.append(log_entry)
        with open(DASHBOARD_LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"[DEBUG] ❌ Error saving to dashboard JSON: {str(e)}")
        logging.error('{"event": "dashboard_log_error", "error": "%s"}' % str(e))

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze incoming requests."""
    try:
        request_data = request.json
        print("\n[DEBUG] 📥 Incoming Request Data to WAF:")
        print(json.dumps(request_data, indent=2, default=str))
        logging.info('{"event": "incoming_request", "data": %s}' % json.dumps(request_data, default=str))
        response, status_code = detect_attack(request_data)
        return response, status_code
    except Exception as e:
        error_msg = '{"event": "analyze_error", "error": "%s"}' % str(e)
        logging.error(error_msg)
        print(f"[DEBUG] ❌ Internal Server Error: {str(e)}")
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    print("\n[DEBUG] 🚀 Starting AWAF on port 8080...\n")
    logging.info('{"event": "awaf_started", "port": 8080}')
    app.run(host="0.0.0.0", port=8080, debug=False)