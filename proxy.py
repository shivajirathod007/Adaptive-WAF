import json
import mitmproxy.http
import requests
import subprocess
import socket
from mitmproxy import ctx
import logging
import numpy as np
from scapy.all import IP, UDP, TCP, ARP
import joblib

# Configure logging for proxy
logging.basicConfig(
    filename="awaf_proxy.log",
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Load IP encoder (ensure ip_encoder.pkl is in the same directory)
le_ip = joblib.load("ip_encoder.pkl")

# AWAF API URL
AWAF_API_URL = "http://127.0.0.1:8080/analyze"

# Function to find an available port for mitmproxy
def find_available_port(start_port=8000, end_port=9000):
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise Exception("No available ports found!")

PROXY_PORT = find_available_port()
print(f"[DEBUG] 🚀 Starting mitmproxy on port {PROXY_PORT}...")

def ip_to_numeric(ip_str):
    """Convert IP address string (e.g., '192.168.1.10') to a numerical value using LabelEncoder."""
    try:
        if isinstance(ip_str, str):
            return le_ip.transform([ip_str])[0].item()  # Convert numpy.int32 to Python int
        return 0  # Default for invalid IPs
    except Exception as e:
        print(f"[DEBUG] ⚠️ Error converting IP {ip_str}: {str(e)}")
        ctx.log.warning('{"event": "ip_conversion_error", "ip": "%s", "error": "%s"}' % (ip_str, str(e)))
        return 0

def extract_network_features(flow):
    """
    Extracts network-level features for DDoS detection.
    Simulates DDoS traffic with high packets_time for testing.
    """
    try:
        # Simulate or use defaults—replace with actual packet data for real-time detection
        is_ddos_simulation = True  # Flag to simulate DDoS for testing
        if is_ddos_simulation:
            source_ip = "192.168.1.10"  # Default
            dest_ip = "192.168.1.1"     # Default
            transport_layer = "UDP"     # Common in DDoS
            highest_layer = "ARP"       # Default
            source_port = np.random.randint(1024, 65535)  # Random port for DDoS
            dest_port = 80              # Target port (e.g., HTTP)
            packet_length = 40          # Small packet for UDP flood
            packets_time = 150.0        # High packets/second for DDoS simulation
        else:
            # Fallback to default values if not simulating DDoS
            source_ip = "192.168.1.10"
            dest_ip = "192.168.1.1"
            transport_layer = "UDP"
            highest_layer = "ARP"
            source_port = 12345
            dest_port = 0
            packet_length = 60
            packets_time = 10.0

        return {
            "highest_layer": highest_layer,
            "transport_layer": transport_layer,
            "source_ip": ip_to_numeric(source_ip),  # Convert to numerical
            "dest_ip": ip_to_numeric(dest_ip),      # Convert to numerical
            "source_port": source_port,
            "dest_port": dest_port,
            "packet_length": packet_length,
            "packets_time": packets_time
        }
    except Exception as e:
        print(f"[DEBUG] ❌ Error extracting network features: {str(e)}")
        ctx.log.error('{"event": "network_features_error", "error": "%s"}' % str(e))
        return {
            "highest_layer": "ARP",
            "transport_layer": "UDP",
            "source_ip": ip_to_numeric("192.168.1.10"),
            "dest_ip": ip_to_numeric("192.168.1.1"),
            "source_port": 0,
            "dest_port": 0,
            "packet_length": 60,
            "packets_time": 10.0
        }

def extract_request_features(flow: mitmproxy.http.HTTPFlow):
    """
    Extracts relevant request features for analysis, handling both normal and attack requests.
    """
    request = flow.request
    body = request.get_text() if request.get_text() else ""
    headers = dict(request.headers)

    # Parse query parameters from URL
    from urllib.parse import urlparse, parse_qs
    parsed_url = urlparse(request.url)
    query_params = parse_qs(parsed_url.query) if parsed_url.query else {}

    request_data = {
        "method": request.method,
        "path": request.path,
        "body": body,
        "header_count": len(headers),
        "url_length": len(request.url),
        "body_length": len(body) if body else 0,
        "single_q": body.count("'") if body else 0,
        "double_q": body.count('"') if body else 0,
        "dashes": body.count("--") if body else 0,
        "braces": body.count("{}") if body else 0,
        "spaces": body.count(" ") if body else 0,
        "sql_injection_count": (body.lower().count("union") + body.lower().count("select")) if body else 0,
        "xss_attack_count": body.lower().count("<script>") if body else 0,
        "command_injection_count": body.count("|") if body else 0,
        "directory_traversal_count": body.count("../") if body else 0,
        "csrf_count": body.lower().count("csrf") if body else 0,
        "query_params": query_params,  # Add query parameters
        "user_agent": headers.get("User-Agent", "Unknown"),  # Add User-Agent
        "referrer": headers.get("Referer", "Unknown")  # Add Referrer
    }
    
    # Add network features for DDoS
    network_data = extract_network_features(flow)
    request_data.update(network_data)
    
    # Ensure all values are JSON-serializable (convert numpy.int32 to int)
    for key, value in request_data.items():
        if isinstance(value, np.integer):
            request_data[key] = int(value)
    
    print(f"[DEBUG] 🔍 Extracted Features: {json.dumps(request_data, indent=2)}")
    ctx.log.info('{"event": "features_extracted", "features": %s}' % json.dumps(request_data))
    return request_data

def request(flow: mitmproxy.http.HTTPFlow):
    """
    Intercepts and analyzes incoming HTTP requests, forwarding to AWAF.
    """
    try:
        print(f"[DEBUG] 📥 Intercepted Request: {flow.request.url}")
        ctx.log.info('{"event": "request_intercepted", "url": "%s"}' % flow.request.url)
        request_data = extract_request_features(flow)

        print("[DEBUG] 🚀 Sending request to AWAF API...")
        ctx.log.info('{"event": "sending_to_awaf", "url": "%s"}' % flow.request.url)
        response = requests.post(AWAF_API_URL, json=request_data, timeout=5)
        
        try:
            awaf_decision = response.json()
            print(f"[DEBUG] 🎯 Response from AWAF: {json.dumps(awaf_decision, indent=2)}")
            ctx.log.info('{"event": "awaf_response", "decision": %s}' % json.dumps(awaf_decision))
        except json.JSONDecodeError:
            print("[DEBUG] ⚠️ Invalid JSON response from AWAF, defaulting to allow.")
            ctx.log.error('{"event": "awaf_response_error", "url": "%s", "error": "Invalid JSON response"}' % flow.request.url)
            awaf_decision = {"status": "Allowed", "response_time": 0.0}

        if response.status_code == 403 or (isinstance(awaf_decision, dict) and awaf_decision.get("status") == "Blocked"):
            print("[DEBUG] 🚨 Malicious request blocked!")
            ctx.log.info('{"event": "request_blocked", "url": "%s", "reason": "malicious"}' % flow.request.url)
            flow.response = mitmproxy.http.Response.make(
                403, b"403 Forbidden - Request Blocked by AWAF",
                {"Content-Type": "text/plain"}
            )
        else:
            print("[DEBUG] ✅ Request allowed, forwarding to target server...")
            ctx.log.info('{"event": "request_allowed", "url": "%s", "response_time": %f}' % (flow.request.url, awaf_decision.get("response_time", 0.0)))
    except Exception as e:
        error_msg = '{"event": "request_processing_error", "url": "%s", "error": "%s"}' % (flow.request.url, str(e))
        logging.error(error_msg)  # Now logging is imported
        print(f"[DEBUG] ❌ Error processing request: {str(e)}")
        flow.response = mitmproxy.http.Response.make(
            500, b"500 Internal Server Error - AWAF Proxy Error",
            {"Content-Type": "text/plain"}
        )

def start_mitmproxy():
    """Start mitmproxy as a subprocess."""
    cmd = f"mitmdump -p {PROXY_PORT} -s proxy.py"
    print(f"[DEBUG] 🚀 Starting mitmproxy with command: {cmd}")
    ctx.log.info('{"event": "mitmproxy_started", "port": %d}' % PROXY_PORT)
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    start_mitmproxy()