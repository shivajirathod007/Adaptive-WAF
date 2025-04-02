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
from urllib.parse import urlparse, parse_qs
import time

# Configure logging for proxy with detailed output
logging.basicConfig(
    filename="awaf_proxy.log",
    level=logging.DEBUG,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s, "module": "%(module)s", "line": %(lineno)d}',
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Load IP encoder
try:
    le_ip = joblib.load("ip_encoder.pkl")
    logging.debug('{"event": "ip_encoder_loaded", "status": "success"}')
except Exception as e:
    logging.error('{"event": "ip_encoder_load_failed", "error": "%s"}' % str(e))
    raise

# AWAF API URL
AWAF_API_URL = "http://127.0.0.1:8080/analyze"

# Load manual rules from JSON
try:
    with open("manual_rules.json", "r") as f:
        MANUAL_RULES = json.load(f)
    logging.debug('{"event": "manual_rules_loaded", "rule_count": %d}' % len(MANUAL_RULES))
except FileNotFoundError:
    MANUAL_RULES = []
    logging.warning('{"event": "manual_rules_load_failed", "error": "manual_rules.json not found"}')

# Refined common attack patterns library
COMMON_ATTACK_PATTERNS = {
    "sql_injection": [
        "union select", "1=1", "or 1=1", "drop table", "information_schema",
        "having 1=1", "and 1=1", "or 'a'='a", "exec(", "xp_cmdshell",
        "waitfor delay", "cast(", "convert(", "char(", "nvarchar("
    ],
    "xss": [
        "<script>", "javascript:", "onerror=", "alert(", "onload=",
        "eval(", "<img src=", "document.cookie", "<iframe>", "vbscript:",
        "onmouseover=", "onclick=", "data:", "<svg", "<object"
    ],
    "command_injection": [
        "; rm -rf", "| ls", "& dir", "&& cat", "; whoami",
        "system(", "exec(", "cmd.exe", "/c ping", "| id",
        "bash -c", "sh -c", "powershell", "wget ", "curl "
    ],
    "directory_traversal": [
        "../", "..\\", "/etc/passwd", "\\windows\\system32", "../../",
        "/proc/self", "/root/", "..%2f", "%5c..", "/var/www",
        "/home/", "..%252f", "%00", "/etc/shadow", "\\boot.ini"
    ],
    "csrf": [
        "csrf_token=", "csrf=", "_csrf", "xsrf=", "csrfmiddlewaretoken",
        "anti-csrf", "csrf-token", "X-CSRF-Token", "X-XSRF-Token"
    ],
    "lfi_rfi": [
        "include(", "require(", "file://", "php://", "http://",
        "https://", "ftp://", "data://", "expect://", "input://"
    ],
    "brute_force": [
        "wp-login", "admin/login", "administrator/index", "login.php?attempt=10",
        "user=admin&pass=admin", "test=test&pass=123456", "root&pass=root"
    ]
}

def find_available_port(start_port=8000, end_port=9000):
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                logging.debug('{"event": "port_check", "port": %d, "status": "available"}' % port)
                return port
    logging.error('{"event": "port_search_failed", "range": "%d-%d"}' % (start_port, end_port))
    raise Exception("No available ports found!")

PROXY_PORT = find_available_port()
print(f"[DEBUG] 🚀 Starting mitmproxy on port {PROXY_PORT}...")
logging.info('{"event": "proxy_starting", "port": %d}' % PROXY_PORT)

def ip_to_numeric(ip_str):
    try:
        if isinstance(ip_str, str):
            numeric_ip = le_ip.transform([ip_str])[0].item()
            logging.debug('{"event": "ip_converted", "ip": "%s", "numeric": %d}' % (ip_str, numeric_ip))
            return numeric_ip
        return 0
    except Exception as e:
        logging.warning('{"event": "ip_conversion_error", "ip": "%s", "error": "%s"}' % (ip_str, str(e)))
        return 0

def extract_network_features(flow):
    try:
        is_ddos_simulation = False  # Set to False for real traffic
        if is_ddos_simulation:
            source_ip = "192.168.1.10"
            dest_ip = "192.168.1.1"
            transport_layer = "UDP"
            highest_layer = "ARP"
            source_port = np.random.randint(1024, 65535)
            dest_port = 80
            packet_length = 40
            packets_time = 150.0
        else:
            source_ip = flow.client_conn.address[0] if flow.client_conn.address else "192.168.1.10"
            dest_ip = "192.168.1.1"
            transport_layer = "UDP"
            highest_layer = "ARP"
            source_port = flow.client_conn.address[1] if flow.client_conn.address else 12345
            dest_port = 0
            packet_length = 60
            packets_time = 10.0

        features = {
            "highest_layer": highest_layer,
            "transport_layer": transport_layer,
            "source_ip": ip_to_numeric(source_ip),
            "dest_ip": ip_to_numeric(dest_ip),
            "source_port": source_port,
            "dest_port": dest_port,
            "packet_length": packet_length,
            "packets_time": packets_time
        }
        logging.debug('{"event": "network_features_extracted", "features": %s}' % json.dumps(features))
        return features
    except Exception as e:
        logging.error('{"event": "network_features_error", "error": "%s"}' % str(e))
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
    start_time = time.time()
    request = flow.request
    body = request.get_text() if request.get_text() else ""
    headers = dict(request.headers)
    parsed_url = urlparse(request.url)
    query_params = dict(parse_qs(parsed_url.query)) if parsed_url.query else {}
    domain = parsed_url.hostname or "unknown"

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
        "query_params": query_params,
        "user_agent": headers.get("User-Agent", "Unknown"),
        "referrer": headers.get("Referer", "Unknown"),
        "domain": domain,
        "source_ip": flow.client_conn.address[0] if flow.client_conn.address else "Unknown",
        "source_port": flow.client_conn.address[1] if flow.client_conn.address else 0,
        "dest_port": parsed_url.port if parsed_url.port else 80
    }
    
    network_data = extract_network_features(flow)
    request_data.update(network_data)
    
    for key, value in request_data.items():
        if isinstance(value, np.integer):
            request_data[key] = int(value)
    
    elapsed_time = time.time() - start_time
    logging.debug('{"event": "request_features_extracted", "url": "%s", "features": %s, "time_taken": %.3f}' % (request.url, json.dumps(request_data), elapsed_time))
    print(f"[DEBUG] 🔍 Extracted Features: {json.dumps(request_data, indent=2)}")
    return request_data

def check_manual_rules(request_data):
    for rule in MANUAL_RULES:
        rule_type = rule.get("type")
        if rule_type == "ip-block" and request_data["source_ip"] == rule["ip"]:
            return True, f"IP {rule['ip']} blocked by manual rule (ID: {rule['id']})"
        elif rule_type == "rate-limit" and request_data["packets_time"] > rule["requestsPerSecond"]:
            return True, f"Rate limit exceeded: {request_data['packets_time']} > {rule['requestsPerSecond']} (ID: {rule['id']})"
        elif rule_type == "geo-block":
            logging.debug('{"event": "geo_block_skipped", "reason": "geo_lookup_not_implemented"}')
        elif rule_type == "http-method" and request_data["method"] == rule["method"] and rule["action"] == "block":
            return True, f"HTTP method {rule['method']} blocked by manual rule (ID: {rule['id']})"
        elif rule_type == "port-block" and request_data["dest_port"] == rule["port"]:
            return True, f"Port {rule['port']} blocked by manual rule (ID: {rule['id']})"
        elif rule_type == "domain-block" and request_data["domain"] == rule["domain"]:
            return True, f"Domain {rule['domain']} blocked by manual rule (ID: {rule['id']})"
    return False, ""

def check_common_attack_patterns(request_data):
    body = request_data["body"].lower()
    path = request_data["path"].lower()
    combined = (body + " " + path).strip()

    for attack_type, patterns in COMMON_ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in combined:
                logging.info('{"event": "attack_pattern_match", "type": "%s", "pattern": "%s", "content": "%s"}' % (attack_type, pattern, combined[:100]))
                return True, f"Blocked due to {attack_type} pattern: '{pattern}'"
    return False, ""

def request(flow: mitmproxy.http.HTTPFlow):
    try:
        start_time = time.time()
        print(f"[DEBUG] 📥 Intercepted Request: {flow.request.url}")
        logging.info('{"event": "request_intercepted", "url": "%s"}' % flow.request.url)
        
        request_data = extract_request_features(flow)

        # Step 1: Check manual rules
        is_blocked, reason = check_manual_rules(request_data)
        if is_blocked:
            print(f"[DEBUG] 🚨 {reason}")
            logging.info('{"event": "request_blocked", "url": "%s", "reason": "%s"}' % (flow.request.url, reason))
            flow.response = mitmproxy.http.Response.make(
                403, b"403 Forbidden - Blocked by Manual Rule",
                {"Content-Type": "text/plain"}
            )
            return

        # Step 2: Check common attack patterns  
        is_blocked, reason = check_common_attack_patterns(request_data)
        if is_blocked:
            print(f"[DEBUG] 🚨 {reason}")
            logging.info('{"event": "request_blocked", "url": "%s", "reason": "%s"}' % (flow.request.url, reason))
            flow.response = mitmproxy.http.Response.make(
                403, b"403 Forbidden - Blocked by Common Attack Pattern",
                {"Content-Type": "text/plain"}
            )
            return

        # Step 3: Forward to AWAF for analysis
        print("[DEBUG] 🚀 Sending request to AWAF API...")
        logging.debug('{"event": "sending_to_awaf", "url": "%s", "data": %s}' % (flow.request.url, json.dumps(request_data)))
        response = requests.post(AWAF_API_URL, json=request_data, timeout=5)
        
        try:
            awaf_decision = response.json()
            print(f"[DEBUG] 🎯 Response from AWAF: {json.dumps(awaf_decision, indent=2)}")
            logging.debug('{"event": "awaf_response", "decision": %s}' % json.dumps(awaf_decision))
        except json.JSONDecodeError:
            print("[DEBUG] ⚠️ Invalid JSON response from AWAF, defaulting to allow.")
            logging.error('{"event": "awaf_response_error", "url": "%s", "error": "Invalid JSON response"}' % flow.request.url)
            awaf_decision = {"status": "Allowed", "response_time": 0.0}

        if response.status_code == 403 or (isinstance(awaf_decision, dict) and awaf_decision.get("status") == "Blocked"):
            print("[DEBUG] 🚨 Malicious request blocked by AWAF!")
            logging.info('{"event": "request_blocked", "url": "%s", "reason": "malicious"}' % flow.request.url)
            flow.response = mitmproxy.http.Response.make(
                403, b"403 Forbidden - Request Blocked by AWAF",
                {"Content-Type": "text/plain"}
            )
        else:
            elapsed_time = time.time() - start_time
            print("[DEBUG] ✅ Request allowed, forwarding to target server...")
            logging.info('{"event": "request_allowed", "url": "%s", "response_time": %.3f}' % (flow.request.url, elapsed_time))
    except Exception as e:
        elapsed_time = time.time() - start_time
        error_msg = '{"event": "request_processing_error", "url": "%s", "error": "%s", "time_taken": %.3f}' % (flow.request.url, str(e), elapsed_time)
        logging.error(error_msg)
        print(f"[DEBUG] ❌ Error processing request: {str(e)}")
        flow.response = mitmproxy.http.Response.make(
            500, b"500 Internal Server Error - AWAF Proxy Error",
            {"Content-Type": "text/plain"}
        )

def start_mitmproxy():
    cmd = f"mitmdump -p {PROXY_PORT} -s proxy.py"
    print(f"[DEBUG] 🚀 Starting mitmproxy with command: {cmd}")
    logging.info('{"event": "mitmproxy_started", "port": %d, "command": "%s"}' % (PROXY_PORT, cmd))
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    start_mitmproxy()