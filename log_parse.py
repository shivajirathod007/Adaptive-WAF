import base64
import csv
import math
from urllib.parse import unquote_plus
from xml.etree import ElementTree as ET

# Define log paths
log_path = 'Bad_CRSF_burp_demo.log'
output_csv_log = 'httpbad_CRSF_log.csv'

# Define bad words and attack patterns
BADWORDS = [
    'sleep', 'drop', 'uid', 'select', 'waitfor', 'delay', 'system', 'union',
    'order by', 'group by', 'insert', 'update', 'exec', 'char', 'or', 'and',
    'having', 'into outfile', 'xp_cmdshell', 'isnull', 'substring', 'declare',
    'cast', 'ascii', 'from', 'concat', 'set', 'benchmark', 'eval', 'base64',
    'load_file', 'load_xml', 'drop table', 'create table'
]

XSS_PATTERNS = [
    "<script>", "</script>", "<img src=", "<iframe src=", "<svg onload=",
    "alert(", "prompt(", "document.cookie", "window.location=", "javascript:",
    "data:", "%3C", "%3E", "%22", "%27", "%3B", "%28", "%29", "<", ">"
]

COMMAND_INJECTION_PATTERNS = [
    'system(', 'exec(', 'shell_exec(', 'popen(', 'passthru(', 'proc_open(',
    'eval(', 'chmod', 'curl', 'wget', 'nc', 'cmd', 'powershell'
]

FILE_INCLUSION_PATTERNS = [
    '../../', 'php://', 'file://', 'ftp://', '/etc/passwd', '/proc/self/environ',
    'index.php?page=', 'file=../../'
]

CSRF_PATTERNS = [
    "Referer", "Origin"
]

class LogParser:
    def calculate_entropy(self, text):
        """Calculate the entropy of a given string."""
        if not text:
            return 0
        probability = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log2(p) for p in probability])

    def extract_features(self, method, path, body, headers):
        """Extract features from HTTP request data."""
        badwords_count = 0
        xss_count = 0
        sql_injection_count = 0
        command_injection_count = 0
        directory_traversal_count = 0
        csrf_count = 0

        # Decode path and body
        path = unquote_plus(path)
        body = unquote_plus(body)

        # Feature calculations
        single_q = path.count("'") + body.count("'")
        double_q = path.count('"') + body.count('"')
        dashes = path.count('--') + body.count('--')
        braces = path.count('(') + body.count(')')
        spaces = path.count(' ') + body.count(' ')
        url_length = len(path)
        body_length = len(body)
        try:
            base64_count = 1 if base64.b64encode(base64.b64decode(
                body, validate=True)).decode('utf-8', 'ignore') == body else 0
        except Exception:
            base64_count = 0

        # Check for bad words
        for word in BADWORDS:
            sql_injection_count += path.lower().count(word) + body.lower().count(word)

        # Check for XSS patterns
        for pattern in XSS_PATTERNS:
            xss_count += path.lower().count(pattern) + body.lower().count(pattern)

        # Check for command injection patterns
        for pattern in COMMAND_INJECTION_PATTERNS:
            command_injection_count += path.lower().count(pattern) + body.lower().count(pattern)

        # Check for directory traversal patterns
        for pattern in FILE_INCLUSION_PATTERNS:
            directory_traversal_count += path.lower().count(pattern) + body.lower().count(pattern)

        # Check for CSRF patterns in headers
        for pattern in CSRF_PATTERNS:
            csrf_count += sum(1 for key in headers if pattern.lower() in key.lower())

        # Entropy calculation
        path_entropy = self.calculate_entropy(path)
        body_entropy = self.calculate_entropy(body)

        # Header analysis
        header_count = len(headers)

        # Label assignment based on thresholds
        # If any feature exceeds the threshold, classify as malicious (1)
        if (single_q > 1 or sql_injection_count > 0 or xss_count > 0 or
            command_injection_count > 0 or directory_traversal_count > 0 or csrf_count > 0):
            label = 1  # Malicious
        else:
            label = 0  # Normal

        return [
            method, path, body, single_q, double_q, dashes, braces, spaces, url_length,
            body_length, base64_count, path_entropy, body_entropy, header_count,
            sql_injection_count, xss_count, command_injection_count,
            directory_traversal_count, csrf_count, label
        ]

    def parse_log(self, log_path):
        """Parse the XML log file and extract HTTP request data."""
        tree = ET.parse(log_path)
        root = tree.getroot()
        for item in root.findall('item'):
            method = item.find('method').text or 'UNKNOWN'
            path = item.find('path').text or ''
            request = item.find('request').text or ''
            base64_encoded = item.find('request').attrib.get('base64', 'false') == 'true'

            # Decode base64 request if necessary
            if base64_encoded:
                try:
                    request = base64.b64decode(request).decode('utf-8')
                except Exception:
                    request = ''

            headers = {}
            body = ''
            if request:
                lines = request.split('\n')
                for line in lines:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value
                    elif line.startswith('GET') or line.startswith('POST'):
                        continue  # Skip method line
                    else:
                        body += line

            yield method, path, body, headers


# Initialize the parser
lp = LogParser()

# Prepare the CSV output
with open(output_csv_log, "w", newline='', encoding='utf-8') as f:
    c = csv.writer(f)
    c.writerow([
        "method", "path", "body", "single_q", "double_q", "dashes", "braces", "spaces",
        "url_length", "body_length", "base64_count", "path_entropy", "body_entropy",
        "header_count", "sql_injection_count", "xss_attack_count",
        "command_injection_count", "directory_traversal_count", "csrf_count", "label"
    ])

    # Parse log and extract features
    for method, path, body, headers in lp.parse_log(log_path):
        features = lp.extract_features(method, path, body, headers)
        c.writerow(features)
