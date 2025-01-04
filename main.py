
import socket
import json
import hashlib

# Mining pool details (replace with actual values)
POOL_HOST = 'ss.antpool.com'  # Corrected: Removed stratum+tcp://
POOL_PORT = 3333  # Replace with the actual port
WORKER_USERNAME = 'ETC-MINE.001'  # Your worker username
WORKER_PASSWORD = 'Testing'  # Your worker password

# Global variable to store current difficulty
current_difficulty = None

# Create a socket to connect to the pool
def create_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((POOL_HOST, POOL_PORT))
        return sock
    except Exception as e:
        print(f"Failed to connect to pool: {e}")
        return None

# Sending a message to the pool
def send_message(sock, id, method, params=None):
    message = {
        'id': id,
        'method': method,
        'params': params if params else []
    }
    try:
        sock.sendall(json.dumps(message).encode('utf-8') + b'\n')
    except Exception as e:
        print(f"Failed to send message: {e}")

def subscribe(sock):
    send_message(sock, 1, 'mining.subscribe')

# Handle incoming messages from the pool
def handle_response(sock):
    buffer = ''
    try:
        while True:
            data = sock.recv(1024).decode('utf-8')
            buffer += data
            while '\n' in buffer:
                response, buffer = buffer.split('\n', 1)
                if response:
                    handle_pool_response(sock, response)
    except Exception as e:
        print(f"Error receiving data: {e}")

# Handle pool responses like difficulty and mining job notifications
def handle_pool_response(sock, response):
    global current_difficulty
    try:
        message = json.loads(response)
        if 'method' in message:
            method = message['method']
            if method == 'mining.set_difficulty':
                current_difficulty = message['params'][0]
                print(f"Difficulty set to {current_difficulty}")
            elif method == 'mining.notify':
                job_id = message['params'][0]
                work_data = message['params'][1]
                process_job(sock, job_id, work_data)
        elif 'result' in message and message['id'] == 3:
            # Handle the response from the share submission
            if message['result']:
                print("Share accepted by the pool.")
            else:
                print("Share rejected by the pool.")
    except Exception as e:
        print(f"Error parsing response: {e}")

def authenticate(sock):
    send_message(sock, 2, 'mining.authorize', [WORKER_USERNAME, WORKER_PASSWORD])

# Processing mining job and calculating hash
def process_job(sock, job_id, work_data):
    global current_difficulty
    if current_difficulty is None:
        print("Waiting for difficulty to be set...")
        return

    target = 2**256 // current_difficulty  # Calculate target from difficulty

    nonce = 0
    while True:
        data = (work_data + str(nonce)).encode('utf-8')
        hash_result = hashlib.sha256(data).hexdigest()

        # Check if the hash is below the target
        if int(hash_result, 16) < target:
            print(f"Found valid hash: {hash_result}")
            submit_share(sock, job_id, nonce, hash_result)
            break
        nonce += 1

def submit_share(sock, job_id, nonce, hash_result):
    params = [job_id, WORKER_USERNAME, str(nonce), hash_result]
    send_message(sock, 3, 'mining.submit', params)
    # Wait and handle the response for this submission
    handle_response(sock)

def start_mining():
    sock = create_socket()
    if sock:
        try:
            subscribe(sock)
            authenticate(sock)
            handle_response(sock)
        finally:
            sock.close()

if __name__ == '__main__':
    start_mining()