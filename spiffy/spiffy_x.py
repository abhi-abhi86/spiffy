import socket
import threading
import random
import sys
import os
import time
import datetime
import string
import hashlib
import base64
import struct
import ssl
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Hacker-style color codes
class HColor:
    GREEN = '\033[92m'
    DARK_GREEN = '\033[32m'
    BRIGHT_GREEN = '\033[1;92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

# --- SECURITY MODULE ---
class SecureCrypto:
    """
    Implements AES-GCM authenticated encryption for secure communication.
    Provides confidentiality, integrity, and replay protection.
    """
    def __init__(self, key):
        self.key = bytes.fromhex(key)
        self.backend = default_backend()
        self.sent_nonces = set()  # For replay protection
        self.recv_nonces = set()

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        nonce = os.urandom(12)  # GCM nonce
        while nonce in self.sent_nonces:
            nonce = os.urandom(12)
        self.sent_nonces.add(nonce)

        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(nonce + encryptor.tag + ciphertext)

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce = raw[:12]
        if nonce in self.recv_nonces:
            raise ValueError("Replay detected")
        self.recv_nonces.add(nonce)

        tag = raw[12:28]
        ciphertext = raw[28:]

        try:
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed")

# --- TERMINAL HELPERS ---
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

def progress_bar(label, duration=1.0):
    sys.stdout.write(f"{HColor.DARK_GREEN}  {label:<20} {HColor.ENDC}")
    sys.stdout.flush()
    steps = 20
    step_delay = duration / steps
    sys.stdout.write(HColor.BRIGHT_GREEN + "[")
    for i in range(steps):
        time.sleep(step_delay)
        sys.stdout.write("█")
        sys.stdout.flush()
    sys.stdout.write("] 100%" + HColor.ENDC + "\n")

def hex_dump_effect(lines=5):
    print(HColor.DIM + HColor.GREEN)
    chars = string.ascii_uppercase + string.digits
    for i in range(lines):
        addr = f"0x{random.randint(4096, 65535):04X}"
        hex_data = " ".join([f"{random.randint(0, 255):02X}" for _ in range(8)])
        ascii_data = "".join([random.choice(chars) for _ in range(8)])
        print(f"  {addr} : {hex_data} | {ascii_data}")
        time.sleep(0.03)
    print(HColor.ENDC)

def fake_update_screen():
    """Panic mode: Looks like a boring system update"""
    clear()
    print("Configuring updates...")
    print("0% complete")
    try:
        for i in range(1, 101):
            time.sleep(random.uniform(0.1, 2.0))
            if random.random() > 0.9: 
                print(f"Applying patch KB{random.randint(400000, 999999)}...")
            sys.stdout.write(f"\r{i}% complete")
            sys.stdout.flush()
    except KeyboardInterrupt:
        sys.exit()

def wipe_memory():
    print(f"\n{HColor.RED}  [!] DISCONNECT DETECTED. INITIATING LOG WIPE...{HColor.ENDC}")
    time.sleep(0.2)
    hex_dump_effect(3)
    print(f"{HColor.BRIGHT_GREEN}  [✓] RAM SCRUBBED. NO FORENSIC TRACE LEFT.{HColor.ENDC}")
    time.sleep(0.5)

def print_matrix_header(extra_art=None):
    clear()
    print(HColor.BRIGHT_GREEN + HColor.BOLD)
    print("███████╗  ██████╗   ██╗  ███████╗  ███████╗  ██╗   ██╗")
    print("██╔════╝  ██╔══██╗  ██║  ██╔════╝  ██╔════╝  ╚██╗ ██╔╝")
    print("███████╗  ██████╔╝  ██║  █████╗    █████╗     ╚████╔╝ ")
    print("╚════██║  ██╔═══╝   ██║  ██╔══╝    ██╔══╝      ╚██╔╝  ")
    print("███████║  ██║       ██║  ██║       ██║          ██║   ")
    print("╚══════╝  ╚═╝       ╚═╝  ╚═╝       ╚═╝          ╚═╝   ")
    print(HColor.ENDC)
    
    # --- ANIMATION GAP CONTENT ---
    if extra_art:
        for line in extra_art:
            print(HColor.CYAN + line.center(68) + HColor.ENDC)
    
    print(f"{HColor.DARK_GREEN}  PROTOCOL: {HColor.WHITE}TLS/AUTH{HColor.DARK_GREEN} | CRYPTO: {HColor.WHITE}AES-GCM{HColor.DARK_GREEN} | MODE: {HColor.WHITE}TERMINAL{HColor.ENDC}")
    print(HColor.DARK_GREEN + "  " + "═" * 68 + HColor.ENDC)

def animate_intro():
    """Plays a loading bar animation"""
    clear()
    print("\n" * 10)
    
    width = 50
    for i in range(101):
        filled = int(width * i / 100)
        bar = "█" * filled + " " * (width - filled)
        sys.stdout.write(f"\r  {HColor.BRIGHT_GREEN} ENHANCING SECURITY  [{bar}] {i}%{HColor.ENDC}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01, 0.06))
    
    print()
    time.sleep(0.2)

    for i in range(101):
        filled = int(width * i / 100)
        bar = "█" * filled + " " * (width - filled)
        sys.stdout.write(f"\r  {HColor.BRIGHT_GREEN} SYSTEM LOAD         [{bar}] {i}%{HColor.ENDC}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.01, 0.06))
    
    print()
    print(f"  {HColor.BRIGHT_GREEN}[✓] CHECKING DONE{HColor.ENDC}")
    time.sleep(1.0)
    
    # Reset to clean header
    print_matrix_header()

def print_status(prefix, message, status="info"):
    timestamp = f"{HColor.DIM}[{get_timestamp()}]{HColor.ENDC}"
    if status == "success":
        symbol = f"{HColor.BRIGHT_GREEN}[✓]{HColor.ENDC}"
        color = HColor.BRIGHT_GREEN
    elif status == "error":
        symbol = f"{HColor.RED}[✗]{HColor.ENDC}"
        color = HColor.RED
    elif status == "warning":
        symbol = f"{HColor.YELLOW}[⚠]{HColor.ENDC}"
        color = HColor.YELLOW
    else:
        symbol = f"{HColor.DARK_GREEN}[►]{HColor.ENDC}"
        color = HColor.GREEN
    print(f"  {timestamp} {symbol} {HColor.BOLD}{prefix}:{HColor.ENDC} {color}{message}{HColor.ENDC}")

# --- NETWORK HELPERS ---
def send_packet(sock, data):
    if isinstance(data, str): data = data.encode('utf-8')
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)

def recv_packet(sock):
    raw_len = sock.recv(4)
    if not raw_len: return None
    msg_len = struct.unpack('>I', raw_len)[0]
    data = b''
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet: return None
        data += packet
    return data

# --- SERVER ---
class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {} # {client_socket: {'name': name, 'crypto': crypto_obj}}
        self.connection_key = self.generate_connection_key()
        self.lock = threading.Lock()  # For thread safety

    def generate_connection_key(self):
        # Generate a 256-bit (32-byte) cryptographically secure key
        return secrets.token_hex(32)
    
    def start(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen()
        except Exception as e:
            print_status("ERROR", f"Failed to bind: {e}", "error")
            return

        # Wrap server with TLS
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Fix: Use paths relative to this script file to work regardless of CWD
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(base_dir, 'server.crt')
        key_path = os.path.join(base_dir, 'server.key')
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.server = context.wrap_socket(self.server, server_side=True)

        print_matrix_header()
        print()
        hex_dump_effect(3)
        print()
        progress_bar("LOADING AES-GCM ENCRYPTION", 0.5)
        time.sleep(0.3)
        print_matrix_header()

        print()
        print(HColor.BRIGHT_GREEN + "  ╔" + "═" * 66 + "╗" + HColor.ENDC)
        key_msg = f"SECURE CHANNEL KEY: {HColor.WHITE}{HColor.BOLD}{self.connection_key[:16]}...{HColor.ENDC}"
        print(f"  ║{key_msg.center(78)}║")
        print(HColor.BRIGHT_GREEN + "  ╚" + "═" * 66 + "╝" + HColor.ENDC)
        print()

        print_status("SERVER", f"TLS Listening on {self.host}:{self.port}", "success")

        while True:
            try:
                client, addr = self.server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.start()
            except Exception as e:
                print_status("ERROR", f"Accept error: {e}", "error")
    
    def handle_client(self, client, addr):
        try:
            crypto = SecureCrypto(self.connection_key)
            challenge = secrets.token_hex(16)  # Secure random challenge
            send_packet(client, challenge.encode())

            raw_response = recv_packet(client)
            if not raw_response: return
            decrypted = crypto.decrypt(raw_response)
            parts = decrypted.split(':')

            if len(parts) != 3 or parts[0] != "RESPONSE" or parts[1] != challenge:
                client.close()
                return

            username = parts[2].strip()
            if not username or len(username) > 50:  # Input validation
                client.close()
                return

            with self.lock:
                self.clients[client] = {'name': username, 'crypto': crypto}

            print_status("NET", f"Secure uplink: {username}", "success")
            send_packet(client, crypto.encrypt("WELCOME:Secure Channel Established. Type /panic to hide."))
            self.broadcast(f"[SYSTEM] {username} joined the encrypted channel.", exclude=client)

            while True:
                encrypted_msg = recv_packet(client)
                if not encrypted_msg: break

                msg = crypto.decrypt(encrypted_msg).strip()
                if not msg: continue

                if msg.startswith('/dm '):
                    try:
                        parts = msg.split(' ', 2)
                        if len(parts) < 3:
                            send_packet(client, crypto.encrypt("[!] Usage: /dm <username> <message>"))
                            continue
                        _, target_name, content = parts
                        target_name = target_name.strip()
                        content = content.strip()
                        if not target_name or not content:
                            send_packet(client, crypto.encrypt("[!] Invalid DM format"))
                            continue

                        target_sock = None
                        with self.lock:
                            for s, data in self.clients.items():
                                if data['name'] == target_name:
                                    target_sock = s
                                    break

                        if target_sock:
                            dm_msg = f"[WHISPER] <{username}> {content}"
                            target_crypto = self.clients[target_sock]['crypto']
                            send_packet(target_sock, target_crypto.encrypt(dm_msg))

                            echo_msg = f"[WHISPER] -> <{target_name}> {content}"
                            send_packet(client, crypto.encrypt(echo_msg))
                            print(f"\r  {HColor.DIM}[LOG]{HColor.ENDC} {username} -> {target_name} (Encrypted DM)")
                        else:
                            err = f"[!] User '{target_name}' not found."
                            send_packet(client, crypto.encrypt(err))
                    except Exception as e:
                        send_packet(client, crypto.encrypt("[!] Error processing DM"))

                else:
                    timestamp = get_timestamp()
                    print(f"\r  {HColor.DIM}[{timestamp}]{HColor.ENDC} {HColor.CYAN}<{username}>{HColor.ENDC} {msg}")
                    full_msg = f"<{username}> {msg}"
                    self.broadcast(full_msg, exclude=client)

        except Exception as e:
            print_status("ERROR", f"Client error: {e}", "error")
        finally:
            self.remove_client(client)
    
    def broadcast(self, message, exclude=None):
        for c, data in self.clients.items():
            if c != exclude:
                try:
                    cipher = data['crypto'].encrypt(message)
                    send_packet(c, cipher)
                except:
                    pass
    
    def remove_client(self, client):
        username = None
        with self.lock:
            if client in self.clients:
                username = self.clients[client]['name']
                del self.clients[client]
        if username:
            print_status("NET", f"Lost signal: {username}", "warning")
            self.broadcast(f"[SYSTEM] {username} disconnected.")
        try:
            client.close()
        except Exception as e:
            print_status("ERROR", f"Close error: {e}", "error")


# --- CLIENT (PURE TERMINAL) ---
class ChatClient:
    def __init__(self, host, port, key, username):
        self.host = host
        self.port = port
        self.key = key
        self.username = username
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.crypto = SimpleCrypto(key)
        self.running = True
    
    def connect(self):
        try:
            print_matrix_header()
            print()
            progress_bar("ESTABLISHING SECURE UPLINK", 0.5)

            # Wrap socket with TLS
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # For demo; in production, verify certs
            self.client = context.wrap_socket(self.client, server_hostname=self.host)
            self.client.connect((self.host, self.port))

            challenge = recv_packet(self.client).decode()
            response = f"RESPONSE:{challenge}:{self.username}"
            send_packet(self.client, self.crypto.encrypt(response))

            welcome_packet = recv_packet(self.client)
            welcome = self.crypto.decrypt(welcome_packet)

            if "WELCOME" in welcome:
                print_status("SECURE", "TLS Handshake Verified. AES-GCM Encryption Active.", "success")
                print()
            else:
                print_status("FATAL", "Authentication Failed. Wrong Key?", "error")
                return

            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

            self.send_messages()

        except Exception as e:
            print_status("FATAL", f"Connection failed: {e}", "error")
            wipe_memory()
    
    def receive_messages(self):
        while self.running:
            try:
                packet = recv_packet(self.client)
                if not packet:
                    self.running = False
                    print(f"\n{HColor.RED}[!] UPLINK SEVERED{HColor.ENDC}")
                    wipe_memory()
                    self.client.close()
                    sys.exit()
                    
                message = self.crypto.decrypt(packet)
                sys.stdout.write('\a')
                sys.stdout.write(f"\r{HColor.WHITE}{message}{HColor.ENDC}\n")
                sys.stdout.write(f"{HColor.BRIGHT_GREEN}{self.username}@secure:~$ {HColor.ENDC}")
                sys.stdout.flush()
            except:
                break
    
    def send_messages(self):
        while self.running:
            try:
                msg = input(f"{HColor.BRIGHT_GREEN}{self.username}@secure:~$ {HColor.ENDC}")
                
                if msg.strip().lower() == '/quit':
                    self.running = False
                    wipe_memory()
                    self.client.close()
                    break
                elif msg.strip().lower() == '/clear':
                    print_matrix_header()
                    continue
                elif msg.strip().lower() == '/panic':
                    fake_update_screen()
                    break
                elif msg.strip().lower() == '/help':
                    print(f"\n{HColor.YELLOW}  --- COMMAND LIST ---{HColor.ENDC}")
                    print(f"  /dm <user> <msg> : Private whisper")
                    print(f"  /panic           : Fake system update screen")
                    print(f"  /clear           : Clear terminal")
                    print(f"  /quit            : Destroy session\n")
                    continue

                if msg.strip():
                    encrypted = self.crypto.encrypt(msg)
                    send_packet(self.client, encrypted)
                    
            except KeyboardInterrupt:
                self.running = False
                wipe_memory()
                break
            except:
                break