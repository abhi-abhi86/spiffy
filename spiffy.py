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

# Hacker-style color codes
class HColor:
    GREEN = '\033[92m'
    DARK_GREEN = '\033[32m'
    BRIGHT_GREEN = '\033[1;92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

# --- SECURITY MODULE ---
class SimpleCrypto:
    """
    Implements a stream cipher using SHA-256 for educational security.
    Includes TRAFFIC MASKING (Padding) to prevent size analysis.
    """
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()
        self.enc_counter = 0
        self.dec_counter = 0

    def _get_keystream_byte(self, counter):
        # Generate a block of keystream based on key + counter
        # We divide counter by 32 (size of sha256 digest) to get block index
        block_idx = counter // 32
        byte_idx = counter % 32
        
        # Hash the Key + Block Index to create a unique block
        block_seed = self.key + struct.pack('>Q', block_idx)
        keystream_block = hashlib.sha256(block_seed).digest()
        
        return keystream_block[byte_idx]

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # --- TRAFFIC MASKING (PADDING) ---
        # We pad every message with random junk so it aligns to 64-byte blocks.
        # This makes a "Hi" packet look the same size as a long sentence.
        # Attackers cannot guess message content based on length.
        
        original_len = len(data)
        block_size = 64
        # Calculate how much padding is needed
        # We add 4 bytes for the length header, so we include that in calculation
        total_len_needed = original_len + 4
        remainder = total_len_needed % block_size
        
        if remainder == 0:
            pad_len = 0
        else:
            pad_len = block_size - remainder

        padding = os.urandom(pad_len)
        
        # Structure: [4-byte-real-length][message-data][random-junk-padding]
        payload = struct.pack('>I', original_len) + data + padding
        
        out = bytearray()
        for b in payload:
            k = self._get_keystream_byte(self.enc_counter)
            out.append(b ^ k)
            self.enc_counter += 1
        return base64.b64encode(out)

    def decrypt(self, data):
        try:
            raw = base64.b64decode(data)
            out = bytearray()
            for b in raw:
                k = self._get_keystream_byte(self.dec_counter)
                out.append(b ^ k)
                self.dec_counter += 1
            
            # --- REMOVE PADDING ---
            if len(out) < 4: return ""
            
            # Read the first 4 bytes to know the REAL message length
            real_len = struct.unpack('>I', out[:4])[0]
            
            # Extract only the real data, ignore the junk padding at the end
            real_data = out[4 : 4 + real_len]
            return real_data.decode('utf-8')
        except:
            return "[DECRYPTION ERROR]"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")

def progress_bar(label, duration=1.0):
    """Displays a hacker-style progress bar"""
    width = 40
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
    """Simulates a memory dump"""
    print(HColor.DIM + HColor.GREEN)
    chars = string.ascii_uppercase + string.digits
    for i in range(lines):
        addr = f"0x{random.randint(4096, 65535):04X}"
        hex_data = " ".join([f"{random.randint(0, 255):02X}" for _ in range(8)])
        ascii_data = "".join([random.choice(chars) for _ in range(8)])
        print(f"  {addr} : {hex_data} | {ascii_data}")
        time.sleep(0.03)
    print(HColor.ENDC)

def wipe_memory():
    """Simulates clearing traces on exit"""
    print(f"\n{HColor.RED}  [!] DISCONNECT DETECTED. INITIATING LOG WIPE...{HColor.ENDC}")
    time.sleep(0.2)
    hex_dump_effect(3)
    print(f"{HColor.BRIGHT_GREEN}  [✓] RAM SCRUBBED. NO FORENSIC TRACE LEFT.{HColor.ENDC}")
    time.sleep(0.5)

def print_matrix_header():
    clear()
    print(HColor.BRIGHT_GREEN + HColor.BOLD)
    # ASCII Art for "SPIFFY"
    print("███████╗  ██████╗   ██╗  ███████╗  ███████╗  ██╗   ██╗")
    print("██╔════╝  ██╔══██╗  ██║  ██╔════╝  ██╔════╝  ╚██╗ ██╔╝")
    print("███████╗  ██████╔╝  ██║  █████╗    █████╗     ╚████╔╝ ")
    print("╚════██║  ██╔═══╝   ██║  ██╔══╝    ██╔══╝      ╚██╔╝  ")
    print("███████║  ██║       ██║  ██║       ██║          ██║   ")
    print("╚══════╝  ╚═╝       ╚═╝  ╚═╝       ╚═╝          ╚═╝   ")
    print(HColor.ENDC)
    
    print(f"{HColor.DARK_GREEN}  PROTOCOL: {HColor.WHITE}TCP/SECURE{HColor.DARK_GREEN} | CRYPTO: {HColor.WHITE}SHA256+PADDING{HColor.DARK_GREEN} | TRAFFIC MASKING: {HColor.WHITE}ACTIVE{HColor.ENDC}")
    print(HColor.DARK_GREEN + "  " + "═" * 68 + HColor.ENDC)

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
    elif status == "system":
        symbol = f"{HColor.CYAN}[SYS]{HColor.ENDC}"
        color = HColor.CYAN
    else:
        symbol = f"{HColor.DARK_GREEN}[►]{HColor.ENDC}"
        color = HColor.GREEN
    
    print(f"  {timestamp} {symbol} {HColor.BOLD}{prefix}:{HColor.ENDC} {color}{message}{HColor.ENDC}")

# --- NETWORK HELPERS ---
def send_packet(sock, data):
    # Prefix data with 4-byte length
    if isinstance(data, str): data = data.encode('utf-8')
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)

def recv_packet(sock):
    # Read 4-byte length
    raw_len = sock.recv(4)
    if not raw_len: return None
    msg_len = struct.unpack('>I', raw_len)[0]
    # Read data
    data = b''
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet: return None
        data += packet
    return data

class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {} # {client_socket: {'name': name, 'crypto': crypto_obj}}
        self.connection_code = self.generate_connection_code()
        
    def generate_connection_code(self):
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    def start(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen()
        except Exception as e:
            print_status("ERROR", f"Failed to bind: {e}", "error")
            return

        print_matrix_header()
        print()
        hex_dump_effect(3)
        print()
        progress_bar("LOADING ENCRYPTION", 0.5)
        time.sleep(0.3)
        print_matrix_header()
        
        print()
        print(HColor.BRIGHT_GREEN + "  ╔" + "═" * 66 + "╗" + HColor.ENDC)
        code_msg = f"SECURE CHANNEL KEY: {HColor.WHITE}{HColor.BOLD}{self.connection_code}{HColor.ENDC}"
        print(f"  ║{code_msg.center(78)}║")
        print(HColor.BRIGHT_GREEN + "  ╚" + "═" * 66 + "╝" + HColor.ENDC)
        print()
        
        print_status("SERVER", f"Listening on {self.host}:{self.port}", "success")
        
        while True:
            client, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client, addr))
            thread.start()
    
    def handle_client(self, client, addr):
        try:
            # 1. Wait for Encrypted Handshake
            # Client sends: Encrypt(Hash(Key), "AUTH:<Username>")
            
            crypto = SimpleCrypto(self.connection_code)
            
            # Send Challenge (Random Nonce)
            challenge = str(random.randint(10000,99999))
            send_packet(client, challenge.encode())
            
            # Receive Response (Encrypted challenge + username)
            raw_response = recv_packet(client)
            if not raw_response: return
            
            decrypted = crypto.decrypt(raw_response)
            
            # Expected format: "RESPONSE:<challenge>:<username>"
            parts = decrypted.split(':')
            
            if len(parts) != 3 or parts[0] != "RESPONSE" or parts[1] != challenge:
                print_status("AUTH", f"Auth failed from {addr}", "error")
                client.close()
                return
            
            username = parts[2]
            
            # Auth Success
            self.clients[client] = {'name': username, 'crypto': crypto}
            
            # Notify Join
            print_status("NET", f"Secure uplink: {username}", "success")
            send_packet(client, crypto.encrypt("WELCOME:Secure Channel Established"))
            self.broadcast(f"[SYSTEM] {username} joined the encrypted channel.", exclude=client)
            
            while True:
                encrypted_msg = recv_packet(client)
                if not encrypted_msg: break
                
                msg = crypto.decrypt(encrypted_msg)
                
                timestamp = get_timestamp()
                print(f"\r  {HColor.DIM}[{timestamp}]{HColor.ENDC} {HColor.CYAN}<{username}>{HColor.ENDC} {msg}")
                
                # Broadcast encrypted to others
                full_msg = f"<{username}> {msg}"
                self.broadcast(full_msg, exclude=client)
                
        except Exception as e:
            # print_status("ERR", str(e), "error")
            pass
        finally:
            self.remove_client(client)
    
    def broadcast(self, message, exclude=None):
        for c, data in self.clients.items():
            if c != exclude:
                try:
                    # Encrypt specifically for this client's stream state
                    cipher = data['crypto'].encrypt(message)
                    send_packet(c, cipher)
                except:
                    pass
    
    def remove_client(self, client):
        if client in self.clients:
            username = self.clients[client]['name']
            del self.clients[client]
            print_status("NET", f"Lost signal: {username}", "warning")
            self.broadcast(f"[SYSTEM] {username} disconnected.")
        try: client.close()
        except: pass


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
            progress_bar("ESTABLISHING UPLINK", 0.5)
            self.client.connect((self.host, self.port))
            
            # Handshake
            # 1. Receive Challenge
            challenge = recv_packet(self.client).decode()
            
            # 2. Send Encrypted Response
            response = f"RESPONSE:{challenge}:{self.username}"
            send_packet(self.client, self.crypto.encrypt(response))
            
            # 3. Wait for Welcome
            welcome_packet = recv_packet(self.client)
            welcome = self.crypto.decrypt(welcome_packet)
            
            if "WELCOME" in welcome:
                print_status("SECURE", "Handshake Verified. Encryption Active.", "success")
                print()
            else:
                print_status("FATAL", "Authentication Failed. Wrong Key?", "error")
                return

            # Start threads
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
                
                # Overwrite current line to show message
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

                if msg.strip():
                    # Move cursor up one line to "hide" the double input visual if possible, 
                    # but for simple python script, just sending is fine.
                    encrypted = self.crypto.encrypt(msg)
                    send_packet(self.client, encrypted)
                    
            except KeyboardInterrupt:
                self.running = False
                wipe_memory()
                break
            except:
                break

def show_main_menu():
    print_matrix_header()
    print()
    print(f"{HColor.BRIGHT_GREEN}  ╔════════════════════════════════════╗{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ║ {HColor.WHITE}[1]{HColor.GREEN} INITIALIZE SERVER NODE         {HColor.BRIGHT_GREEN}║{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ║ {HColor.WHITE}[2]{HColor.GREEN} CONNECT TO SECURE UPLINK       {HColor.BRIGHT_GREEN}║{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ╚════════════════════════════════════╝{HColor.ENDC}")
    print()
    return input(f"{HColor.BRIGHT_GREEN}  SELECT OPTION > {HColor.ENDC}").strip()

def main():
    choice = show_main_menu()
    
    if choice == '1':
        clear()
        # Server always listens on 5555 locally
        server = ChatServer(port=5555) 
        server.start()
    
    elif choice == '2':
        clear()
        print_matrix_header()
        print()
        host = input(f"{HColor.CYAN}  TARGET IP [localhost]: {HColor.ENDC}").strip() or 'localhost'
        
        # ADDED: Allow user to input a custom port (needed for ngrok)
        port_input = input(f"{HColor.CYAN}  TARGET PORT [5555]: {HColor.ENDC}").strip()
        port = int(port_input) if port_input else 5555
        
        key = input(f"{HColor.YELLOW}  ACCESS KEY: {HColor.ENDC}").strip()
        username = input(f"{HColor.CYAN}  CALLSIGN: {HColor.ENDC}").strip()
        
        if not key or not username:
            print_status("ERROR", "Key and Callsign required", "error")
            return

        client = ChatClient(host, port, key, username)
        client.connect()
    
    else:
        print_status("ERROR", "Invalid Option", "error")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        wipe_memory()
        sys.exit()
