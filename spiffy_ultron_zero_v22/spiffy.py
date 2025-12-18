#!/usr/bin/env python3
"""
PROJECT: ULTRON-ZERO (SPIFFY KERNEL V22.0)
ARCHITECT: STARK INDUSTRIES / JARVIS
DIRECTIVE: FULL-SPECTRUM ADVERSARIAL & DEFENSIVE SYNERGY

Modules:
[RED] WIFI_RADAR, DEEP_FINGERPRINT, AUTO_EXPLOIT, SERVICE_STRESSOR, STEALTH_EVASION
[BLUE] MITM_SENTINEL, SSL_TLS_AUDIT, BREACH_SENSE, ENCRYPTED_VAULT
"""

import sys
import os
import time
import asyncio
import socket
import sqlite3
import hashlib
import hmac
import random
import string
import json
import ssl
import re
import subprocess
import getpass
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
from contextlib import contextmanager

# v25.0 Crypto Upgrades
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==============================================================================
# [KERNEL CONSTANTS]
# ==============================================================================

DB_FILE = "ultron_zero.db"
LOG_FILE = "ultron_audit.log"
MAX_CONCURRENCY = 100
WATCHDOG_TIMEOUT = 1.5

# OUI Database (Stark Industries Enhanced)
OUI_DB = {
    "00:50:56": "VMware Virtual", "00:0C:29": "VMware Virtual",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "F0:18:98": "Apple iPhone", "00:25:00": "Apple Mac",
    "A8:5B:78": "Apple iPhone 14 Pro", # High fidelity
    "40:83:1D": "Apple iPad", "FC:F1:52": "Sony PlayStation",
    "50:E5:49": "Microsoft Xbox", "24:77:03": "Intel Corp",
    "50:56:BF": "Samsung Galaxy", "00:07:AB": "Samsung SmartTV",
    "8C:F5:F3": "Samsung Galaxy S23 Ultra", # High fidelity
    "ST:AR:K1": "Stark-Pad (Vibranium Ed.)", # Easter egg
    "ST:AR:K2": "Jarvis Mainframe Node"
}

# User-Agent Pool for Stealth Evasion
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/90.0",
    "Stark-Browser/4.0 (Compatible; Jarvis-OS v22.0)"
]

# ANSI Colors (Emerald Sentinel Theme)
C_EMERALD = "\033[38;5;46m"
C_BRIGHT_GREEN = "\033[38;5;82m"
C_DARK_GREEN = "\033[38;5;22m"
C_CYAN = "\033[38;5;51m"
C_RED = "\033[38;5;196m"
C_YELLOW = "\033[38;5;226m"
C_WHITE = "\033[38;5;255m"
C_GRAY = "\033[38;5;240m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"
C_CLEAR = "\033[H\033[J"

# ==============================================================================
# [PERSISTENCE LAYER: ENCRYPTED_VAULT]
# ==============================================================================

class DatabaseManager:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS identities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    pwd_hash BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    role TEXT DEFAULT 'OPERATOR'
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    module TEXT NOT NULL,
                    target TEXT,
                    details TEXT,
                    severity TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES identities(id) ON DELETE CASCADE
                )
            ''')
            conn.commit()

    def hash_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        if not salt: salt = os.urandom(16)
        pwd_hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return pwd_hash, salt

    def register(self, user, pwd):
        ph, salt = self.hash_password(pwd)
        try:
            with self.get_conn() as conn:
                conn.execute("INSERT INTO identities (username, pwd_hash, salt) VALUES (?,?,?)", (user, ph, salt))
                conn.commit()
            return True
        except sqlite3.IntegrityError: return False

    def verify(self, user, pwd):
        with self.get_conn() as conn:
            row = conn.execute("SELECT id, pwd_hash, salt FROM identities WHERE username=?", (user,)).fetchone()
            if not row: return None
            ph, _ = self.hash_password(pwd, row['salt'])
            if hmac.compare_digest(ph, row['pwd_hash']): return row['id']
        return None

    def log_finding(self, user_id, module, target, details, severity="INFO"):
        with self.get_conn() as conn:
            conn.execute("INSERT INTO findings (user_id, module, target, details, severity) VALUES (?,?,?,?,?)",
                         (user_id, module, target, json.dumps(details), severity))
            conn.commit()

# ==============================================================================
# [SYSTEM CORE: ASYNC NETWORKING & STEALTH]
# ==============================================================================

class AsyncNetworkEngine:
    def __init__(self, concurrency=MAX_CONCURRENCY):
        self.sem = asyncio.Semaphore(concurrency)
        self.headers = {'User-Agent': random.choice(USER_AGENTS)}

    def rotate_identity(self):
        self.headers['User-Agent'] = random.choice(USER_AGENTS)

    async def _async_sleep(self):
        """Randomized jitter for stealth evasion"""
        await asyncio.sleep(random.uniform(0.1, 0.5))

    async def scan_port(self, ip, port) -> Optional[int]:
        loop = asyncio.get_running_loop()
        async with self.sem:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(conn, (ip, port)), timeout=WATCHDOG_TIMEOUT)
                conn.close()
                return port
            except:
                return None

    async def grab_banner(self, ip, port) -> str:
        async with self.sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=WATCHDOG_TIMEOUT)
                if port in [80, 443]:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=WATCHDOG_TIMEOUT)
                writer.close()
                await writer.wait_closed()
                return data.decode(errors='ignore').strip().split('\n')[0][:60]
            except: return ""

    def resolve_mac_vendor(self, mac: str) -> str:
        if not mac: return "Unknown"
        clean = mac.upper().replace(':', '').replace('-', '')[:6]
        # Format XX:XX:XX
        prefix = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
        return OUI_DB.get(prefix, "Unknown Hardware")

    @staticmethod
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 1)); return s.getsockname()[0]
        except: return '127.0.0.1'
        finally: s.close()

# ==============================================================================
# [RED TEAM MODULES: OFFENSIVE]
# ==============================================================================

class AutoExploitSim:
    """[AUTO_EXPLOIT_SIM]: Fuzzing Engine"""
    PAYLOADS = {
        "SQLi": ["' OR 1=1 --", "' UNION SELECT 1,2,3 --", "admin' --"],
        "RCE": ["; id", "| whoami", "`cat /etc/passwd`"],
        "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
    }

    async def fuzz_target(self, url: str) -> List[str]:
        vulns = []
        if not url.startswith('http'): return []
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        
        for p_type, payloads in self.PAYLOADS.items():
            for p in payloads:
                # Naive Append Fuzzing
                fuzzed_url = f"{url}?q={urllib.parse.quote(p)}"
                try:
                    req = urllib.request.Request(fuzzed_url, headers={'User-Agent': 'UltronScan/1.0'})
                    with urllib.request.urlopen(req, timeout=3, context=ctx) as res:
                        # Simple Heuristic: 500 errors or reflective output often implies issues
                        if res.code == 500:
                            vulns.append(f"POTENTIAL {p_type}: Server Error 500 on payload {p}")
                        body = res.read().decode('utf-8', errors='ignore')
                        if p in body and p_type == "XSS":
                            vulns.append(f"CONFIRMED Reflected XSS: {p}")
                except urllib.error.HTTPError as e:
                    if e.code == 500: vulns.append(f"POTENTIAL {p_type}: 500 Error on {p}")
                except: pass
        return vulns

class ServiceStressor:
    """[SERVICE_STRESSOR]: DDoS Simulation"""
    async def stress_test(self, url: str, requests=50) -> Dict:
        successful = 0
        failed = 0
        times = []
        
        async def fetch():
            start = time.time()
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, urllib.request.urlopen, url)
                times.append(time.time() - start)
                return True
            except:
                return False

        results = await asyncio.gather(*[fetch() for _ in range(requests)])
        successful = results.count(True)
        failed = requests - successful
        avg_time = (sum(times) / len(times)) * 1000 if times else 0
        
        return {
            "total": requests,
            "success": successful,
            "failed": failed,
            "avg_latency_ms": round(avg_time, 2),
            "status": "STABLE" if failed < (requests * 0.2) else "UNSTABLE"
        }

# ==============================================================================
# [BLUE TEAM MODULES: DEFENSIVE]
# ==============================================================================

class MitmSentinel:
    """[MITM_SENTINEL]: ARP Analysis"""
    @staticmethod
    def scan_arp_table() -> List[str]:
        alerts = []
        try:
            output = subprocess.check_output("arp -a", shell=True).decode()
            mac_map = {} # MAC -> List of IPs
            
            regex = r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?\s+(?:at|)\s+([0-9a-fA-F:\-]{17})"
            for line in output.splitlines():
                match = re.search(regex, line)
                if match:
                    ip, mac = match.groups()
                    if mac in mac_map:
                        mac_map[mac].append(ip)
                    else:
                        mac_map[mac] = [ip]
            
            # Analyze for Duplicates (Poisoning Sign)
            for mac, ips in mac_map.items():
                if len(ips) > 1 and "ff:ff:ff:ff:ff:ff" not in mac.lower():
                    alerts.append(f"ARP POISON WARNING: MAC {mac} claims IPs {ips}")
        except: pass
        return alerts

class SslTlsAudit:
    """[SSL_TLS_AUDIT]: Cert Checking"""
    @staticmethod
    def audit_cert(hostname: str, port=443) -> Dict:
        result = {"host": hostname, "valid": False, "issues": []}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["valid"] = True
                    result["protocol"] = ssock.version()
                    result["cipher"] = ssock.cipher()[0]
                    # Expiry Check
                    not_after = cert['notAfter']
                    # Simplified parsing for demo
                    result["expiry"] = not_after
                    if ssock.version() in ['TLSv1', 'TLSv1.1']:
                        result["issues"].append("DEPRECATED_PROTOCOL (TLS < 1.2)")
        except Exception as e:
            result["issues"].append(str(e))
        return result

class BreachSense:
    """[BREACH_SENSE]: Leak Detection"""
    @staticmethod
    def check_identity(email: str) -> str:
        # Simulation of HIBP API
        # Real impl would query haveibeenpwned.com API
        h = hashlib.sha1(email.encode()).hexdigest()
        if h[0] in ['0', '1', '2', '3']: # Deterministic simulation
            return f"COMPROMISED (Simulated found in 3 breaches)"
        return "SECURE (No simulated breaches found)"

class BifrostChat:
    """[BIFROST_CHAT]: Secure P2P Protocol (E2EE: ECDH + AES-GCM)"""
    
    def __init__(self):
        # Generate Ephemeral Keys (ECC SECP256R1)
        self.priv_key = ec.generate_private_key(ec.SECP256R1())
        self.pub_key = self.priv_key.public_key()
        self.shared_key = None
        self.aes = None

    def get_pub_bytes(self) -> bytes:
        return self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_secret(self, peer_pub_bytes: bytes):
        try:
            peer_pub = serialization.load_pem_public_key(peer_pub_bytes)
            shared_secret = self.priv_key.exchange(ec.ECDH(), peer_pub)
            # Derive AES Key using HKDF
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'bifrost-v25-handshake'
            ).derive(shared_secret)
            self.aes = AESGCM(self.shared_key)
            return True
        except Exception as e:
            print(f"KEY DERIVATION FAILED: {e}")
            return False

    def encrypt(self, msg: str) -> bytes:
        if not self.aes: return msg.encode()
        nonce = os.urandom(12)
        ct = self.aes.encrypt(nonce, msg.encode(), None)
        return nonce + ct

    def decrypt(self, data: bytes) -> str:
        if not self.aes: return data.decode(errors='ignore')
        try:
            nonce = data[:12]
            ct = data[12:]
            pt = self.aes.decrypt(nonce, ct, None)
            return pt.decode()
        except: return "[DECRYPTION FAILED]"

    @staticmethod
    def generate_token(ip: str, port: int) -> str:
        # Ten digit obfuscation logic
        try:
            parts = ip.split('.')
            if len(parts) != 4: return "INVALID_IP"
            o3 = int(parts[2])
            o4 = int(parts[3])
            token = f"{o3:03d}{o4:03d}{port:05d}"
            return token
        except: return "ERROR"

    @staticmethod
    def resolve_token(token: str) -> Tuple[str, int]:
        try:
            if len(token) != 11: return ("0.0.0.0", 0)
            o3 = int(token[0:3])
            o4 = int(token[3:6])
            port = int(token[6:11])
            return (f"192.168.{o3}.{o4}", port)
        except: return ("0.0.0.0", 0)

    async def start_server(self):
        port = random.randint(10000, 60000)
        local_ip = AsyncNetworkEngine.get_local_ip()
        token = self.generate_token(local_ip, port)
        
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', port)
        
        print(f"{C_EMERALD}BIFROST SECURE UPLINK (AES-GCM) ACTIVE.{C_RESET}")
        print(f"LOCAL NODE: {local_ip}:{port}")
        print(f"SESSION TOKEN: {C_YELLOW}{token}{C_RESET}")
        print("WAITING FOR PEER HANDSHAKE...")
        
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"\n{C_BRIGHT_GREEN}[!] PEER CONNECTED FROM {addr}. INITIATING KEY EXCHANGE...{C_RESET}")
        
        # 1. Send Public Key
        my_pub = self.get_pub_bytes()
        writer.write(len(my_pub).to_bytes(4, 'big') + my_pub)
        await writer.drain()

        # 2. Receive Peer Public Key
        try:
            len_bytes = await reader.read(4)
            p_len = int.from_bytes(len_bytes, 'big')
            peer_pub = await reader.read(p_len)
            
            if self.derive_shared_secret(peer_pub):
                print(f"{C_CYAN}KEYS EXCHANGED. CHANNEL ENCRYPTED VIA AES-256-GCM.{C_RESET}")
            else:
                print(f"{C_RED}HANDSHAKE FAILED.{C_RESET}")
                return
        except: return

        print("TYPE MESSAGE (or 'exit'):")
        
        async def read_loop():
            while True:
                # Read length prefaced messages
                try:
                    lb = await reader.read(4)
                    if not lb: break
                    mlen = int.from_bytes(lb, 'big')
                    data = await reader.read(mlen)
                    plain = self.decrypt(data)
                    print(f"\r{C_CYAN}PEER: {plain}{C_RESET}\nYOU: ", end="", flush=True)
                except: break
        
        asyncio.create_task(read_loop())
        
        # Keep connection open for demo (simulated interactive loop would go here)
        while True:
            await asyncio.sleep(1)

    async def connect_peer(self, token: str):
        ip, port = self.resolve_token(token)
        print(f"{C_YELLOW}RESOLVING TARGET: {ip}:{port}...{C_RESET}")
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            print(f"{C_GREEN}CONNECTED. PERFORMING HANDSHAKE...{C_RESET}")
            
            # 1. Receiver Server Pub Key
            len_bytes = await reader.read(4)
            s_len = int.from_bytes(len_bytes, 'big')
            server_pub = await reader.read(s_len)
            
            # 2. Derive Secret & Send My Pub Key
            if self.derive_shared_secret(server_pub):
                 my_pub = self.get_pub_bytes()
                 writer.write(len(my_pub).to_bytes(4, 'big') + my_pub)
                 await writer.drain()
                 print(f"{C_CYAN}SECURE TUNNEL ESTABLISHED.{C_RESET}")
            else:
                 print(f"{C_RED}KEY EXCHANGE FAILED.{C_RESET}")
                 return

            # Simulate sending a secured message
            msg = "BIFROST_CLIENT_ONLINE"
            enc = self.encrypt(msg)
            writer.write(len(enc).to_bytes(4, 'big') + enc)
            await writer.drain()
            
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            print(f"{C_RED}CONNECTION FAILED: {e}{C_RESET}")

# ==============================================================================
# [UI: ULTRON TERMINAL INTERFACE]
# ==============================================================================

class UltronTUI:
    def clear(self): print(C_CLEAR, end="")

    def glitch_text(self, text):
        chars = string.ascii_uppercase + string.digits
        final = list(text)
        curr = [random.choice(chars) for _ in range(len(text))]
        for _ in range(4):
            print("\r" + "".join(curr), end="")
            time.sleep(0.01)
            curr = [random.choice(chars) for _ in range(len(text))]
        print("\r" + text)

    def draw_box(self, lines, title="", color=C_EMERALD):
        width = max(len(l) for l in lines) + 6
        if title: width = max(width, len(title) + 8)
        print(f"{color}┏{'━'*width}┓")
        if title:
            print(f"┃   {C_WHITE}{C_BOLD}{title.center(width-6)}{C_RESET}{color}   ┃")
            print(f"┣{'━'*width}┫")
        for l in lines:
            print(f"┃   {l.ljust(width-6)}   ┃")
        print(f"┗{'━'*width}┛{C_RESET}")

    def boot_sequence(self):
        self.clear()
        logs = [
            "JARVIS: INITIALIZING ULTRON-ZERO PROTOCOL v22.0...",
            "CORE: MOUNTING VIBRANIUM DATA CORES...",
            "NET: ESTABLISHING SATELLITE UPLINK...",
            "DEF: MITM SENTINELS DEPLOYED.",
            "OFF: RED TEAM MODULES ARMED.",
            "SYS: WELCOME, SIR."
        ]
        for l in logs:
            print(f"[{C_BRIGHT_GREEN}OK{C_RESET}] {l}")
            time.sleep(0.15)
        time.sleep(0.5)

# ==============================================================================
# [MAIN EXECUTABLE]
# ==============================================================================

async def main():
    db = DatabaseManager()
    net = AsyncNetworkEngine()
    tui = UltronTUI()
    
    # Modules
    exploit_sim = AutoExploitSim()
    stressor = ServiceStressor()
    mitm = MitmSentinel()
    ssl_aud = SslTlsAudit()

    tui.boot_sequence()

    # Login Simulation for Demo
    user_id = 1 
    if not db.verify("admin", "admin"):
        db.register("admin", "admin")
        user_id = db.verify("admin", "admin")

    local_ip = net.get_local_ip()

    while True:
        tui.clear()
        print(f"{C_EMERALD}{C_BOLD}")
        print(r"""
  _   _ _   _              ___________ _____ _____ 
 | | | | | | |            |___  /  ___|  __ \_   _|
 | | | | | |_ _ __ ___  _ __ / /| |__ | |  \/ | |  
 | | | | | __| '__/ _ \| '_ \  / |  __|| | __ | |  
 | |_| | | |_| | | (_) | | | / /__| |___| |_\ \| |  
  \___/|_|\__|_|  \___/|_| |_\____\____/ \____/\_/  
                                      v25.0 (BIFROST)
        """)
        print(f"{C_RESET}")
        
        menu = [
            "[1] WIFI_RADAR (TOPO + OUI)",
            "[2] AUTO_EXPLOIT (FUZZER)",
            "[3] SERVICE_STRESSOR (DDoS)",
            "[4] MITM_SENTINEL (ARP ARP)",
            "[5] SSL_TLS_AUDIT",
            "[6] BREACH_SENSE",
            "[7] ENCRYPTED_VAULT",
            "[8] BIFROST_CHAT (P2P)",
            "[0] EXIT PROTOCOL"
        ]
        tui.draw_box(menu, "MISSION CONTROL")
        
        cmd = input(f"\n{C_BRIGHT_GREEN}stark@ultron:~# {C_RESET}")

        if cmd == '0':
            print("SHUTDOWN COMMAND ACCEPTED."); break

        elif cmd == '1':
            print(f"{C_YELLOW}SCANNING LOCAL SUBNET...{C_RESET}")
            subnet = ".".join(local_ip.split('.')[:-1])
            found = []
            
            # ARP Parse First
            try:
                arp_out = subprocess.check_output("arp -a", shell=True).decode()
                # Basic mock parse for context mapping
                arp_map = {}
                for line in arp_out.splitlines():
                    if "(" in line and "at" in line:
                        parts = line.split()
                        ip = parts[1].strip('()')
                        mac = parts[3]
                        arp_map[ip] = mac
            except: arp_map = {}

            # Deep Fingerprint Scan (Ports: HTTP, HTTPS, SSH, iPhone-Sync, SMB)
            target_ports = [80, 443, 22, 62078, 445]
            tasks = []
            for i in range(1, 20): # Limited range for demo
                ip = f"{subnet}.{i}"
                for p in target_ports:
                    tasks.append(net.scan_port(ip, p))
            
            results = await asyncio.gather(*tasks)
            
            # First: ICMP Ping Sweep to find alive hosts
            print(f"{C_YELLOW}PHASE 1: PING SWEEP (192.168.x.1-254)...{C_RESET}")
            alive_hosts = []
            
            async def ping_host(target_ip):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'ping', '-c', '1', '-W', '1', target_ip,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await asyncio.wait_for(proc.wait(), timeout=2)
                    if proc.returncode == 0:
                        return target_ip
                except:
                    pass
                return None
            
            # Scan full subnet range (1-254)
            ping_tasks = [ping_host(f"{subnet}.{i}") for i in range(1, 255)]
            ping_results = await asyncio.gather(*ping_tasks)
            alive_hosts = [ip for ip in ping_results if ip]
            
            print(f"{C_BRIGHT_GREEN}FOUND {len(alive_hosts)} ALIVE HOSTS{C_RESET}")
            print(f"{C_YELLOW}PHASE 2: DEEP FINGERPRINTING...{C_RESET}")
            
            # Phase 2: Deep scan on alive hosts
            target_ports = [80, 443, 22, 62078, 445]
            
            async def scan_host_ports(target_ip):
                open_p = []
                for p in target_ports:
                    if await net.scan_port(target_ip, p):
                        open_p.append(p)
                return (target_ip, open_p)

            scan_tasks = [scan_host_ports(ip) for ip in alive_hosts]
            host_results = await asyncio.gather(*scan_tasks)

            for ip, ports in host_results:
                mac = arp_map.get(ip, "")
                vendor = net.resolve_mac_vendor(mac) if mac else "Unknown"
                banner = ""
                if 80 in ports: banner = await net.grab_banner(ip, 80)
                elif 443 in ports: banner = await net.grab_banner(ip, 443)
                elif 22 in ports: banner = await net.grab_banner(ip, 22)
                
                # Heuristics
                os_guess = "Unknown"
                if ip == local_ip: 
                    os_guess = f"{C_BRIGHT_GREEN}[THIS DEVICE]{C_RESET}"
                elif 62078 in ports: 
                    os_guess = "iOS (iPhone/iPad)"
                elif 445 in ports: 
                    os_guess = "Windows (SMB)"
                elif 22 in ports and 80 not in ports: 
                    os_guess = "Linux (SSH)"
                elif 80 in ports or 443 in ports:
                    os_guess = "Web Server"
                
                port_str = f"Ports: {','.join(map(str, ports))}" if ports else "No common ports"
                found.append(f"{ip.ljust(15)} | {mac.ljust(17)} | {vendor[:20].ljust(20)} | {os_guess.ljust(25)} | {port_str}")
            
            tui.draw_box(found or ["NO PROXIMATE HOSTS IDENTIFIED"], "RADAR SIGNALS")
            input("CONTINUE...")

        elif cmd == '2':
            target = input("TARGET URL: ")
            print(f"{C_YELLOW}INITIATING FUZZING SEQUENCE...{C_RESET}")
            res = await exploit_sim.fuzz_target(target)
            tui.draw_box(res if res else ["TARGET APPEARS RESILIENT"], "EXPLOIT MATRIX", C_RED)
            db.log_finding(user_id, "AUTO_EXPLOIT", target, res, "HIGH" if res else "INFO")
            input("CONTINUE...")

        elif cmd == '3':
            target = input("TARGET URL: ")
            cnt = int(input("PACKET COUNT (Max 100): "))
            if cnt > 100: cnt = 100
            print(f"{C_RED}ENGAGING STRESS TEST...{C_RESET}")
            res = await stressor.stress_test(target, cnt)
            
            lines = [
                f"REQUESTS: {res['total']}",
                f"SUCCESS: {res['success']}",
                f"FAILED: {res['failed']}{C_RESET}",
                f"LATENCY: {res['avg_latency_ms']} ms",
                f"STATUS: {res['status']}"
            ]
            tui.draw_box(lines, "LOAD TEST REPORT", C_CYAN)
            input("CONTINUE...")

        elif cmd == '4':
            alerts = mitm.scan_arp_table()
            if alerts:
                tui.draw_box(alerts, "INTEGRITY WARNING", C_RED)
            else:
                tui.draw_box(["ARP TABLES CLEAN. GATEWAY SECURE."], "SENTINEL STATUS")
            input("CONTINUE...")

        elif cmd == '5':
            host = input("HOSTNAME (e.g., google.com): ")
            res = ssl_aud.audit_cert(host)
            lines = [
                f"VALID: {res['valid']}",
                f"PROTO: {res.get('protocol', 'N/A')}",
                f"CIPHER: {res.get('cipher', 'N/A')}",
                f"EXPIRY: {res.get('expiry', 'N/A')}"
            ]
            if res.get('issues'):
                lines.append(f"{C_RED}ISSUES: {res['issues']}{C_RESET}")
            tui.draw_box(lines, "SSL/TLS DIAGNOSTICS")
            input("CONTINUE...")

        elif cmd == '6':
            email = input("EMAIL IDENTITY: ")
            res = BreachSense.check_identity(email)
            tui.draw_box([res], "BREACH REPOSITORY")
            input("CONTINUE...")

            with db.get_conn() as conn:
                rows = conn.execute("SELECT module, target, severity, timestamp FROM findings WHERE user_id=?", (user_id,)).fetchall()
            lines = [f"{r['timestamp']} | {r['severity']} | {r['module']} | {r['target']}" for r in rows]
            tui.draw_box(lines if lines else ["VAULT EMPTY"], "CLASSIFIED INTEL")
            input("CONTINUE...")

        elif cmd == '8':
            chat = BifrostChat()
            print(f"{C_BLUE}[1] HOST (SERVER)   [2] CONNECT (CLIENT){C_RESET}")
            sc = input("> ")
            if sc == '1':
                # For demo, run server as a task and wait a bit
                try:
                    await chat.start_server()
                except KeyboardInterrupt: pass
            elif sc == '2':
                tk = input("ENTER BIFROST TOKEN: ")
                await chat.connect_peer(tk)
            input("SESSION ENDED...")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nPROTOCOL DISENGAGED.")
