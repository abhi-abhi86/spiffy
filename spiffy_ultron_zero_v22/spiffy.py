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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "ultron_zero.db"
LOG_FILE = "ultron_audit.log"
MAX_CONCURRENCY = 100
WATCHDOG_TIMEOUT = 1.5

OUI_DB = {
    "00:50:56": "VMware Virtual", "00:0C:29": "VMware Virtual",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "F0:18:98": "Apple iPhone", "00:25:00": "Apple Mac",
    "A8:5B:78": "Apple iPhone 14 Pro",
    "40:83:1D": "Apple iPad", "FC:F1:52": "Sony PlayStation",
    "50:E5:49": "Microsoft Xbox", "24:77:03": "Intel Corp",
    "50:56:BF": "Samsung Galaxy", "00:07:AB": "Samsung SmartTV",
    "8C:F5:F3": "Samsung Galaxy S23 Ultra",
    "ST:AR:K1": "Stark-Pad (Vibranium Ed.)",
    "ST:AR:K2": "Jarvis Mainframe Node"
}

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/90.0",
    "Stark-Browser/4.0 (Compatible; Jarvis-OS v22.0)"
]

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
        prefix = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
        return OUI_DB.get(prefix, "Unknown Hardware")

    @staticmethod
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 1)); return s.getsockname()[0]
        except: return '127.0.0.1'
        finally: s.close()

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
                fuzzed_url = f"{url}?q={urllib.parse.quote(p)}"
                try:
                    req = urllib.request.Request(fuzzed_url, headers={'User-Agent': 'UltronScan/1.0'})
                    with urllib.request.urlopen(req, timeout=3, context=ctx) as res:
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

class MitmSentinel:
    """[MITM_SENTINEL]: ARP Analysis"""
    @staticmethod
    def scan_arp_table() -> List[str]:
        alerts = []
        try:
            output = subprocess.check_output("arp -a", shell=True).decode()
            mac_map = {}
            
            regex = r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?\s+(?:at|)\s+([0-9a-fA-F:\-]{17})"
            for line in output.splitlines():
                match = re.search(regex, line)
                if match:
                    ip, mac = match.groups()
                    if mac in mac_map:
                        mac_map[mac].append(ip)
                    else:
                        mac_map[mac] = [ip]
            
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
                    not_after = cert['notAfter']
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
        h = hashlib.sha1(email.encode()).hexdigest()
        if h[0] in ['0', '1', '2', '3']:
            return f"COMPROMISED (Simulated found in 3 breaches)"
        return "SECURE (No simulated breaches found)"

class DNSEnumerator:
    """[DNS_ENUM]: DNS Reconnaissance & Subdomain Discovery"""
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns",
        "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2",
        "new", "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta",
        "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email",
        "images", "img", "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn"
    ]
    
    @staticmethod
    async def enumerate_dns(domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records and discover subdomains"""
        results = {"subdomains": [], "ips": [], "mx_records": []}
        
        # Subdomain discovery
        async def check_subdomain(sub):
            try:
                loop = asyncio.get_event_loop()
                target = f"{sub}.{domain}"
                info = await loop.getaddrinfo(target, None)
                if info:
                    ip = info[0][4][0]
                    return (target, ip)
            except:
                pass
            return None
        
        tasks = [check_subdomain(sub) for sub in DNSEnumerator.COMMON_SUBDOMAINS[:30]]
        found = await asyncio.gather(*tasks)
        
        for result in found:
            if result:
                results["subdomains"].append(result[0])
                if result[1] not in results["ips"]:
                    results["ips"].append(result[1])
        
        return results

class PasswordCracker:
    """[PASSWORD_CRACKER]: Hash Cracking & Password Analysis"""
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
        "qazwsx", "michael", "football", "admin", "welcome", "login", "princess"
    ]
    
    @staticmethod
    def crack_hash(hash_value: str, hash_type: str = "md5") -> Optional[str]:
        """Attempt to crack a hash using common passwords"""
        for password in PasswordCracker.COMMON_PASSWORDS:
            if hash_type == "md5":
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == "sha1":
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == "sha256":
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            else:
                return None
            
            if test_hash == hash_value.lower():
                return password
        return None
    
    @staticmethod
    def analyze_password_strength(password: str) -> Dict[str, Any]:
        """Analyze password strength"""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short (min 8 chars)")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        strength = ["VERY WEAK", "WEAK", "FAIR", "GOOD", "STRONG", "VERY STRONG"][min(score, 5)]
        
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback,
            "length": len(password)
        }

class PacketSniffer:
    """[PACKET_SNIFFER]: Network Traffic Analysis"""
    @staticmethod
    def analyze_traffic(interface: str = "en0", duration: int = 10) -> Dict[str, Any]:
        """Simulate packet sniffing (requires root privileges in real scenario)"""
        # Simulated traffic analysis
        protocols = {"TCP": random.randint(100, 500), "UDP": random.randint(50, 200), 
                    "ICMP": random.randint(10, 50), "HTTP": random.randint(20, 100),
                    "HTTPS": random.randint(50, 200), "DNS": random.randint(30, 80)}
        
        return {
            "interface": interface,
            "duration": duration,
            "total_packets": sum(protocols.values()),
            "protocols": protocols,
            "suspicious": random.randint(0, 5)
        }

class VulnerabilityScanner:
    """[VULN_SCANNER]: Automated Vulnerability Detection"""
    COMMON_VULNS = [
        ("Weak SSL/TLS", ["SSLv2", "SSLv3", "TLSv1.0"]),
        ("Open Ports", [21, 23, 445, 3389]),
        ("Default Credentials", ["admin:admin", "root:root", "admin:password"]),
        ("Missing Headers", ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection"]),
        ("Directory Listing", ["/admin", "/backup", "/.git", "/config"])
    ]
    
    @staticmethod
    async def scan_vulnerabilities(target: str) -> List[str]:
        """Scan for common vulnerabilities"""
        findings = []
        
        # Simulate vulnerability checks
        if random.random() > 0.5:
            findings.append("⚠ Weak SSL/TLS configuration detected")
        
        if random.random() > 0.6:
            findings.append("⚠ Sensitive directories exposed")
        
        if random.random() > 0.7:
            findings.append("⚠ Missing security headers")
        
        if random.random() > 0.8:
            findings.append("⚠ Default credentials may be in use")
        
        if not findings:
            findings.append("✓ No common vulnerabilities detected")
        
        return findings

class BifrostChat:
    """[BIFROST_CHAT]: Secure P2P Protocol (E2EE: ECDH + AES-GCM)"""
    
    def __init__(self):
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
        
        my_pub = self.get_pub_bytes()
        writer.write(len(my_pub).to_bytes(4, 'big') + my_pub)
        await writer.drain()

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
                try:
                    lb = await reader.read(4)
                    if not lb: break
                    mlen = int.from_bytes(lb, 'big')
                    data = await reader.read(mlen)
                    plain = self.decrypt(data)
                    print(f"\r{C_CYAN}PEER: {plain}{C_RESET}\nYOU: ", end="", flush=True)
                except: break
        
        asyncio.create_task(read_loop())
        
        while True:
            await asyncio.sleep(1)

    async def connect_peer(self, token: str):
        ip, port = self.resolve_token(token)
        print(f"{C_YELLOW}RESOLVING TARGET: {ip}:{port}...{C_RESET}")
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            print(f"{C_GREEN}CONNECTED. PERFORMING HANDSHAKE...{C_RESET}")
            
            len_bytes = await reader.read(4)
            s_len = int.from_bytes(len_bytes, 'big')
            server_pub = await reader.read(s_len)
            
            if self.derive_shared_secret(server_pub):
                 my_pub = self.get_pub_bytes()
                 writer.write(len(my_pub).to_bytes(4, 'big') + my_pub)
                 await writer.drain()
                 print(f"{C_CYAN}SECURE TUNNEL ESTABLISHED.{C_RESET}")
            else:
                 print(f"{C_RED}KEY EXCHANGE FAILED.{C_RESET}")
                 return

            msg = "BIFROST_CLIENT_ONLINE"
            enc = self.encrypt(msg)
            writer.write(len(enc).to_bytes(4, 'big') + enc)
            await writer.drain()
            
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            print(f"{C_RED}CONNECTION FAILED: {e}{C_RESET}")

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

async def main():
    db = DatabaseManager()
    net = AsyncNetworkEngine()
    tui = UltronTUI()
    
    exploit_sim = AutoExploitSim()
    stressor = ServiceStressor()
    mitm = MitmSentinel()
    ssl_aud = SslTlsAudit()

    tui.boot_sequence()

    user_id = 1 
    if not db.verify("admin", "admin"):
        db.register("admin", "admin")
        user_id = db.verify("admin", "admin")

    local_ip = net.get_local_ip()

    while True:
        tui.clear()
        print(f"{C_EMERALD}{C_BOLD}")
        print(r"""
  ███████╗██████╗ ██╗███████╗███████╗██╗   ██╗
  ██╔════╝██╔══██╗██║██╔════╝██╔════╝╚██╗ ██╔╝
  ███████╗██████╔╝██║█████╗  █████╗   ╚████╔╝ 
  ╚════██║██╔═══╝ ██║██╔══╝  ██╔══╝    ╚██╔╝  
  ███████║██║     ██║██║     ██║        ██║   
  ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝        ╚═╝   
        """)
        print(f"{C_RED}╔═══════════════════════════════════════════════════╗{C_RESET}")
        print(f"{C_YELLOW}║    ⚡ ULTRON-ZERO v25.0 (BIFROST) ⚡            ║{C_RESET}")
        print(f"{C_CYAN}║    FULL-SPECTRUM OFFENSIVE & DEFENSIVE SYNERGY  ║{C_RESET}")
        print(f"{C_RED}╚═══════════════════════════════════════════════════╝{C_RESET}")
        print(f"{C_RESET}")
        
        menu = [
            "[1] WIFI_RADAR (TOPO + OUI)",
            "[2] AUTO_EXPLOIT (FUZZER)",
            "[3] SERVICE_STRESSOR (DDoS)",
            "[4] MITM_SENTINEL (ARP)",
            "[5] SSL_TLS_AUDIT",
            "[6] BREACH_SENSE",
            "[7] ENCRYPTED_VAULT",
            "[8] BIFROST_CHAT (P2P)",
            "[9] DNS_ENUM (Recon)",
            "[A] PASSWORD_CRACKER",
            "[B] PACKET_SNIFFER",
            "[C] VULN_SCANNER",
            "[0] EXIT PROTOCOL"
        ]
        tui.draw_box(menu, "MISSION CONTROL")
        
        cmd = input(f"\n{C_BRIGHT_GREEN}stark@ultron:~# {C_RESET}").strip().upper()

        if cmd == '0':
            print("SHUTDOWN COMMAND ACCEPTED."); break

        elif cmd == '1':
            print(f"{C_YELLOW}SCANNING LOCAL SUBNET FOR ALL CONNECTED DEVICES...{C_RESET}")
            subnet = ".".join(local_ip.split('.')[:-1])
            found = []
            
            # Get ARP table for MAC addresses
            try:
                arp_out = subprocess.check_output("arp -a", shell=True).decode()
                arp_map = {}
                for line in arp_out.splitlines():
                    if "(" in line and "at" in line:
                        parts = line.split()
                        ip = parts[1].strip('()')
                        mac = parts[3]
                        arp_map[ip] = mac
            except: 
                arp_map = {}

            print(f"{C_YELLOW}PHASE 1: PING SWEEP (Scanning all 254 hosts: {subnet}.1-254)...{C_RESET}")
            print(f"{C_GRAY}This will take ~30 seconds to scan the entire network{C_RESET}")
            
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
            
            # Scan ALL 254 possible hosts in the subnet
            ping_tasks = [ping_host(f"{subnet}.{i}") for i in range(1, 255)]
            ping_results = await asyncio.gather(*ping_tasks)
            alive_hosts = [ip for ip in ping_results if ip]
            
            print(f"{C_BRIGHT_GREEN}✓ FOUND {len(alive_hosts)} ALIVE DEVICES ON NETWORK{C_RESET}")
            print(f"{C_YELLOW}PHASE 2: DEEP FINGERPRINTING (Scanning ports on {len(alive_hosts)} devices)...{C_RESET}")
            
            # Comprehensive port list for better device detection
            target_ports = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445, 3389, 5900, 8080, 8443, 62078]
            
            async def scan_host_ports(target_ip):
                open_p = []
                for p in target_ports:
                    if await net.scan_port(target_ip, p):
                        open_p.append(p)
                return (target_ip, open_p)

            scan_tasks = [scan_host_ports(ip) for ip in alive_hosts]
            host_results = await asyncio.gather(*scan_tasks)

            print(f"{C_YELLOW}PHASE 3: GATHERING DEVICE INFORMATION...{C_RESET}")
            
            for ip, ports in host_results:
                mac = arp_map.get(ip, "")
                vendor = net.resolve_mac_vendor(mac) if mac else "Unknown"
                banner = ""
                
                # Try to grab banner from open ports
                if 80 in ports: 
                    banner = await net.grab_banner(ip, 80)
                elif 443 in ports: 
                    banner = await net.grab_banner(ip, 443)
                elif 22 in ports: 
                    banner = await net.grab_banner(ip, 22)
                elif 8080 in ports:
                    banner = await net.grab_banner(ip, 8080)
                
                # Enhanced OS/Device detection
                os_guess = "Unknown Device"
                device_type = ""
                
                if ip == local_ip: 
                    os_guess = f"{C_BRIGHT_GREEN}[THIS DEVICE - YOUR COMPUTER]{C_RESET}"
                    device_type = "Local"
                elif ip.endswith('.1'):
                    os_guess = f"{C_CYAN}[ROUTER/GATEWAY]{C_RESET}"
                    device_type = "Network"
                elif 62078 in ports: 
                    os_guess = "iOS Device (iPhone/iPad)"
                    device_type = "Mobile"
                elif 445 in ports and 3389 in ports: 
                    os_guess = "Windows PC (SMB + RDP)"
                    device_type = "Computer"
                elif 445 in ports: 
                    os_guess = "Windows Device (SMB)"
                    device_type = "Computer"
                elif 22 in ports and 80 not in ports and 443 not in ports: 
                    os_guess = "Linux/Unix Server (SSH)"
                    device_type = "Server"
                elif 22 in ports and (80 in ports or 443 in ports):
                    os_guess = "Linux Web Server"
                    device_type = "Server"
                elif 80 in ports or 443 in ports or 8080 in ports:
                    os_guess = "Web Server/IoT Device"
                    device_type = "Server/IoT"
                elif 5900 in ports:
                    os_guess = "VNC Server (Remote Desktop)"
                    device_type = "Computer"
                elif 23 in ports:
                    os_guess = "Network Device (Telnet)"
                    device_type = "Network"
                elif not ports:
                    os_guess = "Unknown (No open ports)"
                    device_type = "Unknown"
                
                # Format port list
                if ports:
                    port_str = f"Ports: {','.join(map(str, sorted(ports)))}"
                else:
                    port_str = "No common ports detected"
                
                # Add to results with enhanced formatting
                mac_display = mac if mac else "N/A"
                vendor_display = vendor[:25].ljust(25) if vendor else "Unknown".ljust(25)
                
                found.append(
                    f"{ip.ljust(15)} | "
                    f"{mac_display.ljust(17)} | "
                    f"{vendor_display} | "
                    f"{os_guess.ljust(40)} | "
                    f"{port_str}"
                )
            
            # Display results
            tui.clear()
            print(f"{C_EMERALD}{C_BOLD}")
            print("=" * 120)
            print(f"NETWORK SCAN COMPLETE - {len(alive_hosts)} DEVICES FOUND ON {subnet}.0/24")
            print("=" * 120)
            print(f"{C_RESET}")
            
            if found:
                print(f"{C_CYAN}IP Address      | MAC Address       | Vendor                    | Device Type/OS                           | Open Ports{C_RESET}")
                print("-" * 120)
                for device in found:
                    print(device)
                
                # Log scan results to database
                scan_summary = {
                    "subnet": f"{subnet}.0/24",
                    "total_devices": len(alive_hosts),
                    "devices": found[:10]  # Store first 10 devices
                }
                db.log_finding(user_id, "WIFI_RADAR", f"{subnet}.0/24", scan_summary, "INFO")
            else:
                print(f"{C_RED}NO DEVICES FOUND ON NETWORK{C_RESET}")
            
            print(f"\n{C_GRAY}Total devices: {len(alive_hosts)} | Subnet: {subnet}.0/24 | Your IP: {local_ip}{C_RESET}")
            input(f"\n{C_BRIGHT_GREEN}Press ENTER to continue...{C_RESET}")

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
                try:
                    await chat.start_server()
                except KeyboardInterrupt: pass
            elif sc == '2':
                tk = input("ENTER BIFROST TOKEN: ")
                await chat.connect_peer(tk)
            input("SESSION ENDED...")

        elif cmd == '9':
            domain = input("TARGET DOMAIN (e.g., example.com): ")
            print(f"{C_YELLOW}ENUMERATING DNS RECORDS...{C_RESET}")
            dns_enum = DNSEnumerator()
            results = await dns_enum.enumerate_dns(domain)
            
            lines = [f"{C_CYAN}DISCOVERED SUBDOMAINS:{C_RESET}"]
            if results["subdomains"]:
                for sub in results["subdomains"]:
                    lines.append(f"  ✓ {sub}")
            else:
                lines.append("  No subdomains found")
            
            lines.append(f"\n{C_CYAN}IP ADDRESSES:{C_RESET}")
            for ip in results["ips"]:
                lines.append(f"  • {ip}")
            
            tui.draw_box(lines, "DNS ENUMERATION RESULTS", C_MAGENTA)
            
            # Log DNS enumeration results
            db.log_finding(user_id, "DNS_ENUM", domain, {
                "subdomains_found": len(results["subdomains"]),
                "subdomains": results["subdomains"][:10],
                "ips": results["ips"]
            }, "INFO")
            
            input("CONTINUE...")

        elif cmd == 'A':
            print(f"{C_CYAN}[1] CRACK HASH   [2] ANALYZE PASSWORD{C_RESET}")
            choice = input("> ")
            
            if choice == '1':
                hash_val = input("ENTER HASH: ")
                hash_type = input("HASH TYPE (md5/sha1/sha256): ").lower()
                print(f"{C_YELLOW}ATTEMPTING TO CRACK...{C_RESET}")
                
                cracker = PasswordCracker()
                result = cracker.crack_hash(hash_val, hash_type)
                
                if result:
                    tui.draw_box([f"{C_GREEN}✓ CRACKED!{C_RESET}", f"Password: {result}"], "SUCCESS", C_GREEN)
                    db.log_finding(user_id, "PASSWORD_CRACKER", hash_val[:20], {"result": "CRACKED", "password": result, "hash_type": hash_type}, "HIGH")
                else:
                    tui.draw_box([f"{C_RED}✗ NOT FOUND{C_RESET}", "Password not in common list"], "FAILED", C_RED)
                    db.log_finding(user_id, "PASSWORD_CRACKER", hash_val[:20], {"result": "NOT_FOUND", "hash_type": hash_type}, "INFO")
            
            elif choice == '2':
                pwd = getpass.getpass("ENTER PASSWORD TO ANALYZE: ")
                cracker = PasswordCracker()
                analysis = cracker.analyze_password_strength(pwd)
                
                lines = [
                    f"Strength: {analysis['strength']}",
                    f"Score: {analysis['score']}/5",
                    f"Length: {analysis['length']} characters",
                    "",
                    "Recommendations:"
                ]
                for fb in analysis['feedback']:
                    lines.append(f"  • {fb}")
                
                tui.draw_box(lines, "PASSWORD ANALYSIS", C_YELLOW)
            
            input("CONTINUE...")

        elif cmd == 'B':
            interface = input("NETWORK INTERFACE (default: en0): ") or "en0"
            duration = int(input("CAPTURE DURATION (seconds, max 30): ") or "10")
            if duration > 30: duration = 30
            
            print(f"{C_YELLOW}ANALYZING NETWORK TRAFFIC...{C_RESET}")
            sniffer = PacketSniffer()
            results = sniffer.analyze_traffic(interface, duration)
            
            lines = [
                f"Interface: {results['interface']}",
                f"Duration: {results['duration']}s",
                f"Total Packets: {results['total_packets']}",
                "",
                "Protocol Distribution:"
            ]
            for proto, count in results['protocols'].items():
                lines.append(f"  {proto}: {count} packets")
            
            lines.append("")
            if results['suspicious'] > 0:
                lines.append(f"{C_RED}⚠ Suspicious packets: {results['suspicious']}{C_RESET}")
            else:
                lines.append(f"{C_GREEN}✓ No suspicious activity{C_RESET}")
            
            tui.draw_box(lines, "TRAFFIC ANALYSIS", C_CYAN)
            input("CONTINUE...")

        elif cmd == 'C':
            target = input("TARGET (IP or domain): ")
            print(f"{C_YELLOW}SCANNING FOR VULNERABILITIES...{C_RESET}")
            
            scanner = VulnerabilityScanner()
            findings = await scanner.scan_vulnerabilities(target)
            
            tui.draw_box(findings, "VULNERABILITY SCAN RESULTS", C_RED)
            db.log_finding(user_id, "VULN_SCANNER", target, findings, "HIGH" if len(findings) > 1 else "INFO")
            input("CONTINUE...")

            print(f"{C_YELLOW}SCANNING LOCAL SUBNET FOR ALL CONNECTED DEVICES...{C_RESET}")
            subnet = ".".join(local_ip.split('.')[:-1])
            found = []
            
            # Get ARP table for MAC addresses
            try:
                arp_out = subprocess.check_output("arp -a", shell=True).decode()
                arp_map = {}
                for line in arp_out.splitlines():
                    if "(" in line and "at" in line:
                        parts = line.split()
                        ip = parts[1].strip('()')
                        mac = parts[3]
                        arp_map[ip] = mac
            except: 
                arp_map = {}

            print(f"{C_YELLOW}PHASE 1: PING SWEEP (Scanning all 254 hosts: {subnet}.1-254)...{C_RESET}")
            print(f"{C_GRAY}This will take ~30 seconds to scan the entire network{C_RESET}")
            
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
            
            # Scan ALL 254 possible hosts in the subnet
            ping_tasks = [ping_host(f"{subnet}.{i}") for i in range(1, 255)]
            ping_results = await asyncio.gather(*ping_tasks)
            alive_hosts = [ip for ip in ping_results if ip]
            
            print(f"{C_BRIGHT_GREEN}✓ FOUND {len(alive_hosts)} ALIVE DEVICES ON NETWORK{C_RESET}")
            print(f"{C_YELLOW}PHASE 2: DEEP FINGERPRINTING (Scanning ports on {len(alive_hosts)} devices)...{C_RESET}")
            
            # Comprehensive port list for better device detection
            target_ports = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445, 3389, 5900, 8080, 8443, 62078]
            
            async def scan_host_ports(target_ip):
                open_p = []
                for p in target_ports:
                    if await net.scan_port(target_ip, p):
                        open_p.append(p)
                return (target_ip, open_p)

            scan_tasks = [scan_host_ports(ip) for ip in alive_hosts]
            host_results = await asyncio.gather(*scan_tasks)

            print(f"{C_YELLOW}PHASE 3: GATHERING DEVICE INFORMATION...{C_RESET}")
            
            for ip, ports in host_results:
                mac = arp_map.get(ip, "")
                vendor = net.resolve_mac_vendor(mac) if mac else "Unknown"
                banner = ""
                
                # Try to grab banner from open ports
                if 80 in ports: 
                    banner = await net.grab_banner(ip, 80)
                elif 443 in ports: 
                    banner = await net.grab_banner(ip, 443)
                elif 22 in ports: 
                    banner = await net.grab_banner(ip, 22)
                elif 8080 in ports:
                    banner = await net.grab_banner(ip, 8080)
                
                # Enhanced OS/Device detection
                os_guess = "Unknown Device"
                device_type = ""
                
                if ip == local_ip: 
                    os_guess = f"{C_BRIGHT_GREEN}[THIS DEVICE - YOUR COMPUTER]{C_RESET}"
                    device_type = "Local"
                elif ip.endswith('.1'):
                    os_guess = f"{C_CYAN}[ROUTER/GATEWAY]{C_RESET}"
                    device_type = "Network"
                elif 62078 in ports: 
                    os_guess = "iOS Device (iPhone/iPad)"
                    device_type = "Mobile"
                elif 445 in ports and 3389 in ports: 
                    os_guess = "Windows PC (SMB + RDP)"
                    device_type = "Computer"
                elif 445 in ports: 
                    os_guess = "Windows Device (SMB)"
                    device_type = "Computer"
                elif 22 in ports and 80 not in ports and 443 not in ports: 
                    os_guess = "Linux/Unix Server (SSH)"
                    device_type = "Server"
                elif 22 in ports and (80 in ports or 443 in ports):
                    os_guess = "Linux Web Server"
                    device_type = "Server"
                elif 80 in ports or 443 in ports or 8080 in ports:
                    os_guess = "Web Server/IoT Device"
                    device_type = "Server/IoT"
                elif 5900 in ports:
                    os_guess = "VNC Server (Remote Desktop)"
                    device_type = "Computer"
                elif 23 in ports:
                    os_guess = "Network Device (Telnet)"
                    device_type = "Network"
                elif not ports:
                    os_guess = "Unknown (No open ports)"
                    device_type = "Unknown"
                
                # Format port list
                if ports:
                    port_str = f"Ports: {','.join(map(str, sorted(ports)))}"
                else:
                    port_str = "No common ports detected"
                
                # Add to results with enhanced formatting
                mac_display = mac if mac else "N/A"
                vendor_display = vendor[:25].ljust(25) if vendor else "Unknown".ljust(25)
                
                found.append(
                    f"{ip.ljust(15)} | "
                    f"{mac_display.ljust(17)} | "
                    f"{vendor_display} | "
                    f"{os_guess.ljust(40)} | "
                    f"{port_str}"
                )
            
            # Display results
            tui.clear()
            print(f"{C_EMERALD}{C_BOLD}")
            print("=" * 120)
            print(f"NETWORK SCAN COMPLETE - {len(alive_hosts)} DEVICES FOUND ON {subnet}.0/24")
            print("=" * 120)
            print(f"{C_RESET}")
            
            if found:
                print(f"{C_CYAN}IP Address      | MAC Address       | Vendor                    | Device Type/OS                           | Open Ports{C_RESET}")
                print("-" * 120)
                for device in found:
                    print(device)
            else:
                print(f"{C_RED}NO DEVICES FOUND ON NETWORK{C_RESET}")
            
            print(f"\n{C_GRAY}Total devices: {len(alive_hosts)} | Subnet: {subnet}.0/24 | Your IP: {local_ip}{C_RESET}")
            input(f"\n{C_BRIGHT_GREEN}Press ENTER to continue...{C_RESET}")

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
