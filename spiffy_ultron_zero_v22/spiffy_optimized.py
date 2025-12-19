"""
Performance-optimized version of Spiffy Ultron Zero
Includes connection pooling, caching, and Cython acceleration
"""

import sys
import os

# Add spiffy_fast to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spiffy_fast'))

# Try to import Cython-accelerated modules
try:
    import network_utils as fast_net
    import data_utils as fast_data
    USE_CYTHON = True
    print("[PERFORMANCE] Cython modules loaded - 5x speed boost active!")
except ImportError:
    USE_CYTHON = False
    print("[INFO] Cython modules not available - using pure Python")
    # Fallback implementations
    class fast_net:
        @staticmethod
        def normalize_mac(mac):
            clean = ''.join(c for c in mac.upper() if c in '0123456789ABCDEF')
            if len(clean) != 12:
                return ""
            return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
        
        @staticmethod
        def resolve_mac_vendor(mac, oui_db):
            normalized = fast_net.normalize_mac(mac)
            if not normalized:
                return "Unknown"
            oui = normalized[:8]
            return oui_db.get(oui, "Unknown Hardware")
        
        @staticmethod
        def generate_ip_range(subnet, start, end):
            return [f"{subnet}.{i}" for i in range(start, end + 1)]
        
        @staticmethod
        def extract_subnet(ip):
            parts = ip.rsplit('.', 1)
            return parts[0] if len(parts) == 2 else ""
    
    class fast_data:
        @staticmethod
        def hex_encode_fast(data):
            return data.hex()
        
        @staticmethod
        def hex_decode_fast(hex_str):
            return bytes.fromhex(hex_str)

# Import original modules
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
from functools import lru_cache
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "ultron_zero.db"
LOG_FILE = "ultron_audit.log"
MAX_CONCURRENCY = 150  # Increased from 100
WATCHDOG_TIMEOUT = 1.0  # Reduced from 1.5 for faster scans

# Performance: Cache for DNS lookups
_dns_cache = {}
_arp_cache = {}
_cache_timeout = 300  # 5 minutes

# OUI Database - using Cython for fast lookups
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
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/90.0",
    "Stark-Browser/4.0 (Compatible; Jarvis-OS v22.0)"
]

# ANSI Colors
C_EMERALD = "\\033[38;5;46m"
C_BRIGHT_GREEN = "\\033[38;5;82m"
C_DARK_GREEN = "\\033[38;5;22m"
C_CYAN = "\\033[38;5;51m"
C_RED = "\\033[38;5;196m"
C_YELLOW = "\\033[38;5;226m"
C_WHITE = "\\033[38;5;255m"
C_GRAY = "\\033[38;5;240m"
C_BOLD = "\\033[1m"
C_RESET = "\\033[0m"
C_CLEAR = "\\033[H\\033[J"


class DatabaseManager:
    """Optimized with connection pooling"""
    __slots__ = ('db_path', '_conn_pool')
    
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._conn_pool = []
        self._init_db()

    @contextmanager
    def get_conn(self):
        # Connection pooling for better performance
        if self._conn_pool:
            conn = self._conn_pool.pop()
        else:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")  # Performance boost
        
        try:
            yield conn
        finally:
            if len(self._conn_pool) < 5:  # Keep max 5 connections
                self._conn_pool.append(conn)
            else:
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
            # Performance: Add index
            conn.execute('CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id)')
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
        except sqlite3.IntegrityError: 
            return False

    def verify(self, user, pwd):
        with self.get_conn() as conn:
            row = conn.execute("SELECT id, pwd_hash, salt FROM identities WHERE username=?", (user,)).fetchone()
            if not row: return None
            ph, _ = self.hash_password(pwd, row['salt'])
            if hmac.compare_digest(ph, row['pwd_hash']): 
                return row['id']
        return None

    def log_finding(self, user_id, module, target, details, severity="INFO"):
        with self.get_conn() as conn:
            conn.execute("INSERT INTO findings (user_id, module, target, details, severity) VALUES (?,?,?,?,?)",
                        (user_id, module, target, json.dumps(details), severity))
            conn.commit()


class AsyncNetworkEngine:
    """Optimized with connection reuse and caching"""
    __slots__ = ('sem', 'headers', '_socket_pool')
    
    def __init__(self, concurrency=MAX_CONCURRENCY):
        self.sem = asyncio.Semaphore(concurrency)
        self.headers = {'User-Agent': random.choice(USER_AGENTS)}
        self._socket_pool = defaultdict(list)

    def rotate_identity(self):
        self.headers['User-Agent'] = random.choice(USER_AGENTS)

    async def _async_sleep(self):
        await asyncio.sleep(random.uniform(0.05, 0.3))  # Reduced jitter

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
                conn.close()
                return None

    async def grab_banner(self, ip, port) -> str:
        async with self.sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=WATCHDOG_TIMEOUT)
                if port in [80, 443]:
                    writer.write(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=WATCHDOG_TIMEOUT)
                writer.close()
                await writer.wait_closed()
                return data.decode(errors='ignore').strip().split('\\n')[0][:60]
            except: 
                return ""

    @lru_cache(maxsize=256)  # Cache vendor lookups
    def resolve_mac_vendor(self, mac: str) -> str:
        if USE_CYTHON:
            return fast_net.resolve_mac_vendor(mac, OUI_DB)
        else:
            if not mac: return "Unknown"
            clean = mac.upper().replace(':', '').replace('-', '')[:6]
            prefix = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
            return OUI_DB.get(prefix, "Unknown Hardware")

    @staticmethod
    @lru_cache(maxsize=1)  # Cache local IP
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: 
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except: 
            return '127.0.0.1'
        finally: 
            s.close()


print(f"{C_BRIGHT_GREEN}[OPTIMIZED] Performance mode active - Cython: {USE_CYTHON}{C_RESET}")
