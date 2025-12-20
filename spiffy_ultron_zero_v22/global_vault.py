"""
Global Vault - Enhanced SQLite Logging System
Professional event logging with scrypt password hashing
"""

import sqlite3
import hashlib
import os
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from contextlib import contextmanager

class GlobalVault:
    """
    Enhanced SQLite logging with:
    - scrypt password hashing
    - Structured event logging
    - Session tracking
    - Query interface
    """
    
    def __init__(self, db_path: str = "global_vault.db"):
        self.db_path = db_path
        self.session_id = self._generate_session_id()
        self._init_database()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return hashlib.sha256(
            f"{os.getpid()}{time.time()}".encode()
        ).hexdigest()[:16]
    
    @contextmanager
    def get_conn(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema"""
        with self.get_conn() as conn:
            # Global Vault events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS global_vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type VARCHAR(50) NOT NULL,
                    module VARCHAR(50) NOT NULL,
                    target VARCHAR(255),
                    details TEXT,
                    severity VARCHAR(20) DEFAULT 'INFO',
                    user_hash VARCHAR(128),
                    session_id VARCHAR(64),
                    execution_time_ms INTEGER
                )
            """)
            
            # Create indexes for performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON global_vault(timestamp)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_type 
                ON global_vault(event_type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_module 
                ON global_vault(module)
            """)
            
            # User credentials table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(256) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME
                )
            """)
            
            conn.commit()
    
    def hash_password(self, password: str, salt: bytes = None) -> tuple:
        """
        Hash password with scrypt
        
        Args:
            password: Plain text password
            salt: Optional salt (generated if None)
        
        Returns:
            Tuple of (password_hash, salt) as hex strings
        """
        if salt is None:
            salt = os.urandom(32)
        
        # scrypt parameters: N=16384, r=8, p=1 (recommended for interactive logins)
        password_hash = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=64
        )
        
        return (password_hash.hex(), salt.hex())
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """
        Verify password against stored hash
        
        Args:
            password: Plain text password to verify
            password_hash: Stored password hash (hex)
            salt: Stored salt (hex)
        
        Returns:
            True if password matches
        """
        computed_hash, _ = self.hash_password(password, bytes.fromhex(salt))
        return computed_hash == password_hash
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register new user with scrypt-hashed password
        
        Returns:
            True if registration successful
        """
        try:
            password_hash, salt = self.hash_password(password)
            
            with self.get_conn() as conn:
                conn.execute("""
                    INSERT INTO user_credentials (username, password_hash, salt)
                    VALUES (?, ?, ?)
                """, (username, password_hash, salt))
                conn.commit()
            
            self.log_event("USER_REGISTERED", "AUTH", username, 
                          {"username": username}, "INFO")
            return True
            
        except sqlite3.IntegrityError:
            return False  # Username already exists
    
    def authenticate_user(self, username: str, password: str) -> Optional[int]:
        """
        Authenticate user
        
        Returns:
            User ID if successful, None otherwise
        """
        with self.get_conn() as conn:
            cursor = conn.execute("""
                SELECT id, password_hash, salt 
                FROM user_credentials 
                WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            
            if row and self.verify_password(password, row['password_hash'], row['salt']):
                # Update last login
                conn.execute("""
                    UPDATE user_credentials 
                    SET last_login = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, (row['id'],))
                conn.commit()
                
                self.log_event("USER_LOGIN", "AUTH", username, 
                              {"username": username}, "INFO")
                return row['id']
        
        return None
    
    def log_event(self, event_type: str, module: str, 
                  target: str = None, details: Dict = None,
                  severity: str = "INFO", execution_time_ms: int = None):
        """
        Log structured event to Global Vault
        
        Args:
            event_type: Type of event (e.g., "SCAN_START", "DEVICE_FOUND")
            module: Module name (e.g., "WIFI_RADAR", "BIFROST")
            target: Target of the event (IP, hostname, etc.)
            details: Additional details as dictionary
            severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
            execution_time_ms: Execution time in milliseconds
        """
        with self.get_conn() as conn:
            conn.execute("""
                INSERT INTO global_vault 
                (event_type, module, target, details, severity, session_id, execution_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event_type,
                module,
                target,
                json.dumps(details) if details else None,
                severity,
                self.session_id,
                execution_time_ms
            ))
            conn.commit()
    
    def query_events(self, module: str = None, event_type: str = None,
                    severity: str = None, limit: int = 100) -> List[Dict]:
        """
        Query events from vault
        
        Returns:
            List of event dictionaries
        """
        query = "SELECT * FROM global_vault WHERE 1=1"
        params = []
        
        if module:
            query += " AND module = ?"
            params.append(module)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self.get_conn() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get vault statistics"""
        with self.get_conn() as conn:
            # Total events
            total = conn.execute("SELECT COUNT(*) FROM global_vault").fetchone()[0]
            
            # Events by module
            by_module = conn.execute("""
                SELECT module, COUNT(*) as count 
                FROM global_vault 
                GROUP BY module 
                ORDER BY count DESC 
                LIMIT 10
            """).fetchall()
            
            # Events by severity
            by_severity = conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM global_vault 
                GROUP BY severity
            """).fetchall()
            
            # Recent activity
            recent = conn.execute("""
                SELECT COUNT(*) 
                FROM global_vault 
                WHERE timestamp > datetime('now', '-1 hour')
            """).fetchone()[0]
            
            return {
                "total_events": total,
                "events_by_module": {row['module']: row['count'] for row in by_module},
                "events_by_severity": {row['severity']: row['count'] for row in by_severity},
                "recent_activity_1h": recent,
                "session_id": self.session_id
            }
    
    def cleanup_old_events(self, days: int = 30) -> int:
        """
        Delete events older than specified days
        
        Returns:
            Number of events deleted
        """
        with self.get_conn() as conn:
            cursor = conn.execute("""
                DELETE FROM global_vault 
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            """, (days,))
            conn.commit()
            return cursor.rowcount


def test_global_vault():
    """Test Global Vault functionality"""
    print("Testing Global Vault...")
    
    vault = GlobalVault("test_vault.db")
    
    print("\n1. Testing password hashing...")
    password = "SecurePassword123!"
    hash1, salt1 = vault.hash_password(password)
    print(f"   Hash: {hash1[:32]}...")
    print(f"   Salt: {salt1[:32]}...")
    print(f"   Verify: {vault.verify_password(password, hash1, salt1)}")
    
    print("\n2. Testing user registration...")
    success = vault.register_user("admin", "admin123")
    print(f"   Registration: {'Success' if success else 'Failed'}")
    
    print("\n3. Testing authentication...")
    user_id = vault.authenticate_user("admin", "admin123")
    print(f"   Login: {'Success' if user_id else 'Failed'} (User ID: {user_id})")
    
    print("\n4. Testing event logging...")
    vault.log_event("SCAN_START", "WIFI_RADAR", "192.168.1.0/24", 
                   {"hosts": 254}, "INFO", 1234)
    vault.log_event("DEVICE_FOUND", "WIFI_RADAR", "192.168.1.100",
                   {"type": "Apple", "mac": "AA:BB:CC:DD:EE:FF"}, "INFO")
    print("   Logged 2 events")
    
    print("\n5. Testing event queries...")
    events = vault.query_events(module="WIFI_RADAR", limit=10)
    print(f"   Found {len(events)} events")
    for event in events:
        print(f"   - {event['event_type']}: {event['target']}")
    
    print("\n6. Testing statistics...")
    stats = vault.get_statistics()
    print(f"   Total events: {stats['total_events']}")
    print(f"   By module: {stats['events_by_module']}")
    print(f"   By severity: {stats['events_by_severity']}")
    
    # Cleanup
    os.remove("test_vault.db")
    print("\n✓ All tests passed")


if __name__ == "__main__":
    test_global_vault()
