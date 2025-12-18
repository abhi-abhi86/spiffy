#dont run this at any cost plez !!!!!!!!!!!!!!!!!!!!!!!!‼


import sqlite3
import logging
from contextlib import contextmanager

# Configure logging to track security events safely
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

@contextmanager
def database_connection():
    """Context manager for safe database connection handling."""
    conn = sqlite3.connect(':memory:')
    try:
        yield conn
    finally:
        conn.close()

def setup_db(conn):
    """Initializes the database schema and seed data."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                secret_data TEXT
            )
        ''')
        
        # Using a list of tuples for cleaner bulk insertion
        users = [
            ('admin', 'p@ssword123', 'Top Secret Project X'),
            ('alice', 'alice_key', 'Alice\'s private diary'),
            ('bob', 'bob_secure_789', 'Bob\'s encrypted backup keys')
        ]
        cursor.executemany("INSERT INTO users (username, password, secret_data) VALUES (?, ?, ?)", users)
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database setup failed: {e}")
        raise

def vulnerable_login(conn, username):
    """
    DEMONSTRATION ONLY: This function is intentionally insecure.
    Uses string formatting which allows SQL Injection.
    """
    cursor = conn.cursor()
    query = f"SELECT secret_data FROM users WHERE username = '{username}'"
    
    logger.warning(f"Executing INSECURE query: {query}")
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except sqlite3.Error as e:
        return f"Database Error: {e}"

def secure_login(conn, username):
    """
    BEST PRACTICE: Uses parameterized queries to prevent SQL Injection.
    Input is treated as data, not executable code.
    """
    logger.info(f"Executing secure query for user: {username}")
    try:
        cursor = conn.cursor()
        # The '?' is a placeholder; the driver ensures 'username' is escaped correctly.
        cursor.execute("SELECT secret_data FROM users WHERE username = ?", (username,))
        return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Secure query failed: {e}")
        return None

def run_security_demonstration():
    """Orchestrates the security comparison tests."""
    with database_connection() as conn:
        setup_db(conn)

        print("\n" + "="*50)
        print("SCENARIO 1: Valid Login (Vulnerable Function)")
        print("="*50)
        result = vulnerable_login(conn, 'admin')
        print(f"Data Retrieved: {result}")

        print("\n" + "="*50)
        print("SCENARIO 2: SQL Injection Attack (Vulnerable Function)")
        print("="*50)
        # The attacker inputs a string that alters the logic of the SQL statement
        malicious_input = "' OR '1'='1"
        attack_result = vulnerable_login(conn, malicious_input)
        print(f"ATTACK SUCCESSFUL! Bypassed login and got: {attack_result}")

        print("\n" + "="*50)
        print("SCENARIO 3: Identical Attack (Secure Function)")
        print("="*50)
        secure_result = secure_login(conn, malicious_input)
        if secure_result is None:
            print("ATTACK BLOCKED: No matching user found for the malicious string.")
        else:
            print(f"Warning: Unexpected data retrieved: {secure_result}")

if __name__ == "__main__":
    run_security_demonstration()
