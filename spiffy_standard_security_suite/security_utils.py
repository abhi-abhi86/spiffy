"""
Security Utilities Module

This module provides defensive utility classes for the Spiffy Security Tool:
- PasswordPolicyEnforcer: Enforces strong password policies
- InputSanitizer: Sanitizes user input to prevent SQL injection
- TOTPGenerator: Handles Time-based One-Time Password (2FA) generation and validation
"""

import re
import pyotp
import qrcode
from io import BytesIO
from typing import Tuple


class PasswordPolicyEnforcer:
    """
    Enforces strong password policies to ensure user account security.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    
    MIN_LENGTH = 12
    
    def __init__(self):
        self.uppercase_pattern = re.compile(r'[A-Z]')
        self.lowercase_pattern = re.compile(r'[a-z]')
        self.digit_pattern = re.compile(r'\d')
        self.special_pattern = re.compile(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]')
    
    def check_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validates password against security policy.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (success: bool, message: str)
            - success: True if password meets all requirements
            - message: Descriptive message about validation result
        """
        if not password:
            return False, "ERROR: Password cannot be empty."
        
        if len(password) < self.MIN_LENGTH:
            return False, f"ERROR: Password must be at least {self.MIN_LENGTH} characters long."
        
        if not self.uppercase_pattern.search(password):
            return False, "ERROR: Password must contain at least one uppercase letter."
        
        if not self.lowercase_pattern.search(password):
            return False, "ERROR: Password must contain at least one lowercase letter."
        
        if not self.digit_pattern.search(password):
            return False, "ERROR: Password must contain at least one digit."
        
        if not self.special_pattern.search(password):
            return False, "ERROR: Password must contain at least one special character (!@#$%^&* etc.)."
        
        return True, "SUCCESS: Password meets security requirements."


class InputSanitizer:
    """
    Sanitizes user input to prevent SQL injection and other attacks.
    
    Note: This provides an additional layer of defense. The primary protection
    is parameterized queries, which are already used in the DatabaseManager.
    """
    
    # Dangerous SQL keywords and patterns
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'DECLARE', 'CAST', 'CONVERT', '--', ';--',
        'xp_', 'sp_', 'INFORMATION_SCHEMA', 'SYSOBJECTS', 'SYSCOLUMNS'
    ]
    
    def __init__(self):
        # Pattern to detect SQL injection attempts
        self.sql_injection_pattern = re.compile(
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)|"
            r"(--|;--|\/\*|\*\/|xp_|sp_)",
            re.IGNORECASE
        )
    
    def sanitize_sql(self, input_string: str) -> str:
        """
        Sanitizes input to prevent SQL injection.
        
        Args:
            input_string: The user input to sanitize
            
        Returns:
            Sanitized string safe for use in database operations
            
        Raises:
            ValueError: If input contains dangerous SQL patterns
        """
        if not input_string:
            return input_string
        
        # Check for SQL injection patterns
        if self.sql_injection_pattern.search(input_string):
            raise ValueError(
                "SECURITY ALERT: Input contains potentially dangerous SQL patterns. "
                "Please use only alphanumeric characters and basic punctuation."
            )
        
        # Remove any null bytes
        sanitized = input_string.replace('\x00', '')
        
        # Limit length to prevent buffer overflow attacks
        max_length = 1000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    def validate_username(self, username: str) -> Tuple[bool, str]:
        """
        Validates username format.
        
        Args:
            username: The username to validate
            
        Returns:
            Tuple of (valid: bool, message: str)
        """
        if not username:
            return False, "ERROR: Username cannot be empty."
        
        if len(username) < 3:
            return False, "ERROR: Username must be at least 3 characters."
        
        if len(username) > 50:
            return False, "ERROR: Username must not exceed 50 characters."
        
        # Allow alphanumeric, underscore, hyphen, and dot
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            return False, "ERROR: Username can only contain letters, numbers, dots, underscores, and hyphens."
        
        return True, "Valid username."


class TOTPGenerator:
    """
    Handles Time-based One-Time Password (TOTP) generation and validation for 2FA.
    
    Uses the TOTP algorithm (RFC 6238) with:
    - 6-digit codes
    - 30-second time windows
    - SHA-1 hashing (standard for compatibility with authenticator apps)
    """
    
    def __init__(self):
        self.issuer_name = "Spiffy Security Tool"
    
    def generate_secret(self) -> str:
        """
        Generates a new random TOTP secret for a user.
        
        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """
        Generates a QR code URI for authenticator apps.
        
        Args:
            username: The username for the TOTP account
            secret: The TOTP secret key
            
        Returns:
            otpauth:// URI that can be encoded as a QR code
        """
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
        return uri
    
    def generate_qr_ascii(self, username: str, secret: str) -> str:
        """
        Generates an ASCII art QR code for terminal display.
        
        Args:
            username: The username for the TOTP account
            secret: The TOTP secret key
            
        Returns:
            ASCII representation of the QR code
        """
        uri = self.generate_qr_code(username, secret)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Convert to ASCII art using terminal-friendly characters
        # Use full block (█) for black and space for white
        ascii_qr = []
        matrix = qr.get_matrix()
        
        for row in matrix:
            line = ""
            for cell in row:
                # Use double characters for better aspect ratio in terminal
                line += "██" if cell else "  "
            ascii_qr.append(line)
        
        return "\n".join(ascii_qr)
    
    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verifies a TOTP token against the secret.
        
        Args:
            secret: The user's TOTP secret
            token: The 6-digit token to verify
            window: Number of time windows to check (default 1 = ±30 seconds)
                   Allows for slight time drift between server and client
            
        Returns:
            True if token is valid, False otherwise
        """
        if not token or not secret:
            return False
        
        # Remove any whitespace from token
        token = token.strip()
        
        # Validate token format (must be 6 digits)
        if not re.match(r'^\d{6}$', token):
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    def get_current_token(self, secret: str) -> str:
        """
        Gets the current TOTP token for a secret (for testing purposes).
        
        Args:
            secret: The TOTP secret
            
        Returns:
            Current 6-digit TOTP token
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
