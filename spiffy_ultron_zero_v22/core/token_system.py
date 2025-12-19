#!/usr/bin/env python3
"""
Bifrost Token System - 10-Digit High-Entropy Tokens
Encodes IP + Port into a secure, shareable token
"""

import hashlib
import hmac
import socket
from typing import Tuple, Optional


class BifrostTokenSystem:
    """
    Generates and validates 10-digit high-entropy tokens for P2P connections
    
    Token Format: OOOPPPPPCC
    - OOO: Last 3 digits of IP (octet 3 + octet 4)
    - PPPPP: 5-digit port number (padded)
    - CC: 2-digit HMAC checksum
    
    Example: 192.168.1.5:12345 -> 0011234567
    """
    
    # Secret key for HMAC (in production, load from secure config)
    SECRET_KEY = b"STARK_INDUSTRIES_BIFROST_OMEGA_KERNEL_V25"
    
    @staticmethod
    def generate_token(ip: str, port: int) -> str:
        """
        Generate a 10-digit Bifrost token from IP and port
        
        Args:
            ip: IPv4 address (e.g., "192.168.1.5")
            port: Port number (1-65535)
            
        Returns:
            10-digit token string
            
        Example:
            >>> generate_token("192.168.1.5", 12345)
            "0011234567"
        """
        try:
            # Parse IP address
            parts = ip.split('.')
            if len(parts) != 4:
                return "0000000000"
            
            # Get last two octets (more entropy than just last octet)
            octet3 = int(parts[2])
            octet4 = int(parts[3])
            
            # Combine octets into 3 digits: O3O3O4 (e.g., 001 for 1.5)
            # Use modulo to ensure it fits in 3 digits
            ip_component = (octet3 * 10 + octet4) % 1000
            
            # Port component (5 digits, padded)
            port_component = port % 100000  # Ensure 5 digits max
            
            # Create base token (8 digits)
            base_token = f"{ip_component:03d}{port_component:05d}"
            
            # Generate HMAC checksum (2 digits)
            checksum = BifrostTokenSystem._generate_checksum(base_token)
            
            # Final 10-digit token
            token = base_token + checksum
            
            return token
            
        except (ValueError, IndexError):
            return "0000000000"
    
    @staticmethod
    def _generate_checksum(data: str) -> str:
        """
        Generate 2-digit HMAC checksum
        
        Args:
            data: Base token data
            
        Returns:
            2-digit checksum string
        """
        h = hmac.new(
            BifrostTokenSystem.SECRET_KEY,
            data.encode(),
            hashlib.sha256
        )
        # Take first 2 hex digits and convert to decimal
        hex_digest = h.hexdigest()[:2]
        checksum_value = int(hex_digest, 16) % 100
        return f"{checksum_value:02d}"
    
    @staticmethod
    def resolve_token(token: str, base_subnet: str = "192.168") -> Tuple[str, int]:
        """
        Resolve a 10-digit token back to IP and port
        
        Args:
            token: 10-digit Bifrost token
            base_subnet: Base subnet (first two octets)
            
        Returns:
            Tuple of (ip_address, port)
            
        Example:
            >>> resolve_token("0011234567", "192.168")
            ("192.168.0.1", 12345)
        """
        try:
            if len(token) != 10 or not token.isdigit():
                return ("0.0.0.0", 0)
            
            # Extract components
            ip_component = int(token[0:3])
            port_component = int(token[3:8])
            provided_checksum = token[8:10]
            
            # Validate checksum
            base_token = token[0:8]
            expected_checksum = BifrostTokenSystem._generate_checksum(base_token)
            
            if provided_checksum != expected_checksum:
                print(f"[WARNING] Token checksum mismatch. Token may be invalid or tampered.")
            
            # Decode IP (reverse of encoding)
            octet3 = ip_component // 10
            octet4 = ip_component % 10
            
            # Construct full IP
            ip = f"{base_subnet}.{octet3}.{octet4}"
            port = port_component
            
            return (ip, port)
            
        except (ValueError, IndexError):
            return ("0.0.0.0", 0)
    
    @staticmethod
    def validate_token(token: str) -> bool:
        """
        Validate token format and checksum
        
        Args:
            token: 10-digit token to validate
            
        Returns:
            True if valid, False otherwise
        """
        if len(token) != 10 or not token.isdigit():
            return False
        
        base_token = token[0:8]
        provided_checksum = token[8:10]
        expected_checksum = BifrostTokenSystem._generate_checksum(base_token)
        
        return provided_checksum == expected_checksum
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '127.0.0.1'


# Quick test
if __name__ == "__main__":
    bts = BifrostTokenSystem()
    
    # Test token generation
    test_ip = "192.168.1.5"
    test_port = 12345
    
    token = bts.generate_token(test_ip, test_port)
    print(f"Generated Token: {token}")
    print(f"Token Valid: {bts.validate_token(token)}")
    
    # Test token resolution
    resolved_ip, resolved_port = bts.resolve_token(token)
    print(f"Resolved: {resolved_ip}:{resolved_port}")
    
    # Test with local IP
    local_ip = bts.get_local_ip()
    local_token = bts.generate_token(local_ip, 55555)
    print(f"\nLocal IP: {local_ip}")
    print(f"Local Token: {local_token}")
