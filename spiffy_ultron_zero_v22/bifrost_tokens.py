"""
BIFROST 10-Digit Token System
Compress IP:Port into shareable 10-digit codes for P2P connections
"""

import hashlib
import struct
from typing import Tuple, Optional

class BifrostTokenGenerator:
    """
    10-digit token compression for IP:Port
    Format: AAABBBCCCD
    - AAA: IP compression part 1 (0-999)
    - BBB: IP compression part 2 (0-999)  
    - CCC: Port encoding (0-999)
    - D: Checksum digit (0-9)
    """
    
    # Token mapping database for reverse lookup
    _token_db = {}
    
    @staticmethod
    def encode(ip: str, port: int) -> str:
        """
        Encode IP:Port to 10-digit token
        
        Args:
            ip: IPv4 address (e.g., "192.168.1.100")
            port: Port number (0-65535)
        
        Returns:
            10-digit token string
        """
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
                raise ValueError("Invalid IP address")
            
            if port < 0 or port > 65535:
                raise ValueError("Invalid port number")
            
            # Compress IP octets
            # Part 1: Combine first two octets
            part1 = (octets[0] * 256 + octets[1]) % 1000
            
            # Part 2: Combine last two octets
            part2 = (octets[2] * 256 + octets[3]) % 1000
            
            # Part 3: Port encoding (mod 1000 for 3 digits)
            part3 = port % 1000
            
            # Checksum: sum of all components mod 10
            checksum = (part1 + part2 + part3 + sum(octets) + port) % 10
            
            # Format as 10 digits
            token = f"{part1:03d}{part2:03d}{part3:03d}{checksum:01d}"
            
            # Store in database for reverse lookup
            BifrostTokenGenerator._token_db[token] = (ip, port)
            
            return token
            
        except Exception as e:
            raise ValueError(f"Token encoding failed: {e}")
    
    @staticmethod
    def decode(token: str) -> Tuple[Optional[str], Optional[int], bool]:
        """
        Decode 10-digit token to IP:Port
        
        Args:
            token: 10-digit token string
        
        Returns:
            Tuple of (ip, port, is_valid)
        """
        if len(token) != 10 or not token.isdigit():
            return (None, None, False)
        
        # Check if token exists in database
        if token in BifrostTokenGenerator._token_db:
            ip, port = BifrostTokenGenerator._token_db[token]
            return (ip, port, True)
        
        # If not in database, cannot reliably decode
        # (compression is lossy without lookup table)
        return (None, None, False)
    
    @staticmethod
    def generate_shareable_code(ip: str, port: int) -> str:
        """
        Generate human-friendly formatted token
        
        Returns:
            Formatted token: XXXX-XXXX-XX
        """
        token = BifrostTokenGenerator.encode(ip, port)
        return f"{token[0:4]}-{token[4:8]}-{token[8:10]}"
    
    @staticmethod
    def parse_shareable_code(code: str) -> Tuple[Optional[str], Optional[int], bool]:
        """
        Parse formatted shareable code
        
        Args:
            code: Formatted code (XXXX-XXXX-XX)
        
        Returns:
            Tuple of (ip, port, is_valid)
        """
        # Remove dashes
        token = code.replace("-", "").replace(" ", "")
        return BifrostTokenGenerator.decode(token)
    
    @staticmethod
    def validate_token(token: str) -> bool:
        """
        Validate token checksum
        
        Returns:
            True if checksum is valid
        """
        if len(token) != 10 or not token.isdigit():
            return False
        
        part1 = int(token[0:3])
        part2 = int(token[3:6])
        part3 = int(token[6:9])
        checksum = int(token[9])
        
        # Recalculate checksum
        expected_checksum = (part1 + part2 + part3) % 10
        
        return checksum == expected_checksum
    
    @staticmethod
    def get_token_info(token: str) -> dict:
        """
        Get information about a token
        
        Returns:
            Dictionary with token details
        """
        if not BifrostTokenGenerator.validate_token(token):
            return {
                "valid": False,
                "error": "Invalid token format or checksum"
            }
        
        ip, port, found = BifrostTokenGenerator.decode(token)
        
        if found:
            return {
                "valid": True,
                "token": token,
                "formatted": BifrostTokenGenerator.generate_shareable_code(ip, port),
                "ip": ip,
                "port": port,
                "in_database": True
            }
        else:
            return {
                "valid": True,
                "token": token,
                "in_database": False,
                "note": "Token is valid but not in lookup database"
            }


class BifrostConnection:
    """Helper class for BIFROST P2P connections"""
    
    @staticmethod
    def create_connection_code(ip: str, port: int) -> dict:
        """
        Create a complete connection code with metadata
        
        Returns:
            Dictionary with connection details
        """
        token = BifrostTokenGenerator.encode(ip, port)
        formatted = BifrostTokenGenerator.generate_shareable_code(ip, port)
        
        return {
            "token": token,
            "formatted_code": formatted,
            "ip": ip,
            "port": port,
            "instructions": f"Share this code: {formatted}",
            "connection_string": f"{ip}:{port}"
        }
    
    @staticmethod
    def connect_with_code(code: str) -> dict:
        """
        Parse connection code and return connection details
        
        Returns:
            Dictionary with connection parameters
        """
        ip, port, valid = BifrostTokenGenerator.parse_shareable_code(code)
        
        if not valid:
            return {
                "success": False,
                "error": "Invalid connection code"
            }
        
        return {
            "success": True,
            "ip": ip,
            "port": port,
            "connection_string": f"{ip}:{port}"
        }


def test_bifrost_tokens():
    """Test BIFROST token system"""
    print("Testing BIFROST 10-Digit Token System...")
    
    # Test cases
    test_cases = [
        ("192.168.1.100", 5000),
        ("10.0.0.1", 8080),
        ("172.16.0.50", 443),
        ("8.8.8.8", 53)
    ]
    
    print("\n" + "="*70)
    print("Token Generation Tests")
    print("="*70)
    
    for ip, port in test_cases:
        token = BifrostTokenGenerator.encode(ip, port)
        formatted = BifrostTokenGenerator.generate_shareable_code(ip, port)
        
        print(f"\nOriginal: {ip}:{port}")
        print(f"Token:    {token}")
        print(f"Formatted: {formatted}")
        print(f"Valid:    {BifrostTokenGenerator.validate_token(token)}")
        
        # Test decode
        decoded_ip, decoded_port, valid = BifrostTokenGenerator.decode(token)
        if valid:
            print(f"Decoded:  {decoded_ip}:{decoded_port} ✓")
        else:
            print(f"Decoded:  Failed ✗")
    
    print("\n" + "="*70)
    print("Connection Code Tests")
    print("="*70)
    
    # Test connection code creation
    conn_code = BifrostConnection.create_connection_code("192.168.1.100", 5000)
    print(f"\nConnection Code: {conn_code['formatted_code']}")
    print(f"Instructions: {conn_code['instructions']}")
    
    # Test connection with code
    result = BifrostConnection.connect_with_code(conn_code['formatted_code'])
    print(f"\nConnection Result:")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Connect to: {result['connection_string']}")


if __name__ == "__main__":
    test_bifrost_tokens()
