"""
OMEGA-INFINITY Hardware Fingerprinting Module
Precise device identification using port signatures and MAC OUI lookup
"""

import asyncio
import socket
from typing import Dict, List, Any, Optional
from collections import defaultdict

# Hardware signature ports
HARDWARE_SIGNATURES = {
    # Apple devices
    62078: "Apple Remote Desktop",
    5000: "Apple AirPlay",
    548: "Apple File Protocol",
    
    # Windows devices
    445: "Windows SMB",
    3389: "Windows RDP",
    135: "Windows RPC",
    
    # Google devices
    8008: "Google Cast",
    8009: "Google Cast SSL",
    
    # Samsung devices
    9000: "Samsung SmartView",
    7676: "Samsung AllShare",
    
    # Common services
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL"
}

# MAC OUI Database (Organizationally Unique Identifier)
OUI_DATABASE = {
    # Apple
    "00:03:93": "Apple",
    "00:0D:93": "Apple", 
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "3C:15:C2": "Apple",
    "A4:5E:60": "Apple",
    "B8:E8:56": "Apple",
    "DC:2B:61": "Apple",
    
    # Microsoft
    "00:50:F2": "Microsoft",
    "00:15:5D": "Microsoft",
    "00:03:FF": "Microsoft",
    
    # Google
    "F4:F5:D8": "Google",
    "00:1A:11": "Google",
    "D8:6C:63": "Google",
    "F8:8F:CA": "Google",
    
    # Samsung
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:B9": "Samsung",
    "00:16:32": "Samsung",
    "E8:50:8B": "Samsung",
    
    # Dell
    "00:14:22": "Dell",
    "B8:CA:3A": "Dell",
    
    # HP
    "00:1E:0B": "HP",
    "70:5A:B6": "HP",
    
    # Cisco
    "00:0A:41": "Cisco",
    "00:1B:D5": "Cisco"
}

# Device type classification rules
DEVICE_CLASSIFICATION = {
    "Apple": {
        "required_ports": [62078, 5000],
        "optional_ports": [548],
        "confidence_threshold": 1
    },
    "Windows": {
        "required_ports": [445],
        "optional_ports": [3389, 135],
        "confidence_threshold": 1
    },
    "Google": {
        "required_ports": [8008, 8009],
        "optional_ports": [],
        "confidence_threshold": 1
    },
    "Samsung": {
        "required_ports": [9000],
        "optional_ports": [7676],
        "confidence_threshold": 1
    }
}


class HardwareFingerprinter:
    """Advanced hardware detection using multiple techniques"""
    
    def __init__(self, timeout: float = 0.5):
        self.timeout = timeout
        self.results_cache = {}
    
    async def quick_port_check(self, ip: str, port: int) -> bool:
        """
        Lightning-fast port check with 0.5s timeout
        Returns immediately on timeout
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
    
    async def probe_signature_ports(self, ip: str) -> List[int]:
        """Probe all signature ports in parallel"""
        tasks = [
            self.quick_port_check(ip, port) 
            for port in HARDWARE_SIGNATURES.keys()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for port, result in zip(HARDWARE_SIGNATURES.keys(), results):
            if result is True:
                open_ports.append(port)
        
        return open_ports
    
    def classify_device_type(self, open_ports: List[int]) -> Dict[str, Any]:
        """
        Classify device type based on open ports
        Returns device type and confidence level
        """
        scores = defaultdict(int)
        
        for device_type, rules in DEVICE_CLASSIFICATION.items():
            # Check required ports
            required_found = sum(
                1 for port in rules["required_ports"] 
                if port in open_ports
            )
            
            # Check optional ports
            optional_found = sum(
                1 for port in rules["optional_ports"]
                if port in open_ports
            )
            
            # Calculate score
            if required_found >= rules["confidence_threshold"]:
                scores[device_type] = required_found * 10 + optional_found
        
        if not scores:
            return {
                "device_type": "Unknown",
                "confidence": "LOW",
                "score": 0
            }
        
        # Get highest scoring device type
        best_match = max(scores.items(), key=lambda x: x[1])
        
        return {
            "device_type": best_match[0],
            "confidence": "HIGH" if best_match[1] >= 10 else "MEDIUM",
            "score": best_match[1]
        }
    
    def lookup_vendor_from_mac(self, mac: str) -> str:
        """
        Lookup vendor from MAC address OUI
        
        Args:
            mac: MAC address in format XX:XX:XX:XX:XX:XX
        
        Returns:
            Vendor name or "Unknown"
        """
        if not mac or len(mac) < 8:
            return "Unknown"
        
        # Extract OUI (first 3 octets)
        oui = mac[:8].upper()
        
        return OUI_DATABASE.get(oui, "Unknown")
    
    async def fingerprint_device(self, ip: str, mac: str = None, 
                                 hostname: str = None) -> Dict[str, Any]:
        """
        Complete hardware fingerprinting
        
        Returns comprehensive device information
        """
        # Check cache
        cache_key = f"{ip}:{mac}"
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]
        
        # Probe signature ports
        open_ports = await self.probe_signature_ports(ip)
        
        # Classify device type
        classification = self.classify_device_type(open_ports)
        
        # Lookup vendor from MAC
        vendor = "Unknown"
        if mac:
            vendor = self.lookup_vendor_from_mac(mac)
        
        # Combine information
        result = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "device_type": classification["device_type"],
            "vendor": vendor,
            "confidence": classification["confidence"],
            "open_ports": open_ports,
            "signature_ports": [
                {"port": p, "service": HARDWARE_SIGNATURES[p]}
                for p in open_ports if p in HARDWARE_SIGNATURES
            ],
            "classification_score": classification["score"]
        }
        
        # Cache result
        self.results_cache[cache_key] = result
        
        return result
    
    def get_device_icon(self, device_type: str) -> str:
        """Get emoji icon for device type"""
        icons = {
            "Apple": "🍎",
            "Windows": "🪟",
            "Google": "🔍",
            "Samsung": "📱",
            "Unknown": "❓"
        }
        return icons.get(device_type, "💻")
    
    def format_device_info(self, info: Dict[str, Any]) -> str:
        """Format device info for display"""
        icon = self.get_device_icon(info["device_type"])
        
        lines = [
            f"{icon} {info['ip']}",
            f"  Type: {info['device_type']} ({info['confidence']})",
            f"  Vendor: {info['vendor']}"
        ]
        
        if info.get("hostname"):
            lines.append(f"  Hostname: {info['hostname']}")
        
        if info.get("mac"):
            lines.append(f"  MAC: {info['mac']}")
        
        if info.get("signature_ports"):
            lines.append(f"  Signature Ports:")
            for port_info in info["signature_ports"][:3]:  # Show top 3
                lines.append(f"    • {port_info['port']}: {port_info['service']}")
        
        return "\n".join(lines)


async def test_fingerprinter():
    """Test the hardware fingerprinter"""
    print("Testing Hardware Fingerprinter...")
    
    fingerprinter = HardwareFingerprinter(timeout=0.5)
    
    # Test with Google DNS
    print("\nTesting 8.8.8.8 (Google DNS):")
    result = await fingerprinter.fingerprint_device("8.8.8.8")
    print(fingerprinter.format_device_info(result))
    
    # Test with local gateway (usually .1)
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    gateway = ".".join(local_ip.split('.')[:-1]) + ".1"
    print(f"\nTesting {gateway} (Gateway):")
    result = await fingerprinter.fingerprint_device(gateway)
    print(fingerprinter.format_device_info(result))


if __name__ == "__main__":
    asyncio.run(test_fingerprinter())
