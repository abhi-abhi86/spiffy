"""
Device Labeling System
Automatically identify [THIS DEVICE] and [GATEWAY]
"""

import socket
import subprocess
import re
from typing import Optional

class DeviceLabeler:
    """Identify and label network devices"""
    
    @staticmethod
    def get_local_ip() -> str:
        """Get this device's IP address"""
        try:
            s = socket.socket(socket.AF_INET, SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def get_gateway_ip() -> str:
        """Get default gateway IP"""
        try:
            # macOS/Linux
            result = subprocess.check_output(
                "netstat -nr | grep default | awk '{print $2}' | head -1",
                shell=True
            ).decode().strip()
            
            if result and re.match(r'\d+\.\d+\.\d+\.\d+', result):
                return result
        except:
            pass
        
        # Fallback: assume .1
        local_ip = DeviceLabeler.get_local_ip()
        return ".".join(local_ip.split('.')[:-1]) + ".1"
    
    @staticmethod
    def label_device(ip: str) -> str:
        """Add appropriate label to device"""
        local_ip = DeviceLabeler.get_local_ip()
        gateway_ip = DeviceLabeler.get_gateway_ip()
        
        if ip == local_ip:
            return f"🖥️  {ip} [THIS DEVICE]"
        elif ip == gateway_ip:
            return f"🌐 {ip} [GATEWAY]"
        else:
            return f"   {ip}"
    
    @staticmethod
    def get_network_info() -> dict:
        """Get complete network information"""
        return {
            "local_ip": DeviceLabeler.get_local_ip(),
            "gateway_ip": DeviceLabeler.get_gateway_ip(),
            "subnet": ".".join(DeviceLabeler.get_local_ip().split('.')[:-1]) + ".0/24"
        }
