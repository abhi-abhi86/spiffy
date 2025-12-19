#!/usr/bin/env python3
"""
Export utilities for Spiffy Ultron-Zero v25.0
Handles exporting scan results to JSON and CSV formats
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any


class ExportManager:
    """Manages export of scan results to various formats"""
    
    def __init__(self, export_dir: str = "spiffy_exports"):
        self.export_dir = export_dir
        if not os.path.exists(export_dir):
            os.makedirs(export_dir)
    
    def generate_filename(self, module_name: str, extension: str) -> str:
        """Generate timestamped filename for exports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.export_dir, f"{module_name}_{timestamp}.{extension}")
    
    def export_to_json(self, data: Dict[str, Any], module_name: str) -> str:
        """Export data to JSON file"""
        filepath = self.generate_filename(module_name, "json")
        
        export_data = {
            "module": module_name,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return filepath
    
    def export_wifi_scan_to_csv(self, devices: List[Dict[str, str]], subnet: str) -> str:
        """Export WiFi scan results to CSV"""
        filepath = self.generate_filename("wifi_radar", "csv")
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Subnet', 'IP Address', 'MAC Address', 'Vendor', 'Device Type', 'Open Ports'])
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for device in devices:
                writer.writerow([
                    timestamp,
                    subnet,
                    device.get('ip', 'N/A'),
                    device.get('mac', 'N/A'),
                    device.get('vendor', 'Unknown'),
                    device.get('device_type', 'Unknown'),
                    device.get('ports', '')
                ])
        
        return filepath
    
    def export_dns_enum_to_csv(self, subdomains: List[str], ips: List[str], domain: str) -> str:
        """Export DNS enumeration results to CSV"""
        filepath = self.generate_filename("dns_enum", "csv")
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Domain', 'Subdomain', 'IP Address'])
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for subdomain in subdomains:
                writer.writerow([timestamp, domain, subdomain, ''])
            
            for ip in ips:
                writer.writerow([timestamp, domain, '', ip])
        
        return filepath
    
    def export_vuln_scan_to_json(self, findings: List[str], target: str) -> str:
        """Export vulnerability scan results to JSON"""
        data = {
            "target": target,
            "findings": findings,
            "severity": "HIGH" if len(findings) > 1 else "INFO",
            "total_findings": len(findings)
        }
        return self.export_to_json(data, "vuln_scan")


class InputValidator:
    """Validates user inputs for security and correctness"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        if not url:
            return False
        return url.startswith('http://') or url.startswith('https://')
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name format"""
        if not domain or len(domain) > 253:
            return False
        # Basic domain validation
        import re
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def sanitize_filepath(filepath: str) -> str:
        """Sanitize file path to prevent directory traversal"""
        # Remove any directory traversal attempts
        return os.path.basename(filepath)
