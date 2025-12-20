"""
Bluetooth Security Scanner - THIN Python Frontend (10% of work)
Backend (C++/Rust) does 90% - scanning, analysis, reporting
Python just displays results
"""

import json
from ctypes import *
from pathlib import Path

class BluetoothUI:
    """
    Ultra-thin Python frontend
    - Loads backend library
    - Calls backend functions
    - Displays results
    That's it!
    """
    
    def __init__(self):
        self.backend = None
        self._load_backend()
    
    def _load_backend(self):
        """Load C++ backend library"""
        lib_path = Path(__file__).parent / "cpp_accelerators"
        
        for ext in ['.so', '.dylib', '.dll']:
            lib_file = lib_path / f"libbt_scanner{ext}"
            if lib_file.exists():
                try:
                    self.backend = CDLL(str(lib_file))
                    self._setup_api()
                    print("✓ Backend loaded")
                    return
                except Exception as e:
                    print(f"✗ Backend load failed: {e}")
        
        print("✗ Backend not available")
        print("  Build with: cd cpp_accelerators && make")
    
    def _setup_api(self):
        """Setup backend API"""
        # bt_init() -> void*
        self.backend.bt_init.restype = c_void_p
        
        # bt_scan(duration) -> int
        self.backend.bt_scan.argtypes = [c_int]
        self.backend.bt_scan.restype = c_int
        
        # bt_get_report() -> const char*
        self.backend.bt_get_report.restype = c_char_p
        
        # bt_get_stats() -> const char*
        self.backend.bt_get_stats.restype = c_char_p
        
        # bt_cleanup()
        self.backend.bt_cleanup.restype = None
    
    def scan(self, duration=10):
        """
        Scan for Bluetooth devices
        Backend does ALL the work!
        """
        if not self.backend:
            print("✗ Backend not available")
            return
        
        print(f"\n🔵 Scanning for {duration} seconds...")
        
        # Check if using mock data
        import platform
        if platform.system() == "Darwin":  # macOS
            print(f"   ⚠️  Using MOCK DATA (macOS doesn't support BlueZ)")
            print(f"   ℹ️  For real Bluetooth scanning, use Linux with BlueZ")
        else:
            print(f"   (Backend doing all the work...)")
        
        print()
        
        # Backend does EVERYTHING
        device_count = self.backend.bt_scan(duration)
        
        if device_count == 0:
            print("✗ No devices found")
            return
        
        # Get complete report from backend (already formatted!)
        report_json = self.backend.bt_get_report()
        report_data = json.loads(report_json.decode())
        
        # Just display it
        self._display_report(report_data)
    
    def _display_report(self, data):
        """Display report (UI only - 10% of work)"""
        import platform
        
        print("="*70)
        print("🔵 BLUETOOTH SECURITY SCAN REPORT")
        print("="*70)
        
        # Show data source
        if platform.system() == "Darwin":
            print(f"⚠️  Data Source: MOCK DATA (macOS - no real Bluetooth scanning)")
            print(f"ℹ️  For real scanning: Use Linux with BlueZ installed")
            print()
        
        print(f"Devices Found: {data['devices_found']}")
        print(f"Vulnerable: {data['vulnerable_devices']}")
        print(f"Scan Duration: {data['scan_duration_seconds']}s")
        
        # Risk distribution
        risk_counts = {}
        for dev in data['devices']:
            risk = dev['risk_level']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        print(f"\nRisk Distribution:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in risk_counts:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[level]
                print(f"  {icon} {level}: {risk_counts[level]}")
        
        print("\n" + "-"*70)
        print("DEVICE DETAILS")
        print("-"*70)
        
        for i, dev in enumerate(data['devices'], 1):
            icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠", 
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(dev['risk_level'], "⚪")
            
            print(f"\n{i}. {icon} {dev['name']} ({dev['address']})")
            print(f"   Bluetooth: {dev['bluetooth_version']}")
            print(f"   Risk: {dev['risk_level']} (Score: {dev['security_score']}/100)")
            print(f"   RSSI: {dev['rssi']} dBm")
            
            # Vulnerabilities
            vulns = dev['vulnerabilities']
            if any(vulns.values()):
                print(f"   Vulnerabilities:")
                if vulns['bluejacking']: print(f"     • Bluejacking")
                if vulns['bluesnarfing']: print(f"     • Bluesnarfing")
                if vulns['bluebugging']: print(f"     • Bluebugging")
                if vulns['legacy_pairing']: print(f"     • Legacy Pairing")
            
            # Security
            sec = dev['security']
            print(f"   Security:")
            print(f"     Pairing: {sec['pairing_method']}")
            print(f"     Encryption: {sec['encryption']} ({sec['key_size']}-bit)")
            if sec['le_secure_connections']:
                print(f"     LE Secure Connections: ✓")
            if sec['privacy_enabled']:
                print(f"     Privacy: ✓")
        
        print("\n" + "="*70)
    
    def export_json(self, filename="bluetooth_scan.json"):
        """Export report to JSON"""
        if not self.backend:
            return
        
        report_json = self.backend.bt_get_report()
        
        with open(filename, 'wb') as f:
            f.write(report_json)
        
        print(f"✓ Report exported to {filename}")
    
    def get_stats(self):
        """Get scan statistics"""
        if not self.backend:
            return
        
        stats_json = self.backend.bt_get_stats()
        stats = json.loads(stats_json.decode())
        
        print("\n📊 Scan Statistics:")
        print(f"  Total Scanned: {stats['total_scanned']}")
        print(f"  Vulnerable: {stats['vulnerable_count']}")
        print(f"  Devices Found: {stats['devices_found']}")
    
    def cleanup(self):
        """Cleanup backend"""
        if self.backend:
            self.backend.bt_cleanup()
    
    def __del__(self):
        self.cleanup()


def main():
    """Main entry point - just UI"""
    print("🔵 Bluetooth Security Scanner")
    print("   Backend: C++ (90% of work)")
    print("   Frontend: Python (10% - UI only)")
    print("="*70)
    
    ui = BluetoothUI()
    
    # Scan (backend does everything)
    ui.scan(duration=8)
    
    # Export (backend generates JSON)
    ui.export_json()
    
    # Stats (backend calculates)
    ui.get_stats()
    
    ui.cleanup()


if __name__ == "__main__":
    main()
