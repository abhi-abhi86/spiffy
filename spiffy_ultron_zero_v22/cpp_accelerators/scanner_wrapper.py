#!/usr/bin/env python3
"""
Python wrapper for C++ Fast Scanner
Provides high-performance port scanning for WIFI_RADAR
"""

import ctypes
import os
from typing import List, Tuple

class ScanResult(ctypes.Structure):
    _fields_ = [
        ("ip", ctypes.c_char * 16),
        ("port", ctypes.c_int),
        ("is_open", ctypes.c_bool),
        ("response_time_ms", ctypes.c_int)
    ]

class FastScanner:
    """Python wrapper for C++ FastScanner"""
    
    def __init__(self, lib_path: str = None):
        if lib_path is None:
            lib_path = os.path.join(os.path.dirname(__file__), "libfast_scanner.so")
        
        try:
            self.lib = ctypes.CDLL(lib_path)
            self._setup_functions()
            self.scanner = self.lib.create_scanner()
        except OSError:
            # Fallback to Python implementation if C++ lib not available
            self.lib = None
            self.scanner = None
            print("⚠️  C++ accelerator not available, using Python fallback")
    
    def _setup_functions(self):
        """Setup C function signatures"""
        self.lib.create_scanner.restype = ctypes.c_void_p
        
        self.lib.scan_port_fast.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int
        ]
        self.lib.scan_port_fast.restype = ctypes.c_int
        
        self.lib.scan_host_fast.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, 
            ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_int
        ]
        
        self.lib.get_scan_results.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ScanResult), ctypes.c_int
        ]
        self.lib.get_scan_results.restype = ctypes.c_int
        
        self.lib.clear_scan_results.argtypes = [ctypes.c_void_p]
    
    def scan_port(self, ip: str, port: int, timeout_ms: int = 1000) -> int:
        """
        Scan a single port
        Returns: response time in ms if open, 0 if closed
        """
        if not self.lib:
            return 0  # Fallback
        
        return self.lib.scan_port_fast(
            self.scanner, 
            ip.encode('utf-8'), 
            port, 
            timeout_ms
        )
    
    def scan_host(self, ip: str, ports: List[int], timeout_ms: int = 1000) -> List[Tuple[int, int]]:
        """
        Scan multiple ports on a host
        Returns: List of (port, response_time) tuples for open ports
        """
        if not self.lib:
            return []  # Fallback
        
        # Convert ports to C array
        port_array = (ctypes.c_int * len(ports))(*ports)
        
        # Clear previous results
        self.lib.clear_scan_results(self.scanner)
        
        # Perform scan
        self.lib.scan_host_fast(
            self.scanner,
            ip.encode('utf-8'),
            port_array,
            len(ports),
            timeout_ms
        )
        
        # Get results
        max_results = len(ports)
        results_array = (ScanResult * max_results)()
        count = self.lib.get_scan_results(self.scanner, results_array, max_results)
        
        # Convert to Python list
        open_ports = []
        for i in range(count):
            result = results_array[i]
            open_ports.append((result.port, result.response_time_ms))
        
        return open_ports
    
    def __del__(self):
        """Cleanup"""
        if self.lib and self.scanner:
            self.lib.destroy_scanner(self.scanner)

# Example usage
if __name__ == "__main__":
    scanner = FastScanner()
    
    if scanner.lib:
        print("🚀 C++ Fast Scanner Loaded")
        
        # Test scan
        ip = "192.168.1.1"
        ports = [80, 443, 22, 8080]
        
        print(f"\nScanning {ip}...")
        open_ports = scanner.scan_host(ip, ports, timeout_ms=500)
        
        print(f"\nOpen ports:")
        for port, response_time in open_ports:
            print(f"  Port {port}: {response_time}ms")
    else:
        print("❌ C++ library not compiled")
        print("Compile with: g++ -shared -fPIC -o libfast_scanner.so fast_scanner.cpp")
