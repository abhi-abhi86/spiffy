"""
Python wrapper for C++ Fast Scanner v2
Uses ctypes for safe bindings with proper error handling
"""

import os
import ctypes
from typing import List, Optional
from pathlib import Path

class FastScannerV2:
    """Python wrapper for C++ fast scanner with RAII and connection pooling"""
    
    def __init__(self, max_connections: int = 200):
        self.lib = None
        self.scanner = None
        self.max_connections = max_connections
        
        # Try to load the library
        lib_path = self._find_library()
        if lib_path:
            try:
                self.lib = ctypes.CDLL(str(lib_path))
                self._setup_functions()
                self.scanner = self.lib.create_scanner(max_connections)
                
                if not self.scanner:
                    raise RuntimeError("Failed to create scanner instance")
                    
            except Exception as e:
                print(f"⚠️  Failed to load C++ scanner: {e}")
                self.lib = None
                self.scanner = None
    
    def _find_library(self) -> Optional[Path]:
        """Find the compiled library"""
        base_dir = Path(__file__).parent
        
        # Try different extensions
        for ext in ['.dylib', '.so']:
            lib_path = base_dir / f"libfast_scanner_v2{ext}"
            if lib_path.exists():
                return lib_path
        
        return None
    
    def _setup_functions(self):
        """Setup function signatures"""
        # create_scanner(int max_connections) -> void*
        self.lib.create_scanner.argtypes = [ctypes.c_int]
        self.lib.create_scanner.restype = ctypes.c_void_p
        
        # destroy_scanner(void* scanner)
        self.lib.destroy_scanner.argtypes = [ctypes.c_void_p]
        self.lib.destroy_scanner.restype = None
        
        # scan_port_fast(void* scanner, const char* ip, int port, int timeout_ms) -> int
        self.lib.scan_port_fast.argtypes = [
            ctypes.c_void_p, 
            ctypes.c_char_p, 
            ctypes.c_int, 
            ctypes.c_int
        ]
        self.lib.scan_port_fast.restype = ctypes.c_int
        
        # scan_ports_fast(void* scanner, const char* ip, const int* ports, 
        #                 int port_count, int timeout_ms, int* output, int max_output) -> int
        self.lib.scan_ports_fast.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int
        ]
        self.lib.scan_ports_fast.restype = ctypes.c_int
        
        # clear_results(void* scanner)
        self.lib.clear_results.argtypes = [ctypes.c_void_p]
        self.lib.clear_results.restype = None
        
        # get_pool_size(void* scanner) -> int
        self.lib.get_pool_size.argtypes = [ctypes.c_void_p]
        self.lib.get_pool_size.restype = ctypes.c_int
    
    def is_available(self) -> bool:
        """Check if C++ scanner is available"""
        return self.lib is not None and self.scanner is not None
    
    def scan_port(self, ip: str, port: int, timeout_ms: int = 1000) -> int:
        """
        Scan a single port
        
        Returns:
            Response time in ms if open, 0 if closed, -1 if error
        """
        if not self.is_available():
            return -1
        
        try:
            result = self.lib.scan_port_fast(
                self.scanner,
                ip.encode('utf-8'),
                port,
                timeout_ms
            )
            return result
        except Exception as e:
            print(f"Scan error: {e}")
            return -1
    
    def scan_ports(self, ip: str, ports: List[int], timeout_ms: int = 1000) -> List[int]:
        """
        Scan multiple ports (parallel)
        
        Returns:
            List of open ports
        """
        if not self.is_available():
            return []
        
        try:
            # Convert Python list to C array
            port_count = len(ports)
            ports_array = (ctypes.c_int * port_count)(*ports)
            
            # Output array (max same as input)
            output_array = (ctypes.c_int * port_count)()
            
            # Call C++ function
            result_count = self.lib.scan_ports_fast(
                self.scanner,
                ip.encode('utf-8'),
                ports_array,
                port_count,
                timeout_ms,
                output_array,
                port_count
            )
            
            # Convert C array back to Python list
            open_ports = [output_array[i] for i in range(result_count)]
            return sorted(open_ports)
            
        except Exception as e:
            print(f"Scan error: {e}")
            return []
    
    def clear_results(self):
        """Clear scan results"""
        if self.is_available():
            self.lib.clear_results(self.scanner)
    
    def get_pool_size(self) -> int:
        """Get current connection pool size"""
        if self.is_available():
            return self.lib.get_pool_size(self.scanner)
        return 0
    
    def __del__(self):
        """Cleanup on destruction"""
        if self.scanner and self.lib:
            try:
                self.lib.destroy_scanner(self.scanner)
            except:
                pass
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.__del__()


# Convenience function
def create_scanner(max_connections: int = 200) -> FastScannerV2:
    """Create a new fast scanner instance"""
    return FastScannerV2(max_connections)


if __name__ == "__main__":
    # Test the scanner
    print("Testing C++ Fast Scanner v2...")
    
    scanner = FastScannerV2(max_connections=100)
    
    if scanner.is_available():
        print("✓ C++ scanner loaded successfully")
        print(f"  Pool size: {scanner.get_pool_size()}")
        
        # Test single port
        print("\nTesting single port scan...")
        result = scanner.scan_port("8.8.8.8", 53, timeout_ms=2000)
        if result > 0:
            print(f"  ✓ Port 53 open (response time: {result}ms)")
        else:
            print(f"  ✗ Port 53 closed or timeout")
        
        # Test multiple ports
        print("\nTesting multiple port scan...")
        ports = [22, 80, 443, 8080, 3306, 5432]
        open_ports = scanner.scan_ports("scanme.nmap.org", ports, timeout_ms=2000)
        print(f"  Open ports: {open_ports}")
        
        print(f"\n  Final pool size: {scanner.get_pool_size()}")
    else:
        print("✗ C++ scanner not available")
        print("  Run 'make' to compile the library")
