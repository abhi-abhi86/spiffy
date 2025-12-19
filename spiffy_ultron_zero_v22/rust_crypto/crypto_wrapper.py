#!/usr/bin/env python3
"""
Python wrapper for Rust Crypto Accelerator
Provides high-performance cryptography for Bifrost
"""

import ctypes
import os
from typing import Optional

class RustCrypto:
    """Python wrapper for Rust crypto accelerator"""
    
    def __init__(self, lib_path: str = None):
        if lib_path is None:
            # Try to find the compiled library
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "target/release/libomega_crypto.dylib"),
                os.path.join(os.path.dirname(__file__), "target/release/libomega_crypto.so"),
                os.path.join(os.path.dirname(__file__), "target/release/omega_crypto.dll"),
            ]
            
            lib_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    lib_path = path
                    break
        
        try:
            self.lib = ctypes.CDLL(lib_path) if lib_path else None
            if self.lib:
                self._setup_functions()
                print("🚀 Rust Crypto Accelerator Loaded")
        except OSError:
            self.lib = None
            print("⚠️  Rust accelerator not available, using Python fallback")
    
    def _setup_functions(self):
        """Setup Rust function signatures"""
        # AES-GCM encryption
        self.lib.rust_encrypt_aes_gcm.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # key
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # plaintext
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)  # output
        ]
        self.lib.rust_encrypt_aes_gcm.restype = ctypes.c_int
        
        # AES-GCM decryption
        self.lib.rust_decrypt_aes_gcm.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # key
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # ciphertext
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)  # output
        ]
        self.lib.rust_decrypt_aes_gcm.restype = ctypes.c_int
        
        # SHA-256
        self.lib.rust_sha256.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # data
            ctypes.POINTER(ctypes.c_uint8)  # output (32 bytes)
        ]
        self.lib.rust_sha256.restype = ctypes.c_int
        
        # HMAC-SHA256
        self.lib.rust_hmac_sha256.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # key
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # data
            ctypes.POINTER(ctypes.c_uint8)  # output (32 bytes)
        ]
        self.lib.rust_hmac_sha256.restype = ctypes.c_int
    
    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes) -> Optional[bytes]:
        """
        Encrypt with AES-256-GCM (Rust accelerated)
        Returns: nonce + ciphertext + tag
        """
        if not self.lib:
            return None  # Fallback to Python
        
        # Prepare buffers
        key_array = (ctypes.c_uint8 * len(key))(*key)
        plaintext_array = (ctypes.c_uint8 * len(plaintext))(*plaintext)
        output_array = (ctypes.c_uint8 * (len(plaintext) + 100))()  # Extra space for nonce+tag
        output_len = ctypes.c_size_t(len(plaintext) + 100)
        
        # Call Rust function
        result = self.lib.rust_encrypt_aes_gcm(
            key_array, len(key),
            plaintext_array, len(plaintext),
            output_array, ctypes.byref(output_len)
        )
        
        if result != 0:
            return None  # Encryption failed
        
        # Convert to bytes
        return bytes(output_array[:output_len.value])
    
    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt with AES-256-GCM (Rust accelerated)
        """
        if not self.lib:
            return None  # Fallback to Python
        
        # Prepare buffers
        key_array = (ctypes.c_uint8 * len(key))(*key)
        ciphertext_array = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)
        output_array = (ctypes.c_uint8 * len(ciphertext))()
        output_len = ctypes.c_size_t(len(ciphertext))
        
        # Call Rust function
        result = self.lib.rust_decrypt_aes_gcm(
            key_array, len(key),
            ciphertext_array, len(ciphertext),
            output_array, ctypes.byref(output_len)
        )
        
        if result != 0:
            return None  # Decryption failed
        
        return bytes(output_array[:output_len.value])
    
    def sha256(self, data: bytes) -> Optional[bytes]:
        """SHA-256 hash (Rust accelerated)"""
        if not self.lib:
            return None
        
        data_array = (ctypes.c_uint8 * len(data))(*data)
        output_array = (ctypes.c_uint8 * 32)()
        
        result = self.lib.rust_sha256(data_array, len(data), output_array)
        
        if result != 0:
            return None
        
        return bytes(output_array)
    
    def hmac_sha256(self, key: bytes, data: bytes) -> Optional[bytes]:
        """HMAC-SHA256 (Rust accelerated)"""
        if not self.lib:
            return None
        
        key_array = (ctypes.c_uint8 * len(key))(*key)
        data_array = (ctypes.c_uint8 * len(data))(*data)
        output_array = (ctypes.c_uint8 * 32)()
        
        result = self.lib.rust_hmac_sha256(
            key_array, len(key),
            data_array, len(data),
            output_array
        )
        
        if result != 0:
            return None
        
        return bytes(output_array)

# Example usage
if __name__ == "__main__":
    crypto = RustCrypto()
    
    if crypto.lib:
        # Test encryption
        key = b"0" * 32  # 256-bit key
        plaintext = b"Hello, Omega Kernel!"
        
        print(f"Plaintext: {plaintext}")
        
        encrypted = crypto.encrypt_aes_gcm(key, plaintext)
        if encrypted:
            print(f"Encrypted: {len(encrypted)} bytes")
            
            decrypted = crypto.decrypt_aes_gcm(key, encrypted)
            if decrypted:
                print(f"Decrypted: {decrypted}")
                print(f"✓ Match: {decrypted == plaintext}")
        
        # Test SHA-256
        hash_result = crypto.sha256(b"test data")
        if hash_result:
            print(f"\nSHA-256: {hash_result.hex()}")
    else:
        print("❌ Rust library not compiled")
        print("Compile with: cd rust_crypto && cargo build --release")
