#!/usr/bin/env python3
"""
Encrypted Chat - Python Frontend (10% of work)
Backend-heavy architecture: Rust does crypto, C++ does networking
Python just loads libraries and displays UI
"""

import ctypes
import os
import sys
import time
from pathlib import Path

# Load Rust crypto backend
try:
    import rust_chat_crypto
    print("✓ Rust crypto backend loaded")
except ImportError as e:
    print(f"✗ Failed to load Rust crypto: {e}")
    print("Run: cd rust_chat_crypto && maturin develop --release")
    sys.exit(1)

# Load C++ network backend
try:
    lib_path = Path(__file__).parent / "cpp_accelerators" / "libchat_network.dylib"
    if not lib_path.exists():
        lib_path = Path(__file__).parent / "cpp_accelerators" / "libchat_network.so"
    
    chat_net = ctypes.CDLL(str(lib_path))
    
    # Define C function signatures
    chat_net.chat_server_create.argtypes = [ctypes.c_int]
    chat_net.chat_server_create.restype = ctypes.c_void_p
    
    chat_net.chat_server_start.argtypes = [ctypes.c_void_p]
    chat_net.chat_server_start.restype = ctypes.c_int
    
    chat_net.chat_server_send.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    chat_net.chat_server_send.restype = ctypes.c_int
    
    chat_net.chat_server_receive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
    chat_net.chat_server_receive.restype = ctypes.c_int
    
    chat_net.chat_client_create.argtypes = [ctypes.c_char_p, ctypes.c_int]
    chat_net.chat_client_create.restype = ctypes.c_void_p
    
    chat_net.chat_client_connect.argtypes = [ctypes.c_void_p]
    chat_net.chat_client_connect.restype = ctypes.c_int
    
    chat_net.chat_client_send.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    chat_net.chat_client_send.restype = ctypes.c_int
    
    chat_net.chat_client_receive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
    chat_net.chat_client_receive.restype = ctypes.c_int
    
    print("✓ C++ network backend loaded")
except Exception as e:
    print(f"✗ Failed to load C++ network: {e}")
    print("Run: cd cpp_accelerators && g++ -shared -fPIC -O3 -o libchat_network.dylib chat_network.cpp -lpthread")
    sys.exit(1)


class EncryptedChat:
    """
    Python Frontend (10% of work)
    Just loads backends and displays UI
    """
    
    def __init__(self, mode, host=None, port=8888):
        self.mode = mode
        self.host = host
        self.port = port
        
        # Rust crypto backend (does ALL crypto)
        self.crypto = rust_chat_crypto.ChatCrypto()
        
        # C++ network backend (does ALL networking)
        self.network = None
        
        print(f"\n{'='*60}")
        print(f"  ENCRYPTED CHAT - Backend-Heavy Architecture")
        print(f"  Rust: 45% (Crypto) | C++: 45% (Network) | Python: 10% (UI)")
        print(f"{'='*60}\n")
    
    def start_server(self):
        """Start as server (Python just orchestrates)"""
        print(f"[Server] Starting on port {self.port}...")
        
        # C++ does networking
        self.network = chat_net.chat_server_create(self.port)
        if chat_net.chat_server_start(self.network) != 0:
            print("✗ Failed to start server")
            return
        
        print(f"✓ Server listening on port {self.port}")
        print("Waiting for client connection...")
        
        # Rust does key exchange
        print("\n[Crypto] Generating keypair...")
        my_public = self.crypto.generate_keypair()
        print(f"✓ Public key: {my_public[:16].hex()}...")
        
        # Exchange keys (C++ sends, Rust encrypts)
        print("[Crypto] Exchanging keys...")
        chat_net.chat_server_send(self.network, my_public, len(my_public))
        
        # Receive peer's public key
        buffer = ctypes.create_string_buffer(8192)
        length = ctypes.c_size_t(8192)
        
        while chat_net.chat_server_receive(self.network, buffer, ctypes.byref(length)) != 0:
            time.sleep(0.1)
        
        peer_public = bytes(buffer[:length.value])
        print(f"✓ Received peer key: {peer_public[:16].hex()}...")
        
        # Rust computes shared secret
        if not self.crypto.compute_shared_secret(list(peer_public)):
            print("✗ Key exchange failed")
            return
        
        print("✓ Secure channel established!\n")
        
        # Chat loop (Python just displays)
        self._chat_loop()
    
    def start_client(self):
        """Start as client (Python just orchestrates)"""
        print(f"[Client] Connecting to {self.host}:{self.port}...")
        
        # C++ does networking
        self.network = chat_net.chat_client_create(self.host.encode(), self.port)
        if chat_net.chat_client_connect(self.network) != 0:
            print("✗ Failed to connect")
            return
        
        print("✓ Connected to server")
        
        # Rust does key exchange
        print("\n[Crypto] Generating keypair...")
        my_public = self.crypto.generate_keypair()
        print(f"✓ Public key: {my_public[:16].hex()}...")
        
        # Receive server's public key first
        buffer = ctypes.create_string_buffer(8192)
        length = ctypes.c_size_t(8192)
        
        while chat_net.chat_client_receive(self.network, buffer, ctypes.byref(length)) != 0:
            time.sleep(0.1)
        
        peer_public = bytes(buffer[:length.value])
        print(f"✓ Received peer key: {peer_public[:16].hex()}...")
        
        # Send our public key
        chat_net.chat_client_send(self.network, my_public, len(my_public))
        
        # Rust computes shared secret
        if not self.crypto.compute_shared_secret(list(peer_public)):
            print("✗ Key exchange failed")
            return
        
        print("✓ Secure channel established!\n")
        
        # Chat loop (Python just displays)
        self._chat_loop()
    
    def _chat_loop(self):
        """Main chat loop (Python just displays, backends do work)"""
        print("="*60)
        print("  Chat started! Type messages (Ctrl+C to quit)")
        print("="*60)
        
        import threading
        
        # Receive thread
        def receive_loop():
            buffer = ctypes.create_string_buffer(8192)
            length = ctypes.c_size_t(8192)
            
            while True:
                # C++ receives
                if self.mode == 'server':
                    result = chat_net.chat_server_receive(self.network, buffer, ctypes.byref(length))
                else:
                    result = chat_net.chat_client_receive(self.network, buffer, ctypes.byref(length))
                
                if result == 0:
                    encrypted = bytes(buffer[:length.value])
                    
                    # Rust decrypts
                    try:
                        plaintext = self.crypto.decrypt(list(encrypted))
                        message = bytes(plaintext).decode('utf-8')
                        
                        # Python just displays
                        print(f"\n[Peer] {message}")
                        print("[You] ", end='', flush=True)
                    except Exception as e:
                        print(f"\n✗ Decryption failed: {e}")
                    
                    length.value = 8192
                
                time.sleep(0.1)
        
        recv_thread = threading.Thread(target=receive_loop, daemon=True)
        recv_thread.start()
        
        # Send loop
        try:
            while True:
                message = input("[You] ")
                if not message:
                    continue
                
                # Rust encrypts
                encrypted = self.crypto.encrypt(message.encode('utf-8'))
                
                # C++ sends
                if self.mode == 'server':
                    chat_net.chat_server_send(self.network, bytes(encrypted), len(encrypted))
                else:
                    chat_net.chat_client_send(self.network, bytes(encrypted), len(encrypted))
        
        except KeyboardInterrupt:
            print("\n\n✓ Chat ended")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Encrypted Chat (Backend-Heavy)")
    parser.add_argument('--server', action='store_true', help='Run as server')
    parser.add_argument('--client', action='store_true', help='Run as client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (client mode)')
    parser.add_argument('--port', type=int, default=8888, help='Port number')
    
    args = parser.parse_args()
    
    if args.server:
        chat = EncryptedChat('server', port=args.port)
        chat.start_server()
    elif args.client:
        chat = EncryptedChat('client', host=args.host, port=args.port)
        chat.start_client()
    else:
        print("Usage:")
        print("  Server: python3 encrypted_chat.py --server --port 8888")
        print("  Client: python3 encrypted_chat.py --client --host 127.0.0.1 --port 8888")
