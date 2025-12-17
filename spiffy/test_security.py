#!/usr/bin/env python3
# no need to run this file its not for you 🫵 🖕

import sys
import os
sys.path.append('.')

from spiffy_x import SecureCrypto
import secrets

def test_crypto():
    print("Testing SecureCrypto...")

    # Test encryption/decryption
    key = secrets.token_hex(32)
    crypto = SecureCrypto(key)

    test_msg = "Hello, secure world!"
    encrypted = crypto.encrypt(test_msg)
    decrypted = crypto.decrypt(encrypted)

    assert decrypted == test_msg, f"Decryption failed: {decrypted}"
    print("✓ Basic encrypt/decrypt works")

    # Test replay protection
    try:
        crypto.decrypt(encrypted)  # Should fail
        assert False, "Replay not detected"
    except ValueError as e:
        if "Replay detected" in str(e):
            print("✓ Replay protection works")
        else:
            raise

    # Test tamper detection
    tampered = encrypted[:-1] + b'x'  # Tamper last byte
    try:
        crypto.decrypt(tampered)
        assert False, "Tamper not detected"
    except ValueError:
        print("✓ Tamper detection works")

    print("All crypto tests passed!")

if __name__ == "__main__":
    test_crypto()
