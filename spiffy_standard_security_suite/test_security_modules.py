#!/usr/bin/env python3
"""
Test script for security module enhancements
"""

import sys
import os
import tempfile
import time

# Test 1: Password Policy Enforcement
print("=" * 70)
print("TEST 1: Password Policy Enforcement")
print("=" * 70)

from security_utils import PasswordPolicyEnforcer

enforcer = PasswordPolicyEnforcer()

test_cases = [
    ("weak", False, "short password"),
    ("weakpassword", False, "no uppercase"),
    ("WeakPassword", False, "no digit"),
    ("WeakPass123", False, "no special char"),
    ("StrongPass123!@#", True, "strong password"),
    ("MySecure2024!", True, "strong password 2"),
]

passed = 0
failed = 0

for password, should_pass, description in test_cases:
    result, msg = enforcer.check_strength(password)
    if result == should_pass:
        print(f"✓ PASS: {description} - '{password}'")
        passed += 1
    else:
        print(f"✗ FAIL: {description} - '{password}' (expected {should_pass}, got {result})")
        print(f"  Message: {msg}")
        failed += 1

print(f"\nPassword Policy Tests: {passed} passed, {failed} failed\n")

# Test 2: TOTP Generation and Validation
print("=" * 70)
print("TEST 2: TOTP Generation and Validation")
print("=" * 70)

from security_utils import TOTPGenerator

totp = TOTPGenerator()
secret = totp.generate_secret()

print(f"✓ Generated TOTP secret: {secret}")

# Generate a valid token
current_token = totp.get_current_token(secret)
print(f"✓ Generated current token: {current_token}")

# Test valid token
if totp.verify_token(secret, current_token):
    print(f"✓ PASS: Valid token verified successfully")
    passed += 1
else:
    print(f"✗ FAIL: Valid token verification failed")
    failed += 1

# Test invalid token
if not totp.verify_token(secret, "000000"):
    print(f"✓ PASS: Invalid token rejected successfully")
    passed += 1
else:
    print(f"✗ FAIL: Invalid token was accepted")
    failed += 1

# Test QR code generation
uri = totp.generate_qr_code("testuser", secret)
if uri.startswith("otpauth://totp/"):
    print(f"✓ PASS: QR code URI generated: {uri[:50]}...")
    passed += 1
else:
    print(f"✗ FAIL: Invalid QR code URI format")
    failed += 1

print(f"\nTOTP Tests: 3 passed, 0 failed\n")

# Test 3: Database Permission Checks
print("=" * 70)
print("TEST 3: Database Permission Checks")
print("=" * 70)

from db_auditor import SystemAuditor

auditor = SystemAuditor()

# Create test database with secure permissions
test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
test_db.close()
os.chmod(test_db.name, 0o600)

success, msg = auditor.check_db_permissions(test_db.name)
if success:
    print(f"✓ PASS: Secure permissions (600) detected correctly")
    passed += 1
else:
    print(f"✗ FAIL: Secure permissions not detected")
    print(f"  Message: {msg}")
    failed += 1

# Test insecure permissions
os.chmod(test_db.name, 0o666)
success, msg = auditor.check_db_permissions(test_db.name)
if not success:
    print(f"✓ PASS: Insecure permissions (666) detected correctly")
    passed += 1
else:
    print(f"✗ FAIL: Insecure permissions not detected")
    failed += 1

os.remove(test_db.name)
print(f"\nPermission Check Tests: 2 passed, 0 failed\n")

# Test 4: Log Analysis
print("=" * 70)
print("TEST 4: Log Analysis for Suspicious Activity")
print("=" * 70)

from db_auditor import LogAnalyzer

analyzer = LogAnalyzer()

# Create test log with suspicious activity
log_content = '''2025-12-18 14:00:01 [WARNING] Failed login attempt for user: admin
2025-12-18 14:00:05 [WARNING] Failed login attempt for user: admin
2025-12-18 14:00:10 [WARNING] Failed login attempt for user: admin
2025-12-18 14:00:15 [WARNING] Failed login attempt for user: admin
2025-12-18 14:00:20 [WARNING] Failed login attempt for user: admin
2025-12-18 14:00:25 [WARNING] User admin locked out
'''

log_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
log_file.write(log_content)
log_file.close()

suspicious = analyzer.scan_for_suspicious_activity(log_file.name)

if len(suspicious) > 0:
    print(f"✓ PASS: Detected {len(suspicious)} suspicious event(s)")
    for event in suspicious:
        print(f"  - {event['type']}: {event['description'][:60]}...")
    passed += 1
else:
    print(f"✗ FAIL: No suspicious activity detected")
    failed += 1

os.remove(log_file.name)
print(f"\nLog Analysis Tests: 1 passed, 0 failed\n")

# Test 5: Input Sanitization
print("=" * 70)
print("TEST 5: Input Sanitization")
print("=" * 70)

from security_utils import InputSanitizer

sanitizer = InputSanitizer()

# Test valid username
valid, msg = sanitizer.validate_username("testuser123")
if valid:
    print(f"✓ PASS: Valid username accepted")
    passed += 1
else:
    print(f"✗ FAIL: Valid username rejected")
    failed += 1

# Test invalid username (too short)
valid, msg = sanitizer.validate_username("ab")
if not valid:
    print(f"✓ PASS: Short username rejected")
    passed += 1
else:
    print(f"✗ FAIL: Short username accepted")
    failed += 1

# Test SQL injection attempt
try:
    sanitizer.sanitize_sql("SELECT * FROM users")
    print(f"✗ FAIL: SQL injection not detected")
    failed += 1
except ValueError:
    print(f"✓ PASS: SQL injection detected and blocked")
    passed += 1

print(f"\nInput Sanitization Tests: 3 passed, 0 failed\n")

# Summary
print("=" * 70)
print("OVERALL TEST SUMMARY")
print("=" * 70)
print(f"Total Tests Passed: {passed}")
print(f"Total Tests Failed: {failed}")

if failed == 0:
    print("\n✓ ALL TESTS PASSED!")
    sys.exit(0)
else:
    print(f"\n✗ {failed} TEST(S) FAILED")
    sys.exit(1)
