"""
Bluetooth Security Scanner - Comprehensive Documentation
"""

# Bluetooth Security Scanner

## Overview

A polyglot Bluetooth security scanner that combines:
- **Python**: Orchestration, UI, and reporting
- **C++**: High-performance device discovery (5-10x faster)
- **Rust**: Memory-safe cryptographic analysis

## Features

### 1. Device Discovery
- Scans for nearby Bluetooth devices
- Identifies device name, address, class
- Measures signal strength (RSSI)
- Enumerates available services

### 2. Vulnerability Detection
- **Bluejacking**: Tests for unsolicited message acceptance
- **Bluesnarfing**: Checks for unauthorized data access
- **Bluebugging**: Detects remote control vulnerabilities
- **Legacy Pairing**: Identifies weak authentication

### 3. Security Analysis
- Pairing method detection (SSP, Legacy PIN)
- Encryption strength validation
- LE Secure Connections support
- Privacy features (RPA)

### 4. Risk Assessment
- Automatic risk scoring (LOW, MEDIUM, HIGH, CRITICAL)
- Vulnerability aggregation
- Security posture evaluation

## Installation

### System Requirements

**Linux:**
```bash
sudo apt-get install bluez libbluetooth-dev python3-dev
```

**macOS:**
```bash
# Bluetooth support is built-in
# May require Xcode Command Line Tools
```

### Python Dependencies
```bash
pip install pybluez
```

### Build C++ Scanner
```bash
cd cpp_accelerators
make clean && make
```

### Build Rust Analyzer (Optional)
```bash
cd rust_bluetooth
cargo build --release
maturin develop --release
```

## Usage

### Basic Scan
```bash
python3 bluetooth_security.py
```

### From Python
```python
from bluetooth_security import BluetoothSecurityScanner

scanner = BluetoothSecurityScanner()
devices = await scanner.scan_bluetooth_devices(duration=10)

# Generate report
report = scanner.generate_report(devices)
print(report)

# Export JSON
scanner.export_json(devices, "scan_results.json")
```

### Integration with Spiffy
```python
# In spiffy.py
from bluetooth_security import BluetoothSecurityScanner

# Add menu option
print(f"{C_BLUE}[T] BLUETOOTH_SCAN{C_RESET}  - Bluetooth security audit")

# Handler
elif cmd == 'T':
    scanner = BluetoothSecurityScanner()
    devices = await scanner.scan_bluetooth_devices(10)
    print(scanner.generate_report(devices))
```

## Output Example

```
======================================================================
🔵 BLUETOOTH SECURITY SCAN REPORT
======================================================================
Scan Time: 2025-12-20 09:25:00
Devices Found: 3

Risk Distribution:
  HIGH: 1
  MEDIUM: 1
  LOW: 1

----------------------------------------------------------------------
DEVICE DETAILS
----------------------------------------------------------------------

1. 🟠 iPhone 12 (AA:BB:CC:DD:EE:FF)
   Class: Phone
   Bluetooth: 5.0
   Risk Level: MEDIUM
   Security:
     Pairing: SSP_NUMERIC_COMPARISON
     Encryption: AES-CCM-128

2. 🔴 Old Headset (11:22:33:44:55:66)
   Class: Audio/Video
   Bluetooth: 2.0
   Risk Level: HIGH
   Vulnerabilities:
     • LEGACY_PAIRING
     • BLUEJACKING
     • BLUESNARFING
   Security:
     Pairing: LEGACY_PIN
     Encryption: E0_WEAK

3. 🟢 AirPods Pro (77:88:99:AA:BB:CC)
   Class: Audio/Video
   Bluetooth: 5.2
   Risk Level: LOW
   Security:
     Pairing: SSP_NUMERIC_COMPARISON
     Encryption: AES-CCM-128

======================================================================
```

## Architecture

```
bluetooth_security.py (Python Orchestrator)
    ├── libbt_scanner.so (C++ Engine)
    │   ├── Device Discovery
    │   ├── Service Enumeration
    │   └── Vulnerability Testing
    │
    └── rust_bluetooth (Rust Analyzer)
        ├── Pairing Analysis
        ├── Encryption Validation
        └── Security Scoring
```

## Performance

- **Device Discovery**: 1-10 seconds (C++)
- **Service Enumeration**: 0.5-2 seconds per device
- **Vulnerability Testing**: 1-3 seconds per device
- **Crypto Analysis**: <10ms per device (Rust)
- **Overall Scan**: 10-30 seconds for typical environment

**Speedup vs Pure Python**: 5-10x faster

## Security Considerations

### Legal Warning
⚠️ **Only scan devices you own or have permission to test**

Unauthorized Bluetooth scanning may violate:
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- Local privacy laws

### Ethical Use
This tool is designed for:
- Security auditing of your own devices
- Research and education
- Defensive security assessment

**NOT for:**
- Unauthorized device access
- Privacy invasion
- Malicious activities

## Troubleshooting

### "Bluetooth adapter not available"
- Check Bluetooth is enabled
- Verify permissions (may need sudo/root)
- Ensure BlueZ is installed (Linux)

### "PyBluez not installed"
```bash
pip install pybluez
```

### "C++ library not found"
```bash
cd cpp_accelerators
make clean && make
```

### "Permission denied"
```bash
# May need root for HCI access
sudo python3 bluetooth_security.py
```

## API Reference

### BluetoothSecurityScanner

**Methods:**
- `scan_bluetooth_devices(duration: int)` - Scan for devices
- `generate_report(devices: List)` - Generate text report
- `export_json(devices: List, filename: str)` - Export JSON

### BluetoothDevice

**Attributes:**
- `address` - MAC address
- `name` - Device name
- `bluetooth_version` - BT version
- `vulnerabilities` - Dict of vulnerabilities
- `security_analysis` - Security details
- `risk_level` - Overall risk (LOW/MEDIUM/HIGH/CRITICAL)

## Contributing

To add new vulnerability tests:
1. Add test method to `BluetoothScanner` class
2. Update `_test_vulnerabilities()` in Python
3. Update risk calculation logic

## License

Part of the Spiffy/Ultron Security Suite
