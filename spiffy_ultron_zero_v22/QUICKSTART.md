# Spiffy Ultron Zero V22 - Quick Start Guide

## 🚀 One-Command Setup & Launch

```bash
./spiffy_runner.sh
```

That's it! This single script will:
1. ✅ Check all system requirements
2. ✅ Install Python dependencies
3. ✅ Build C++ accelerators
4. ✅ Build Rust modules (if available)
5. ✅ Setup configuration files
6. ✅ Verify all components
7. ✅ Display all available features
8. ✅ Launch the application

---

## 📋 What Gets Built

### C++ Accelerators (6-10x faster)
- **Fast Scanner V2**: High-performance network scanning
- **Bluetooth Scanner**: Device enumeration and security analysis

### Rust Modules (Memory-safe crypto)
- **Crypto Accelerator**: Secure cryptographic operations
- **Bluetooth Analyzer**: Security scoring and analysis

### Python Components
- Hardware Fingerprinting
- BIFROST 10-Digit Tokens
- Global Vault Logging
- Device Labeling
- Async Connection Pool
- Cache Manager
- Packet Analyzer
- Scheduler
- Notifier

---

## 🎯 Available Features

### 🔴 OFFENSIVE MODULES
- `[1]` **WIFI_RADAR** - Network topology scan with device fingerprinting
- `[2]` **AUTO_EXPLOIT** - Automated fuzzing engine (SQLi, XSS, RCE)
- `[3]` **SERVICE_STRESSOR** - DDoS simulation and load testing
- `[9]` **DNS_ENUM** - DNS reconnaissance & subdomain discovery
- `[A]` **PASSWORD_CRACKER** - Hash cracking & password analysis
- `[C]` **VULN_SCANNER** - Automated vulnerability detection

### 🔵 DEFENSIVE MODULES
- `[4]` **MITM_SENTINEL** - ARP spoofing detection & monitoring
- `[5]` **SSL_TLS_AUDIT** - Certificate validation & protocol analysis
- `[6]` **BREACH_SENSE** - Identity leak detection
- `[B]` **PACKET_SNIFFER** - Network traffic analysis
- `[T]` **BLUETOOTH_SCAN** - Bluetooth security audit (C++ backend)

### 🟢 UTILITY MODULES
- `[7]` **ENCRYPTED_VAULT** - Secure file encryption (AES-256-GCM)
- `[8]` **BIFROST_CHAT** - P2P encrypted messaging (ECDH + AES)

### 🔔 AUTOMATION & ALERTS
- `[S]` **SCHEDULER** - Manage scheduled scans
- `[N]` **NOTIFICATIONS** - Configure alerts (Email/Telegram/Discord)

---

## 🏃 Quick Launch Options

### Option 1: Interactive Mode (Full TUI)
```bash
./spiffy_runner.sh
# Select: [1] Interactive Mode
```

### Option 2: Quick WiFi Scan
```bash
./spiffy_runner.sh
# Select: [2] Quick WiFi Scan
```

### Option 3: Bluetooth Security Scan
```bash
./spiffy_runner.sh
# Select: [3] Bluetooth Security Scan
```

### Option 4: Direct Module Launch
```bash
python3 spiffy.py --module WIFI_RADAR
python3 spiffy.py --module BLUETOOTH_SCAN
python3 bluetooth_security.py
```

---

## 📦 System Requirements

### Required
- **Python 3.8+** ✅
- **pip3** ✅

### Optional (for performance)
- **g++/clang++** - For C++ accelerators (6-10x faster)
- **make** - For building C++ components
- **Rust + Cargo** - For Rust crypto modules
- **maturin** - For Rust Python bindings

### Install Optional Tools
```bash
# macOS
brew install rust

# Linux
sudo apt-get install build-essential cargo

# Python tools
pip3 install maturin
```

---

## 🔧 Manual Build (if needed)

### Build C++ Accelerators
```bash
cd cpp_accelerators
make clean && make
```

### Build Rust Modules
```bash
cd rust_crypto
cargo build --release

cd ../rust_bluetooth
maturin develop --release
```

---

## 📊 Performance Enhancements

| Component | Speedup | Status |
|-----------|---------|--------|
| C++ Fast Scanner | 6-10x | ✅ Auto-built |
| C++ Bluetooth Scanner | 5-10x | ✅ Auto-built |
| Rust Crypto Analyzer | 3-5x | ⚠️ Requires Rust |
| Async I/O Pool | 2-3x | ✅ Built-in |
| Redis Caching | 100-1000x | ⚠️ Requires Redis |

---

## 🗂️ Project Structure

```
spiffy_ultron_zero_v22/
├── spiffy_runner.sh          ← MASTER SCRIPT (run this!)
├── spiffy.py                  ← Main application
├── omega_ops.sh               ← CLI wrapper
│
├── OMEGA-INFINITY Features
│   ├── hardware_fingerprint.py
│   ├── bifrost_tokens.py
│   ├── global_vault.py
│   └── device_labeler.py
│
├── Bluetooth Security
│   ├── bluetooth_security.py  ← Python frontend (10%)
│   └── cpp_accelerators/
│       └── bluetooth_scanner.cpp  ← C++ backend (90%)
│
├── Performance
│   ├── async_pool.py
│   ├── cache_manager.py
│   └── cpp_accelerators/
│       └── fast_scanner_v2.cpp
│
├── Automation
│   ├── packet_analyzer.py
│   ├── scheduler.py
│   └── notifier.py
│
└── Configuration
    ├── config.json
    ├── notifications.conf
    └── scan_schedule.json
```

---

## 🐛 Troubleshooting

### "Backend not available"
```bash
cd cpp_accelerators
make clean && make
```

### "Rust not found"
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### "Permission denied"
```bash
chmod +x spiffy_runner.sh
chmod +x omega_ops.sh
```

### "Module not found"
```bash
# Install Python dependencies
pip3 install -r requirements.txt
# Or
pip3 install cryptography scapy APScheduler requests redis
```

---

## 📝 Configuration

### Notifications (Email/Telegram/Discord)
Edit `notifications.conf`:
```ini
[email]
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
username = your_email@gmail.com
password = your_app_password
```

### Scheduled Scans
Edit `scan_schedule.json`:
```json
{
  "jobs": [
    {
      "name": "daily_wifi_scan",
      "module": "WIFI_RADAR",
      "schedule": "cron",
      "cron": "0 9 * * *"
    }
  ]
}
```

---

## 🎓 Usage Examples

### Example 1: Full Security Audit
```bash
./spiffy_runner.sh
# Select [1] Interactive Mode
# Run: 1 (WiFi Radar)
# Run: T (Bluetooth Scan)
# Run: 5 (SSL/TLS Audit)
```

### Example 2: Automated Scanning
```bash
# Setup schedule
./spiffy_runner.sh
# Select [1] Interactive Mode
# Press S (Scheduler)
# Add jobs
```

### Example 3: Quick Network Check
```bash
./spiffy_runner.sh
# Select [2] Quick WiFi Scan
```

---

## 🏆 Features Summary

✅ **11/11 Components Available**
✅ **C++ Accelerators Built**
✅ **All Modules Verified**
✅ **Configuration Auto-Setup**
✅ **One-Command Launch**

---

## 📞 Support

For issues or questions:
1. Check build logs in `cpp_accelerators/`
2. Verify Python version: `python3 --version`
3. Check component status: `./spiffy_runner.sh` (Phase 6)

---

**Ready to go! Just run: `./spiffy_runner.sh`** 🚀
