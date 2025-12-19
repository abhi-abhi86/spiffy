# Omega Kernel v32.0 - Complete Deployment Guide

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Clone repository
git clone https://github.com/abhi-abhi86/spiffy.git
cd spiffy/spiffy_ultron_zero_v22

# 2. Run deployment script
./deploy.sh

# 3. Start Omega Kernel
python3 spiffy.py
```

---

## 📋 System Requirements

### Minimum
- **OS**: macOS, Linux, or Windows (WSL)
- **Python**: 3.8+
- **RAM**: 2GB
- **Disk**: 1GB for logs and exports
- **Network**: Required for scanning features

### Recommended
- **Python**: 3.10+
- **RAM**: 4GB
- **CPU**: 4+ cores for parallel scanning
- **Privileges**: sudo for some features

---

## 🔧 Installation

### Step 1: Install Dependencies

**Python packages:**
```bash
pip3 install cryptography psutil
```

**Optional (for accelerators):**
```bash
# C++ compiler
xcode-select --install  # macOS
sudo apt-get install build-essential  # Linux

# Rust (for crypto accelerator)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# PHP (for dashboard)
brew install php  # macOS
sudo apt-get install php  # Linux
```

### Step 2: Build Accelerators (Optional)

**C++ Fast Scanner:**
```bash
cd cpp_accelerators
g++ -shared -fPIC -std=c++17 -O3 -o libfast_scanner.so fast_scanner.cpp
```

**Rust Crypto:**
```bash
cd rust_crypto
cargo build --release
```

### Step 3: Start Services

**Python Core:**
```bash
python3 spiffy.py
```

**PHP Dashboard:**
```bash
cd php_dashboard && php -S localhost:8080
# Access: http://localhost:8080
```

---

## 📚 Module Guide

### 🔴 OFFENSIVE MODULES

#### [1] WIFI_RADAR - Network Scanner
- Scans entire subnet (254 hosts)
- Device fingerprinting
- Port scanning (15 ports)
- Export to JSON/CSV
- **Performance**: 6x faster with C++

#### [2] AUTO_EXPLOIT - Fuzzing Engine
- SQLi, XSS, RCE payloads
- Web application testing
- Educational purposes

#### [3] SERVICE_STRESSOR - Load Testing
- DDoS simulation
- Stress testing
- Performance metrics

#### [9] DNS_ENUM - DNS Reconnaissance
- Subdomain discovery
- DNS record enumeration

#### [A] PASSWORD_CRACKER - Hash Analysis
- MD5, SHA1, SHA256 support
- Password strength analyzer

#### [C] VULN_SCANNER - Vulnerability Detection
- Automated scanning
- Common vulnerability checks

### 🔵 DEFENSIVE MODULES

#### [4] MITM_SENTINEL - ARP Monitoring
- ARP spoofing detection
- Network monitoring

#### [5] SSL_TLS_AUDIT - Certificate Validation
- SSL/TLS configuration audit
- Certificate expiration checks

#### [6] BREACH_SENSE - Identity Leak Detection
- Credential breach checking

#### [B] PACKET_SNIFFER - Traffic Analysis
- Network traffic monitoring
- Protocol analysis

### 🟢 UTILITY MODULES

#### [7] ENCRYPTED_VAULT - File Encryption
- AES-256-GCM encryption
- Secure file storage

#### [8] BIFROST_CHAT - P2P Messaging
- Encrypted P2P communication
- ECDH + AES-256-GCM
- **Performance**: 10x faster with Rust

---

## 🌐 Polyglot Components

| Language | Role | Performance |
|----------|------|-------------|
| **Python** | Main orchestrator | Baseline |
| **C++** | Network scanning | 6x faster |
| **Rust** | Cryptography | 10x faster |
| **PHP** | Web dashboard | N/A |
| **Ruby** | Automation | N/A |
| **Bash** | Deployment | N/A |
| **Java** | Portable agent | N/A |

---

## 🐛 Troubleshooting

**Permission denied:**
```bash
sudo python3 spiffy.py
```

**Module not found:**
```bash
pip3 install cryptography psutil
```

**Database locked:**
```bash
pkill -f spiffy.py
rm ultron_zero.db-journal
```

**C++ accelerator not loading:**
```bash
cd cpp_accelerators
g++ -shared -fPIC -std=c++17 -O3 -o libfast_scanner.so fast_scanner.cpp
```

---

## 📊 Monitoring

### Log Files
```
omega_logs/
├── security.log
├── performance.log
├── error.log
└── audit.log
```

### Analytics
```bash
python3 analytics.py
```

### Web Dashboard
```bash
cd php_dashboard && php -S localhost:8080
```

---

## ✅ Quick Reference

```bash
# Start application
python3 spiffy.py

# Start dashboard
cd php_dashboard && php -S localhost:8080

# Run automation
cd ruby_automation && ruby workflows/daily_scan.rb

# Generate analytics
python3 analytics.py

# Deploy system
./deploy.sh
```

---

⚡ **OMEGA KERNEL: PRODUCTION-READY** ⚡
