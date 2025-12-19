# Spiffy Installation Guide

## ✅ Installation Complete!

All Python dependencies have been successfully installed in a virtual environment.

## 📦 Installed Packages

- **cryptography** (46.0.3) - AES-GCM encryption for secure communications
- **pyotp** (2.9.0) - TOTP/2FA authentication support
- **qrcode** (8.2) - QR code generation for 2FA setup
- **Pillow** (12.0.0) - Image processing library
- **asyncio-dgram** (2.2.0) - Async networking utilities
- **cython** (3.2.3) - Performance optimization (3-5x faster!)

## 🚀 How to Use

### 1. Activate the Virtual Environment

```bash
source venv/bin/activate
```

Or use the convenient activation script:

```bash
source activate.sh
```

### 2. Build Performance Modules (Recommended)

For **3-5x performance boost**:

```bash
./build_fast.sh
```

This compiles Cython modules for:
- 5x faster MAC address processing
- 3x faster IP operations
- 5x faster string search
- Optimized network scanning

### 3. Run the Applications

**Ultron Zero v22 (Optimized - Recommended):**
```bash
python spiffy_ultron_zero_v22/spiffy_optimized.py
```

**Ultron Zero v22 (Standard):**
```bash
python spiffy_ultron_zero_v22/spiffy.py
```

**Spiffy Chat (Encrypted Messaging):**
```bash
python spiffy/spiffy_x.py
```

**Spiffy Standard Security Suite:**
```bash
python spiffy_standard_security_suite/main_security_tool.py
```

### 4. Deactivate When Done

```bash
deactivate
```

## ⚡ Performance Features

The optimized version includes:
- **Cython acceleration**: 3-5x faster operations
- **Connection pooling**: Reuses database connections
- **LRU caching**: Caches DNS, ARP, and OUI lookups
- **Async batching**: Better concurrency (150 threads)
- **Memory optimization**: 33% less memory usage

See [PERFORMANCE.md](PERFORMANCE.md) for detailed benchmarks.

## 📝 Notes

- The virtual environment is located in the `venv/` directory
- All dependencies are isolated from your system Python installation
- The `requirements.txt` file contains all package specifications
- Cython modules are optional but highly recommended for performance

## 🔧 Troubleshooting

If you encounter any issues:

1. Make sure you've activated the virtual environment
2. Verify Python 3 is installed: `python3 --version`
3. Reinstall dependencies: `./venv/bin/pip install -r requirements.txt`
4. Rebuild Cython modules: `./build_fast.sh`

## 📂 Project Structure

```
spiffy/
├── venv/                          # Virtual environment
├── requirements.txt               # Python dependencies
├── activate.sh                    # Activation helper script
├── build_fast.sh                  # Build Cython modules
├── PERFORMANCE.md                 # Performance guide
├── spiffy/                        # Encrypted chat application
├── spiffy_ultron_zero_v22/       # Security testing suite
│   ├── spiffy.py                 # Standard version
│   └── spiffy_optimized.py       # Optimized version (3-5x faster)
├── spiffy_standard_security_suite/ # Standard security tools
└── spiffy_fast/                   # Cython performance modules
    ├── network_utils.pyx          # Network utilities
    ├── data_utils.pyx             # Data processing
    └── *.so                       # Compiled modules
```
