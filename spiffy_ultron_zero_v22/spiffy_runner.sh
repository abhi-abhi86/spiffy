#!/bin/bash
# ============================================================================
# SPIFFY ULTRON ZERO V22 - MASTER RUNNER SCRIPT
# One script to rule them all - builds and runs everything
# ============================================================================

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}${BOLD}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     SPIFFY ULTRON ZERO V22 - MASTER SETUP & RUNNER           ║"
echo "║     Complete System Initialization & Launch                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ============================================================================
# PHASE 1: SYSTEM CHECK
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 1] System Requirements Check${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python 3 found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip3 found${NC}"
else
    echo -e "${RED}✗ pip3 not found. Please install pip${NC}"
    exit 1
fi

# Check C++ compiler
if command -v g++ &> /dev/null; then
    GCC_VERSION=$(g++ --version | head -n1)
    echo -e "${GREEN}✓ g++ found: $GCC_VERSION${NC}"
    HAS_CPP=true
elif command -v clang++ &> /dev/null; then
    CLANG_VERSION=$(clang++ --version | head -n1)
    echo -e "${GREEN}✓ clang++ found: $CLANG_VERSION${NC}"
    HAS_CPP=true
else
    echo -e "${YELLOW}⚠ No C++ compiler found. C++ accelerators will be disabled.${NC}"
    HAS_CPP=false
fi

# Check Rust
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(cargo --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Rust found: $RUST_VERSION${NC}"
    HAS_RUST=true
else
    echo -e "${YELLOW}⚠ Rust not found. Rust crypto accelerator will be disabled.${NC}"
    HAS_RUST=false
fi

# Check make
if command -v make &> /dev/null; then
    echo -e "${GREEN}✓ make found${NC}"
else
    echo -e "${YELLOW}⚠ make not found. Will skip C++ builds.${NC}"
    HAS_CPP=false
fi

echo ""

# ============================================================================
# PHASE 2: PYTHON DEPENDENCIES
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 2] Installing Python Dependencies${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "requirements.txt" ]; then
    echo -e "${CYAN}Installing from requirements.txt...${NC}"
    pip3 install -r requirements.txt --quiet || {
        echo -e "${YELLOW}⚠ Some packages failed to install. Continuing...${NC}"
    }
    echo -e "${GREEN}✓ Python dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠ requirements.txt not found. Installing core packages...${NC}"
    pip3 install cryptography scapy APScheduler requests --quiet || true
fi

echo ""

# ============================================================================
# PHASE 3: BUILD C++ ACCELERATORS
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 3] Building C++ Accelerators${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$HAS_CPP" = true ]; then
    # Build fast scanner v2
    if [ -d "cpp_accelerators" ]; then
        echo -e "${CYAN}Building fast_scanner_v2...${NC}"
        cd cpp_accelerators
        make clean &> /dev/null || true
        if make &> build.log; then
            echo -e "${GREEN}✓ C++ fast scanner built successfully${NC}"
        else
            echo -e "${YELLOW}⚠ C++ scanner build failed. Check cpp_accelerators/build.log${NC}"
        fi
        cd ..
    fi
    
    # Build Bluetooth scanner
    if [ -d "cpp_accelerators" ] && [ -f "cpp_accelerators/bluetooth_scanner.cpp" ]; then
        echo -e "${CYAN}Building Bluetooth scanner...${NC}"
        cd cpp_accelerators
        if make &> bt_build.log; then
            echo -e "${GREEN}✓ Bluetooth scanner built successfully${NC}"
        else
            echo -e "${YELLOW}⚠ Bluetooth scanner build failed${NC}"
        fi
        cd ..
    fi
else
    echo -e "${YELLOW}⚠ Skipping C++ builds (no compiler)${NC}"
fi

echo ""

# ============================================================================
# PHASE 4: BUILD RUST MODULES
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 4] Building Rust Modules${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$HAS_RUST" = true ]; then
    # Build Rust crypto
    if [ -d "rust_crypto" ] && [ -f "rust_crypto/Cargo.toml" ]; then
        echo -e "${CYAN}Building Rust crypto accelerator...${NC}"
        cd rust_crypto
        if cargo build --release &> ../rust_build.log; then
            echo -e "${GREEN}✓ Rust crypto built successfully${NC}"
        else
            echo -e "${YELLOW}⚠ Rust crypto build failed${NC}"
        fi
        cd ..
    fi
    
    # Build Rust Bluetooth analyzer
    if [ -d "rust_bluetooth" ] && [ -f "rust_bluetooth/Cargo.toml" ]; then
        echo -e "${CYAN}Building Rust Bluetooth analyzer...${NC}"
        cd rust_bluetooth
        
        # Check for maturin
        if command -v maturin &> /dev/null; then
            if maturin develop --release &> ../rust_bt_build.log; then
                echo -e "${GREEN}✓ Rust Bluetooth analyzer built${NC}"
            else
                echo -e "${YELLOW}⚠ Rust Bluetooth build failed${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ maturin not found. Install with: pip install maturin${NC}"
        fi
        cd ..
    fi
else
    echo -e "${YELLOW}⚠ Skipping Rust builds (no Rust toolchain)${NC}"
fi

echo ""

# ============================================================================
# PHASE 5: SETUP CONFIGURATION FILES
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 5] Configuration Setup${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create notifications config if not exists
if [ ! -f "notifications.conf" ] && [ -f "notifications.conf.example" ]; then
    echo -e "${CYAN}Creating notifications.conf from example...${NC}"
    cp notifications.conf.example notifications.conf
    echo -e "${GREEN}✓ notifications.conf created${NC}"
    echo -e "${YELLOW}  Edit notifications.conf to add your credentials${NC}"
fi

# Create scan schedule if not exists
if [ ! -f "scan_schedule.json" ] && [ -f "scan_schedule.json.example" ]; then
    echo -e "${CYAN}Creating scan_schedule.json from example...${NC}"
    cp scan_schedule.json.example scan_schedule.json
    echo -e "${GREEN}✓ scan_schedule.json created${NC}"
fi

# Create config.json if not exists
if [ ! -f "config.json" ]; then
    echo -e "${CYAN}Creating default config.json...${NC}"
    cat > config.json << 'EOF'
{
  "version": "22.0",
  "features": {
    "cpp_scanner": true,
    "rust_crypto": true,
    "redis_cache": false,
    "async_pool": true
  },
  "scan_defaults": {
    "timeout": 0.5,
    "max_threads": 100
  }
}
EOF
    echo -e "${GREEN}✓ config.json created${NC}"
fi

echo ""

# ============================================================================
# PHASE 6: VERIFY COMPONENTS
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 6] Component Verification${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

COMPONENTS_OK=0
COMPONENTS_TOTAL=0

# Check main script
if [ -f "spiffy.py" ]; then
    echo -e "${GREEN}✓ spiffy.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${RED}✗ spiffy.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check hardware fingerprinter
if [ -f "hardware_fingerprint.py" ]; then
    echo -e "${GREEN}✓ hardware_fingerprint.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ hardware_fingerprint.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check BIFROST tokens
if [ -f "bifrost_tokens.py" ]; then
    echo -e "${GREEN}✓ bifrost_tokens.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ bifrost_tokens.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check Global Vault
if [ -f "global_vault.py" ]; then
    echo -e "${GREEN}✓ global_vault.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ global_vault.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check device labeler
if [ -f "device_labeler.py" ]; then
    echo -e "${GREEN}✓ device_labeler.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ device_labeler.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check Bluetooth scanner
if [ -f "bluetooth_security.py" ]; then
    echo -e "${GREEN}✓ bluetooth_security.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ bluetooth_security.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check async pool
if [ -f "async_pool.py" ]; then
    echo -e "${GREEN}✓ async_pool.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ async_pool.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check cache manager
if [ -f "cache_manager.py" ]; then
    echo -e "${GREEN}✓ cache_manager.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ cache_manager.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check packet analyzer
if [ -f "packet_analyzer.py" ]; then
    echo -e "${GREEN}✓ packet_analyzer.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ packet_analyzer.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check scheduler
if [ -f "scheduler.py" ]; then
    echo -e "${GREEN}✓ scheduler.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ scheduler.py${NC}"
fi
((COMPONENTS_TOTAL++))

# Check notifier
if [ -f "notifier.py" ]; then
    echo -e "${GREEN}✓ notifier.py${NC}"
    ((COMPONENTS_OK++))
else
    echo -e "${YELLOW}⚠ notifier.py${NC}"
fi
((COMPONENTS_TOTAL++))

echo ""
echo -e "${CYAN}Components: ${COMPONENTS_OK}/${COMPONENTS_TOTAL} available${NC}"

echo ""

# ============================================================================
# PHASE 7: SYSTEM SUMMARY
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 7] System Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo -e "${BOLD}Available Features:${NC}"
echo ""

echo -e "${GREEN}🔴 OFFENSIVE MODULES${NC}"
echo "   [1] WIFI_RADAR       - Network topology scan"
echo "   [2] AUTO_EXPLOIT     - Automated fuzzing engine"
echo "   [3] SERVICE_STRESSOR - DDoS simulation"
echo "   [9] DNS_ENUM         - DNS reconnaissance"
echo "   [A] PASSWORD_CRACKER - Hash cracking"
echo "   [C] VULN_SCANNER     - Vulnerability detection"
echo ""

echo -e "${CYAN}🔵 DEFENSIVE MODULES${NC}"
echo "   [4] MITM_SENTINEL    - ARP spoofing detection"
echo "   [5] SSL_TLS_AUDIT    - Certificate validation"
echo "   [6] BREACH_SENSE     - Identity leak detection"
echo "   [B] PACKET_SNIFFER   - Network traffic analysis"
echo "   [T] BLUETOOTH_SCAN   - Bluetooth security audit"
echo ""

echo -e "${YELLOW}🟢 UTILITY MODULES${NC}"
echo "   [7] ENCRYPTED_VAULT  - Secure file encryption"
echo "   [8] BIFROST_CHAT     - P2P encrypted messaging"
echo "   [P] PRIVATE_CHAT     - Encrypted chat with GUI (NEW!)"
echo ""

echo -e "${BLUE}🔔 AUTOMATION & ALERTS${NC}"
echo "   [S] SCHEDULER        - Manage scheduled scans"
echo "   [N] NOTIFICATIONS    - Configure alerts"
echo ""

echo -e "${BOLD}Performance Enhancements:${NC}"
if [ "$HAS_CPP" = true ] && [ -f "cpp_accelerators/libbt_scanner.dylib" -o -f "cpp_accelerators/libbt_scanner.so" ]; then
    echo -e "   ${GREEN}✓ C++ Accelerators (6-10x faster)${NC}"
else
    echo -e "   ${YELLOW}⚠ C++ Accelerators (not available)${NC}"
fi

if [ "$HAS_RUST" = true ]; then
    echo -e "   ${GREEN}✓ Rust Crypto Analyzer${NC}"
else
    echo -e "   ${YELLOW}⚠ Rust Crypto Analyzer (not available)${NC}"
fi

echo -e "   ${GREEN}✓ Async I/O Connection Pool${NC}"
echo -e "   ${YELLOW}⚠ Redis Caching (requires Redis server)${NC}"

echo ""

# ============================================================================
# PHASE 8: LAUNCH OPTIONS
# ============================================================================
echo -e "${BLUE}${BOLD}[PHASE 8] Launch${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "How would you like to launch Spiffy?"
echo ""
echo "  [1] Interactive Mode (Full TUI)"
echo "  [2] Quick WiFi Scan"
echo "  [3] Bluetooth Security Scan"
echo "  [4] Run Specific Module"
echo "  [5] Show Help"
echo "  [0] Exit"
echo ""
read -p "Select option: " LAUNCH_OPTION

case $LAUNCH_OPTION in
    1)
        echo -e "${GREEN}Launching Spiffy in interactive mode...${NC}"
        python3 spiffy.py
        ;;
    2)
        echo -e "${GREEN}Running WiFi scan...${NC}"
        python3 spiffy.py --module WIFI_RADAR
        ;;
    3)
        echo -e "${GREEN}Running Bluetooth scan...${NC}"
        python3 bluetooth_security.py
        ;;
    4)
        echo ""
        echo "Available modules:"
        echo "  WIFI_RADAR, AUTO_EXPLOIT, SERVICE_STRESSOR, SSL_TLS_AUDIT"
        echo "  VULN_SCANNER, ENCRYPTED_VAULT, BIFROST_CHAT, BLUETOOTH_SCAN"
        echo ""
        read -p "Enter module name: " MODULE_NAME
        python3 spiffy.py --module "$MODULE_NAME"
        ;;
    5)
        ./omega_ops.sh help
        ;;
    P|p)
        echo -e "${GREEN}Launching Private Chat GUI...${NC}"
        echo ""
        # Check dependencies
        if ! python3 -c "import PyQt6" 2>/dev/null; then
            echo -e "${YELLOW}Installing PyQt6...${NC}"
            pip3 install PyQt6 --break-system-packages 2>/dev/null || pip3 install PyQt6
        fi
        if ! python3 -c "import flask_socketio" 2>/dev/null; then
            echo -e "${YELLOW}Installing Flask-SocketIO...${NC}"
            pip3 install flask flask-socketio python-socketio --break-system-packages 2>/dev/null || \
            pip3 install flask flask-socketio python-socketio
        fi
        # Build if needed
        if [ ! -f "rust_private_chat/target/release/librust_private_chat.dylib" ] && [ ! -f "rust_private_chat/target/release/librust_private_chat.so" ]; then
            echo -e "${CYAN}Building Rust crypto module...${NC}"
            ./build_private_chat.sh
        fi
        # Launch GUI
        python3 private_chat_gui.py
        ;;
    0)
        echo -e "${CYAN}Goodbye!${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}${BOLD}✓ Spiffy Ultron Zero V22 - Session Complete${NC}"
