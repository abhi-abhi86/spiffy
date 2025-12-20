#!/bin/bash
# ============================================================================
# SPIFFY ULTRON ZERO V22 - MASTER RUNNER SCRIPT
# Animated Setup & Launch System
# ============================================================================

set -e

# Colors & Effects
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
BLINK='\033[5m'
NC='\033[0m'

# Animation functions
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

progress_bar() {
    local duration=$1
    local width=50
    local progress=0
    
    while [ $progress -le 100 ]; do
        local filled=$((progress * width / 100))
        local empty=$((width - filled))
        
        printf "\r${CYAN}["
        printf "%${filled}s" | tr ' ' '█'
        printf "%${empty}s" | tr ' ' '░'
        printf "] ${progress}%%${NC}"
        
        progress=$((progress + 2))
        sleep $(echo "scale=3; $duration/50" | bc)
    done
    echo ""
}

type_text() {
    local text="$1"
    local delay=${2:-0.03}
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo ""
}

# Animated Banner
clear
echo -e "${CYAN}${BOLD}"
cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ███████╗██████╗ ██╗███████╗███████╗██╗   ██╗                ║
║   ██╔════╝██╔══██╗██║██╔════╝██╔════╝╚██╗ ██╔╝                ║
║   ███████╗██████╔╝██║█████╗  █████╗   ╚████╔╝                 ║
║   ╚════██║██╔═══╝ ██║██╔══╝  ██╔══╝    ╚██╔╝                  ║
║   ███████║██║     ██║██║     ██║        ██║                   ║
║   ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝        ╚═╝                   ║
║                                                                ║
║        ⚡ ULTRON ZERO V22 - MASTER INITIALIZATION ⚡          ║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║  Developed by @abhi-abhi86 | https://github.com/abhi-abhi86   ║
╚════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

sleep 0.5

# Get directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR/spiffy_ultron_zero_v22"

if [ ! -d "$PROJECT_DIR" ]; then
    echo -e "${RED}✗ Project directory not found${NC}"
    exit 1
fi

cd "$PROJECT_DIR"
echo -e "${DIM}Working directory: $PROJECT_DIR${NC}"
echo ""
sleep 0.3

# ============================================================================
# PHASE 1: SYSTEM CHECK
# ============================================================================
echo -e "${BLUE}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║  PHASE 1: SYSTEM REQUIREMENTS CHECK                          ║${NC}"
echo -e "${BLUE}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Animated checks
echo -ne "${CYAN}[⚙]${NC} Checking Python 3...        "
sleep 0.3
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Found v$PYTHON_VERSION${NC}"
    HAS_PYTHON=true
else
    echo -e "${RED}✗ Not found${NC}"
    exit 1
fi

echo -ne "${CYAN}[⚙]${NC} Checking pip3...           "
sleep 0.2
command -v pip3 &> /dev/null && echo -e "${GREEN}✓ Available${NC}" || { echo -e "${RED}✗ Missing${NC}"; exit 1; }

echo -ne "${CYAN}[⚙]${NC} Checking C++ compiler...   "
sleep 0.2
if command -v g++ &> /dev/null || command -v clang++ &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_CPP=true
else
    echo -e "${YELLOW}⚠ Not found${NC}"
    HAS_CPP=false
fi

echo -ne "${CYAN}[⚙]${NC} Checking Rust toolchain... "
sleep 0.2
if command -v cargo &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_RUST=true
else
    echo -e "${YELLOW}⚠ Not found${NC}"
    HAS_RUST=false
fi

echo -ne "${CYAN}[⚙]${NC} Checking make utility...   "
sleep 0.2
command -v make &> /dev/null && echo -e "${GREEN}✓ Available${NC}" || HAS_CPP=false

echo ""

# ============================================================================
# PHASE 2: BUILD C++ ACCELERATORS
# ============================================================================
echo -e "${MAGENTA}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}${BOLD}║  PHASE 2: BUILDING C++ ACCELERATORS                          ║${NC}"
echo -e "${MAGENTA}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$HAS_CPP" = true ] && [ -d "cpp_accelerators" ]; then
    echo -e "${CYAN}[🔨] Compiling C++ components...${NC}"
    cd cpp_accelerators
    make clean &> /dev/null || true
    
    if make &> build.log 2>&1; then
        progress_bar 1.5
        echo -e "${GREEN}✓ Fast Scanner built successfully (6-10x speedup)${NC}"
        echo -e "${GREEN}✓ Bluetooth Scanner built successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Build failed (check cpp_accelerators/build.log)${NC}"
    fi
    cd ..
else
    echo -e "${YELLOW}⚠ Skipping C++ builds (compiler not available)${NC}"
fi

echo ""

# ============================================================================
# PHASE 3: COMPONENT VERIFICATION
# ============================================================================
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  PHASE 3: COMPONENT VERIFICATION                             ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

COMPONENTS=(
    "spiffy.py:Main Application"
    "hardware_fingerprint.py:Hardware Fingerprinting"
    "bifrost_tokens.py:BIFROST Tokens"
    "global_vault.py:Global Vault"
    "device_labeler.py:Device Labeling"
    "bluetooth_security.py:Bluetooth Scanner"
    "async_pool.py:Async I/O Pool"
    "cache_manager.py:Cache Manager"
    "packet_analyzer.py:Packet Analyzer"
    "scheduler.py:Scheduler"
    "notifier.py:Notifier"
)

COMPONENTS_OK=0
COMPONENTS_TOTAL=${#COMPONENTS[@]}

for component in "${COMPONENTS[@]}"; do
    IFS=':' read -r file name <<< "$component"
    echo -ne "${CYAN}[◆]${NC} Verifying ${name}..."
    
    # Pad to align checkmarks
    padding=$((40 - ${#name}))
    printf "%${padding}s"
    
    sleep 0.1
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC}"
        ((COMPONENTS_OK++))
    else
        echo -e "${RED}✗${NC}"
    fi
done

echo ""
echo -e "${BOLD}Components Status: ${GREEN}${COMPONENTS_OK}/${COMPONENTS_TOTAL}${NC} ${BOLD}available${NC}"
echo ""

# ============================================================================
# PHASE 4: FEATURE SUMMARY
# ============================================================================
echo -e "${YELLOW}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}${BOLD}║  PHASE 4: AVAILABLE FEATURES                                 ║${NC}"
echo -e "${YELLOW}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

sleep 0.3

echo -e "${RED}${BOLD}🔴 OFFENSIVE MODULES${NC}"
type_text "   [1] WIFI_RADAR       - Network topology & fingerprinting" 0.01
type_text "   [2] AUTO_EXPLOIT     - Automated fuzzing engine" 0.01
type_text "   [3] SERVICE_STRESSOR - DDoS simulation" 0.01
type_text "   [9] DNS_ENUM         - DNS reconnaissance" 0.01
type_text "   [A] PASSWORD_CRACKER - Hash cracking" 0.01
type_text "   [C] VULN_SCANNER     - Vulnerability detection" 0.01
echo ""

echo -e "${CYAN}${BOLD}🔵 DEFENSIVE MODULES${NC}"
type_text "   [4] MITM_SENTINEL    - ARP spoofing detection" 0.01
type_text "   [5] SSL_TLS_AUDIT    - Certificate validation" 0.01
type_text "   [6] BREACH_SENSE     - Identity leak detection" 0.01
type_text "   [B] PACKET_SNIFFER   - Network traffic analysis" 0.01
type_text "   [T] BLUETOOTH_SCAN   - Bluetooth security audit ⭐" 0.01
echo ""

echo -e "${GREEN}${BOLD}🟢 UTILITY MODULES${NC}"
type_text "   [7] ENCRYPTED_VAULT  - AES-256-GCM encryption" 0.01
type_text "   [8] BIFROST_CHAT     - P2P encrypted messaging" 0.01
echo ""

echo -e "${MAGENTA}${BOLD}🔔 AUTOMATION & ALERTS${NC}"
type_text "   [S] SCHEDULER        - Automated scans" 0.01
type_text "   [N] NOTIFICATIONS    - Multi-channel alerts" 0.01
echo ""

# Performance status
echo -e "${BOLD}⚡ Performance Enhancements:${NC}"
if [ "$HAS_CPP" = true ] && [ -f "cpp_accelerators/libbt_scanner.dylib" -o -f "cpp_accelerators/libbt_scanner.so" ]; then
    echo -e "   ${GREEN}✓ C++ Accelerators${NC} ${DIM}(6-10x faster)${NC}"
else
    echo -e "   ${YELLOW}⚠ C++ Accelerators${NC} ${DIM}(not available)${NC}"
fi

[ "$HAS_RUST" = true ] && echo -e "   ${GREEN}✓ Rust Crypto${NC}" || echo -e "   ${YELLOW}⚠ Rust Crypto${NC} ${DIM}(optional)${NC}"
echo -e "   ${GREEN}✓ Async I/O Pool${NC}"
echo ""

# ============================================================================
# PHASE 5: LAUNCH MENU
# ============================================================================
echo -e "${BLUE}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║  PHASE 5: LAUNCH OPTIONS                                     ║${NC}"
echo -e "${BLUE}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}Select launch mode:${NC}"
echo ""
echo -e "  ${GREEN}[1]${NC} ${BOLD}Interactive Mode${NC}     ${DIM}(Full TUI experience)${NC}"
echo -e "  ${CYAN}[2]${NC} ${BOLD}Quick WiFi Scan${NC}      ${DIM}(Network reconnaissance)${NC}"
echo -e "  ${MAGENTA}[3]${NC} ${BOLD}Bluetooth Scan${NC}       ${DIM}(Security audit)${NC}"
echo -e "  ${YELLOW}[4]${NC} ${BOLD}Specific Module${NC}      ${DIM}(Choose module)${NC}"
echo -e "  ${BLUE}[5]${NC} ${BOLD}Show Help${NC}            ${DIM}(Documentation)${NC}"
echo -e "  ${RED}[0]${NC} ${BOLD}Exit${NC}                 ${DIM}(Shutdown)${NC}"
echo ""
echo -ne "${BOLD}${GREEN}➤ ${NC}"
read -p "" LAUNCH_OPTION

echo ""

case $LAUNCH_OPTION in
    1)
        echo -e "${GREEN}${BOLD}[⚡] Launching Interactive Mode...${NC}"
        progress_bar 0.5
        python3 spiffy.py
        ;;
    2)
        echo -e "${CYAN}${BOLD}[📡] Initiating WiFi Scan...${NC}"
        progress_bar 0.5
        python3 spiffy.py --module WIFI_RADAR
        ;;
    3)
        echo -e "${MAGENTA}${BOLD}[🔵] Starting Bluetooth Security Scan...${NC}"
        progress_bar 0.5
        python3 bluetooth_security.py
        ;;
    4)
        echo ""
        echo -e "${YELLOW}Available modules:${NC}"
        echo "  WIFI_RADAR, AUTO_EXPLOIT, SERVICE_STRESSOR, SSL_TLS_AUDIT"
        echo "  VULN_SCANNER, ENCRYPTED_VAULT, BIFROST_CHAT, BLUETOOTH_SCAN"
        echo ""
        read -p "Enter module name: " MODULE_NAME
        echo -e "${YELLOW}${BOLD}[⚙] Loading $MODULE_NAME...${NC}"
        progress_bar 0.5
        python3 spiffy.py --module "$MODULE_NAME"
        ;;
    5)
        [ -f "omega_ops.sh" ] && ./omega_ops.sh help || echo "Help not available"
        ;;
    0)
        echo ""
        echo -e "${CYAN}${BOLD}"
        type_text "╔════════════════════════════════════════════════════════════════╗" 0.005
        type_text "║  SHUTDOWN SEQUENCE INITIATED                                  ║" 0.005
        type_text "╚════════════════════════════════════════════════════════════════╝" 0.005
        echo -e "${NC}"
        sleep 0.3
        echo -e "${GREEN}✓ All systems nominal${NC}"
        echo -e "${GREEN}✓ Goodbye!${NC}"
        echo ""
        exit 0
        ;;
    *)
        echo -e "${RED}✗ Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}${BOLD}✓ Session Complete${NC}"
echo ""
