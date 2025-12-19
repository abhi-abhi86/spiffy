#!/bin/bash
# Omega Kernel - Complete System Deployment
# Automated setup for all polyglot components

set -e

echo "⚡ OMEGA KERNEL v32.0 - POLYGLOT DEPLOYMENT ⚡"
echo "================================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check root privileges
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}⚠ Not running as root. Some features may be limited.${NC}"
fi

# 1. System Requirements Check
echo -e "\n${CYAN}[1/6] Checking System Requirements...${NC}"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ Python ${PYTHON_VERSION}${NC}"
else
    echo -e "${RED}✗ Python 3 not found${NC}"
    exit 1
fi

# Check PHP
if command -v php &> /dev/null; then
    PHP_VERSION=$(php --version | head -n 1 | awk '{print $2}')
    echo -e "${GREEN}✓ PHP ${PHP_VERSION}${NC}"
else
    echo -e "${YELLOW}⚠ PHP not found (dashboard will not work)${NC}"
fi

# Check Ruby
if command -v ruby &> /dev/null; then
    RUBY_VERSION=$(ruby --version | awk '{print $2}')
    echo -e "${GREEN}✓ Ruby ${RUBY_VERSION}${NC}"
else
    echo -e "${YELLOW}⚠ Ruby not found (automation will not work)${NC}"
fi

# Check Java
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java --version 2>&1 | head -n 1 | awk '{print $2}')
    echo -e "${GREEN}✓ Java ${JAVA_VERSION}${NC}"
else
    echo -e "${YELLOW}⚠ Java not found (agent will not work)${NC}"
fi

# 2. Install Python Dependencies
echo -e "\n${CYAN}[2/6] Installing Python Dependencies...${NC}"

PYTHON_PACKAGES=(
    "cryptography"
    "psutil"
)

for package in "${PYTHON_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        echo -e "${GREEN}✓ $package${NC}"
    else
        echo -e "${YELLOW}Installing $package...${NC}"
        pip3 install --user "$package" || echo -e "${RED}Failed to install $package${NC}"
    fi
done

# 3. Install Ruby Gems
echo -e "\n${CYAN}[3/6] Installing Ruby Gems...${NC}"

if command -v gem &> /dev/null; then
    gem list sqlite3 -i &>/dev/null || gem install sqlite3 --user-install
    echo -e "${GREEN}✓ Ruby gems installed${NC}"
fi

# 4. Setup Directories
echo -e "\n${CYAN}[4/6] Setting Up Directories...${NC}"

mkdir -p omega_logs
mkdir -p spiffy_exports
mkdir -p java_agent/build

echo -e "${GREEN}✓ Directories created${NC}"

# 5. Compile Java Agent
echo -e "\n${CYAN}[5/6] Compiling Java Agent...${NC}"

if [ -f "java_agent/BifrostAgent.java" ] && command -v javac &> /dev/null; then
    cd java_agent
    javac BifrostAgent.java 2>/dev/null && echo -e "${GREEN}✓ Java agent compiled${NC}" || echo -e "${YELLOW}⚠ Java compilation failed${NC}"
    cd ..
else
    echo -e "${YELLOW}⚠ Java agent not found or javac not available${NC}"
fi

# 6. System Diagnostics
echo -e "\n${CYAN}[6/6] System Diagnostics...${NC}"

python3 << 'EOF'
import platform
import psutil

print(f"OS: {platform.system()} {platform.release()}")
print(f"Architecture: {platform.machine()}")
print(f"CPU Cores: {psutil.cpu_count()}")
print(f"RAM: {psutil.virtual_memory().total / (1024**3):.1f} GB")
print(f"Disk Free: {psutil.disk_usage('/').free / (1024**3):.1f} GB")
EOF

# Final Summary
echo -e "\n${GREEN}✅ Deployment Complete!${NC}"
echo -e "\n${CYAN}Quick Start:${NC}"
echo -e "  ${GREEN}Python Core:${NC}     python3 spiffy.py"
echo -e "  ${GREEN}PHP Dashboard:${NC}   cd php_dashboard && php -S localhost:8080"
echo -e "  ${GREEN}Ruby Automation:${NC} cd ruby_automation && ruby workflows/daily_scan.rb"
echo -e "  ${GREEN}Java Agent:${NC}      cd java_agent && java BifrostAgent"

echo -e "\n${YELLOW}For full features, run with sudo:${NC}"
echo -e "  ${GREEN}sudo python3 spiffy.py${NC}"
