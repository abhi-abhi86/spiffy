#!/bin/bash
# Omega Kernel Installation Script
# Checks dependencies and sets up the environment

set -e

echo "⚡ OMEGA KERNEL INSTALLATION ⚡"
echo "================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -e "\n${YELLOW}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"

if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${GREEN}✓ Python $PYTHON_VERSION (OK)${NC}"
else
    echo -e "${RED}✗ Python 3.8+ required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

# Check required packages
echo -e "\n${YELLOW}Checking required packages...${NC}"

PACKAGES=(
    "cryptography"
    "psutil"
)

MISSING_PACKAGES=()

for package in "${PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        echo -e "${GREEN}✓ $package${NC}"
    else
        echo -e "${RED}✗ $package (missing)${NC}"
        MISSING_PACKAGES+=("$package")
    fi
done

# Install missing packages
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Installing missing packages...${NC}"
    pip3 install "${MISSING_PACKAGES[@]}"
fi

# Check system requirements
echo -e "\n${YELLOW}Checking system requirements...${NC}"

# Check if running as root (for some features)
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Running as root (some features require this)${NC}"
else
    echo -e "${YELLOW}⚠ Not running as root (some features may be limited)${NC}"
fi

# Create necessary directories
echo -e "\n${YELLOW}Creating directories...${NC}"
mkdir -p omega_logs
mkdir -p spiffy_exports
echo -e "${GREEN}✓ Directories created${NC}"

# Set permissions
chmod +x spiffy.py 2>/dev/null || true

# Run system check
echo -e "\n${YELLOW}Running system diagnostics...${NC}"
python3 << 'EOF'
import psutil
import platform

print(f"OS: {platform.system()} {platform.release()}")
print(f"CPU Cores: {psutil.cpu_count()}")
print(f"RAM: {psutil.virtual_memory().total / (1024**3):.1f} GB")
print(f"Disk Space: {psutil.disk_usage('/').free / (1024**3):.1f} GB free")
EOF

echo -e "\n${GREEN}✓ Installation complete!${NC}"
echo -e "\n${YELLOW}To run Omega Kernel:${NC}"
echo -e "  ${GREEN}python3 spiffy.py${NC}"
echo -e "\n${YELLOW}For full features, run with sudo:${NC}"
echo -e "  ${GREEN}sudo python3 spiffy.py${NC}"
