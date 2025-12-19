#!/bin/bash

# ULTRON-ZERO OPS CONTROL v1.0
# Shell wrapper for Spiffy Security Kernel

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BANNER="
${RED}██╗   ██╗██╗  ████████╗██████╗  ██████╗ ███╗   ██╗
██║   ██║██║  ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
██║   ██║██║     ██║   ██████╔╝██║   ██║██╔██╗ ██║
██║   ██║██║     ██║   ██╔══██╗██║   ██║██║╚██╗██║
╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝${NC}
        ${YELLOW}>>> OPS CONTROL TERMINAL <<<${NC}
"

function show_help() {
    echo -e "$BANNER"
    echo -e "USAGE: ./omega_ops.sh [COMMAND] [TARGET]"
    echo ""
    echo -e "COMMANDS:"
    echo -e "  ${GREEN}scan${NC}              : Run WiFi Rader scan on local subnet"
    echo -e "  ${GREEN}attack${NC} <url>      : Run Auto-Exploit fuzzing on target URL"
    echo -e "  ${GREEN}stress${NC} <url>      : Run Service Stressor (DDoS sim) on target"
    echo -e "  ${GREEN}audit${NC}  <domain>   : Audit SSL/TLS certificate of domain"
    echo -e "  ${GREEN}help${NC}              : Show this menu"
    echo ""
    echo -e "EXAMPLES:"
    echo -e "  ./omega_ops.sh scan"
    echo -e "  ./omega_ops.sh attack http://target.local"
}

if [ "$1" == "" ]; then
    show_help
    exit 0
fi

CMD=$1
TARGET=$2

echo -e "$BANNER"

case $CMD in
    scan)
        echo -e "${BLUE}[*] INITIATING WIFI RADAR SCAN...${NC}"
        python3 spiffy.py --module wifi --headless
        ;;
    attack)
        if [ "$TARGET" == "" ]; then echo -e "${RED}[!] Target URL required${NC}"; exit 1; fi
        echo -e "${RED}[*] LAUNCHING AUTO-EXPLOIT MODULE vs $TARGET...${NC}"
        python3 spiffy.py --module exploit --target "$TARGET" --headless
        ;;
    stress)
        if [ "$TARGET" == "" ]; then echo -e "${RED}[!] Target URL required${NC}"; exit 1; fi
        echo -e "${RED}[!] ENGAGING STRESS TEST vs $TARGET...${NC}"
        python3 spiffy.py --module stress --target "$TARGET" --headless
        ;;
    audit)
        if [ "$TARGET" == "" ]; then echo -e "${RED}[!] Target Domain required${NC}"; exit 1; fi
        echo -e "${BLUE}[*] AUDITING SSL CERTIFICATE for $TARGET...${NC}"
        python3 spiffy.py --module ssl --target "$TARGET" --headless
        ;;
    help)
        show_help
        ;;
    *)
        echo -e "${RED}[!] UNKNOWN COMMAND: $CMD${NC}"
        show_help
        exit 1
        ;;
esac

echo -e "\n${GREEN}[✓] OPERATION COMPLETE.${NC}"
