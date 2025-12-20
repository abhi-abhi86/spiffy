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
    echo -e "USAGE: ./omega_ops.sh [COMMAND] [OPTIONS]"
    echo ""
    echo -e "COMMANDS:"
    echo -e "  ${GREEN}scan${NC}              : Run WiFi Radar scan on local subnet"
    echo -e "  ${GREEN}attack${NC} <url>      : Run Auto-Exploit fuzzing on target URL"
    echo -e "  ${GREEN}stress${NC} <url>      : Run Service Stressor (DDoS sim) on target"
    echo -e "  ${GREEN}audit${NC}  <domain>   : Audit SSL/TLS certificate of domain"
    echo -e "  ${GREEN}sniff${NC}  [iface]    : Real packet capture (requires sudo)"
    echo -e "  ${GREEN}schedule${NC} <action> : Manage scheduled scans"
    echo -e "    - ${YELLOW}list${NC}          : List all scheduled jobs"
    echo -e "    - ${YELLOW}add${NC}           : Add new scheduled job"
    echo -e "  ${GREEN}notify${NC}   <action> : Notification management"
    echo -e "    - ${YELLOW}status${NC}        : Show notification config status"
    echo -e "    - ${YELLOW}test${NC}          : Test all notification channels"
    echo -e "  ${GREEN}help${NC}              : Show this menu"
    echo ""
    echo -e "EXAMPLES:"
    echo -e "  ./omega_ops.sh scan"
    echo -e "  ./omega_ops.sh attack http://target.local"
    echo -e "  sudo ./omega_ops.sh sniff en0"
    echo -e "  ./omega_ops.sh schedule list"
    echo -e "  ./omega_ops.sh notify test"
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
    sniff)
        IFACE=${TARGET:-"en0"}
        echo -e "${BLUE}[*] STARTING PACKET CAPTURE on $IFACE (requires sudo)...${NC}"
        sudo python3 packet_analyzer.py -i "$IFACE" -t 30
        ;;
    schedule)
        ACTION=$TARGET
        case $ACTION in
            list)
                echo -e "${BLUE}[*] LISTING SCHEDULED JOBS...${NC}"
                python3 scheduler.py list
                ;;
            add)
                echo -e "${BLUE}[*] ADDING SCHEDULED JOB...${NC}"
                echo -e "${YELLOW}This is an interactive process${NC}"
                python3 -c "from scheduler import ScanScheduler; s = ScanScheduler(); \
                    name = input('Job Name: '); \
                    module = input('Module (WIFI_RADAR/VULN_SCANNER/etc): '); \
                    schedule = input('Schedule (cron or interval): '); \
                    s.add_job(name, module, schedule)"
                ;;
            *)
                echo -e "${RED}[!] Unknown schedule action. Use: list, add${NC}"
                ;;
        esac
        ;;
    notify)
        ACTION=$TARGET
        case $ACTION in
            status)
                echo -e "${BLUE}[*] NOTIFICATION STATUS...${NC}"
                python3 notifier.py --status
                ;;
            test)
                echo -e "${BLUE}[*] TESTING NOTIFICATIONS...${NC}"
                python3 notifier.py --test
                ;;
            *)
                echo -e "${RED}[!] Unknown notify action. Use: status, test${NC}"
                ;;
        esac
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
