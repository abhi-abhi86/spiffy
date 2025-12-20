#!/bin/bash
# Spiffy Web Chat Server Launcher
# Starts Flask server and creates public URL with ngrok

set -e

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          SPIFFY WEB CHAT SERVER - LAUNCHER                    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}Installing Flask and dependencies...${NC}"
    pip3 install flask flask-socketio python-socketio --break-system-packages --quiet
    echo -e "${GREEN}✓ Dependencies installed${NC}"
fi

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo -e "${YELLOW}⚠ Ngrok not found${NC}"
    echo "Install with: brew install ngrok"
    echo "Or download from: https://ngrok.com/download"
    echo ""
    read -p "Continue without ngrok? (local only) [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    USE_NGROK=false
else
    USE_NGROK=true
fi

# Start Flask server in background
echo -e "${CYAN}[1/3] Starting Flask server...${NC}"
python3 chat_server.py &
SERVER_PID=$!

sleep 3

if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${YELLOW}✗ Server failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Server running on http://localhost:5000${NC}"
echo ""

# Start ngrok if available
if [ "$USE_NGROK" = true ]; then
    echo -e "${CYAN}[2/3] Starting ngrok tunnel...${NC}"
    ngrok http 5001 --log=stdout > ngrok.log 2>&1 &
    NGROK_PID=$!
    
    sleep 3
    
    # Extract public URL
    PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "import sys, json; print(json.load(sys.stdin)['tunnels'][0]['public_url'])" 2>/dev/null || echo "")
    
    if [ -n "$PUBLIC_URL" ]; then
        echo -e "${GREEN}✓ Public URL created!${NC}"
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║  SHARE THIS URL WITH OTHERS:                                  ║${NC}"
        echo -e "${CYAN}║                                                                ║${NC}"
        echo -e "${CYAN}║  ${GREEN}${PUBLIC_URL}${NC}${CYAN}  ║${NC}"
        echo -e "${CYAN}║                                                                ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${YELLOW}⚠ Could not get ngrok URL${NC}"
        echo "Check ngrok dashboard: http://localhost:4040"
    fi
else
    echo -e "${CYAN}[2/3] Skipping ngrok (local only)${NC}"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  LOCAL ACCESS ONLY:                                            ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}║  ${GREEN}http://localhost:5001${NC}${CYAN}                                       ║${NC}"
    echo -e "${CYAN}║                                                                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
fi

echo ""
echo -e "${CYAN}[3/3] Server ready!${NC}"
echo ""
echo -e "${GREEN}✓ Users can now join the chat${NC}"
echo -e "${GREEN}✓ Real-time messaging enabled${NC}"
echo -e "${GREEN}✓ Press Ctrl+C to stop${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${CYAN}Shutting down...${NC}"
    kill $SERVER_PID 2>/dev/null || true
    [ -n "$NGROK_PID" ] && kill $NGROK_PID 2>/dev/null || true
    rm -f ngrok.log
    echo -e "${GREEN}✓ Server stopped${NC}"
    exit 0
}

trap cleanup INT TERM

# Wait
wait
