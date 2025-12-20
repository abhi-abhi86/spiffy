#!/bin/bash
# Simple test to access chat locally and via ngrok

echo "🔍 Checking Spiffy Chat Server Status"
echo "======================================"
echo ""

# Check if server is running
echo "1. Flask Server:"
if curl -s http://localhost:5001/health > /dev/null 2>&1; then
    echo "   ✅ Running on http://localhost:5001"
    curl -s http://localhost:5001/health | python3 -m json.tool
else
    echo "   ❌ Not running"
    echo "   Start with: python3 chat_server.py &"
fi

echo ""
echo "2. Ngrok Tunnel:"
if curl -s http://localhost:4040/api/tunnels > /dev/null 2>&1; then
    PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "import sys, json; data = json.load(sys.stdin); print(data['tunnels'][0]['public_url'] if data.get('tunnels') and len(data['tunnels']) > 0 else 'No tunnel')" 2>/dev/null)
    
    if [ "$PUBLIC_URL" != "No tunnel" ] && [ -n "$PUBLIC_URL" ]; then
        echo "   ✅ Active"
        echo "   📡 Public URL: $PUBLIC_URL"
        echo ""
        echo "   🌐 SHARE THIS URL:"
        echo "   ┌────────────────────────────────────────┐"
        echo "   │ $PUBLIC_URL"
        echo "   └────────────────────────────────────────┘"
    else
        echo "   ⚠️  Ngrok running but no tunnel"
        echo "   Check: http://localhost:4040"
    fi
else
    echo "   ❌ Not running"
    echo "   Start with: ngrok http 5001 &"
    echo ""
    echo "   📝 Note: Ngrok requires free account"
    echo "   Sign up: https://ngrok.com/signup"
    echo "   Then run: ngrok config add-authtoken YOUR_TOKEN"
fi

echo ""
echo "3. Local Access:"
echo "   🏠 http://localhost:5001"
echo ""
echo "======================================"
