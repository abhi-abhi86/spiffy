#!/bin/bash
# Spiffy Private Chat - Global Access Setup
# Makes your chat accessible from anywhere in the world!

echo "🌍 SPIFFY PRIVATE CHAT - GLOBAL ACCESS SETUP"
echo "=============================================="
echo ""

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo "❌ ngrok not found!"
    echo ""
    echo "📥 Installing ngrok..."
    echo ""
    
    # Detect OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install ngrok/ngrok/ngrok
        else
            echo "Please install Homebrew first: https://brew.sh"
            echo "Or download ngrok from: https://ngrok.com/download"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
        echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
        sudo apt update && sudo apt install ngrok
    else
        echo "Please install ngrok manually from: https://ngrok.com/download"
        exit 1
    fi
fi

echo "✅ ngrok is installed"
echo ""

# Check if ngrok is authenticated
if ! ngrok config check &> /dev/null; then
    echo "⚠️  ngrok not authenticated"
    echo ""
    echo "📝 To authenticate ngrok:"
    echo "   1. Sign up at: https://dashboard.ngrok.com/signup"
    echo "   2. Get your authtoken from: https://dashboard.ngrok.com/get-started/your-authtoken"
    echo "   3. Run: ngrok config add-authtoken YOUR_TOKEN"
    echo ""
    read -p "Press Enter after you've authenticated ngrok..."
fi

echo ""
echo "🚀 Starting Spiffy Private Chat with Global Access..."
echo ""

# Start the chat server in background
cd "$(dirname "$0")"
source /Users/mg/Documents/spiffy/venv/bin/activate 2>/dev/null || true
python3 private_chat_web.py > chat_server.log 2>&1 &
SERVER_PID=$!

echo "✅ Chat server started (PID: $SERVER_PID)"
sleep 3

# Start ngrok tunnel
echo "🌐 Creating secure tunnel to the internet..."
ngrok http 5001 > ngrok.log 2>&1 &
NGROK_PID=$!

echo "✅ Ngrok tunnel started (PID: $NGROK_PID)"
sleep 4

# Get the public URL
echo ""
echo "🎉 YOUR CHAT IS NOW ACCESSIBLE WORLDWIDE!"
echo "=========================================="
echo ""

# Extract ngrok URL
PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | python3 -c "import sys, json; print(json.load(sys.stdin)['tunnels'][0]['public_url'])" 2>/dev/null)

if [ -n "$PUBLIC_URL" ]; then
    echo "🌍 PUBLIC URL: $PUBLIC_URL"
    echo ""
    echo "📋 Host Dashboard: $PUBLIC_URL"
    echo ""
    echo "✨ Share this URL with anyone, anywhere in the world!"
    echo "   They can access your chat from any device, any network!"
    echo ""
else
    echo "⚠️  Could not get public URL automatically"
    echo "   Check ngrok dashboard: http://localhost:4040"
fi

echo "📊 Ngrok Dashboard: http://localhost:4040"
echo ""
echo "🛑 To stop: Press Ctrl+C or run: pkill -f ngrok && pkill -f private_chat_web"
echo ""

# Keep script running
trap "kill $SERVER_PID $NGROK_PID 2>/dev/null" EXIT
wait
