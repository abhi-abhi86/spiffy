#!/bin/bash
# Ngrok Setup Helper for Spiffy Chat

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          NGROK SETUP - ONE-TIME CONFIGURATION                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo "❌ Ngrok not found"
    echo "Install with: brew install ngrok"
    exit 1
fi

echo "✅ Ngrok is installed"
echo ""

# Check if already configured
if ngrok config check &> /dev/null; then
    echo "✅ Ngrok is already configured!"
    echo ""
    echo "Starting tunnel..."
    ngrok http 5001
    exit 0
fi

echo "⚠️  Ngrok needs authentication (one-time setup)"
echo ""
echo "📝 STEPS:"
echo ""
echo "1. Open this URL in your browser:"
echo "   👉 https://dashboard.ngrok.com/signup"
echo ""
echo "2. Sign up for FREE account (takes 30 seconds)"
echo ""
echo "3. After signup, copy your authtoken from:"
echo "   👉 https://dashboard.ngrok.com/get-started/your-authtoken"
echo ""
echo "4. Paste your authtoken below and press Enter"
echo ""
echo "────────────────────────────────────────────────────────────────"
read -p "Enter your ngrok authtoken: " AUTHTOKEN

if [ -z "$AUTHTOKEN" ]; then
    echo ""
    echo "❌ No token entered"
    exit 1
fi

echo ""
echo "Configuring ngrok..."
ngrok config add-authtoken "$AUTHTOKEN"

if [ $? -eq 0 ]; then
    echo "✅ Ngrok configured successfully!"
    echo ""
    echo "Starting tunnel..."
    sleep 2
    ngrok http 5001
else
    echo "❌ Configuration failed"
    echo "Please check your authtoken and try again"
    exit 1
fi
