#!/bin/bash
# Build script for Spiffy Private Chat
# MIT Licensed - Free to use and modify

echo "🔨 Building Spiffy Private Chat..."
echo ""

# Check Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Install from: https://rustup.rs"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

# Build Rust crypto module (90% of logic)
echo "📦 Building Rust crypto module..."
cd rust_private_chat
maturin develop --release
if [ $? -ne 0 ]; then
    echo "❌ Rust build failed"
    exit 1
fi
cd ..

echo "✅ Rust crypto module built"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install PyQt6 flask flask-socketio python-socketio --break-system-packages 2>/dev/null || \
pip3 install PyQt6 flask flask-socketio python-socketio

echo ""
echo "✅ Build complete!"
echo ""
echo "🚀 To run:"
echo "   python3 private_chat_gui.py"
echo ""
