#!/bin/bash
# Activation script for Spiffy virtual environment

echo "Activating Spiffy virtual environment..."
source venv/bin/activate

echo "✓ Virtual environment activated!"
echo ""
echo "Available Python modules:"
echo "  - cryptography (AES-GCM encryption)"
echo "  - pyotp (2FA/TOTP support)"
echo "  - qrcode (QR code generation)"
echo "  - Pillow (Image processing)"
echo "  - asyncio-dgram (Async networking)"
echo ""
echo "To run the applications:"
echo "  - Spiffy Chat: python spiffy/spiffy_x.py"
echo "  - Ultron Zero: python spiffy_ultron_zero_v22/spiffy.py"
echo "  - Security Suite: python spiffy_standard_security_suite/main_security_tool.py"
echo ""
echo "To deactivate: deactivate"
