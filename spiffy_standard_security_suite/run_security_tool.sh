#!/bin/bash

echo "Starting Spiffy Security Tool with enhanced security modules..."
echo ""

source ../venv/bin/activate

python main_security_tool.py


cd spiffy_ultron_zero_v22 && ./run_omega.sh