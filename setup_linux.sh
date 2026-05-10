#!/bin/bash
# Setup script for Linux

echo "========================================"
echo "Network Security Scanner - Linux Setup"
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed!"
    echo "Install it with: sudo apt install python3 python3-pip"
    exit 1
fi

echo "Python version: $(python3 --version)"
echo ""

# Install dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install system dependencies (for network tools)
if command -v apt-get &> /dev/null; then
    echo ""
    echo "Installing system dependencies (ping, arp, ip)..."
    sudo apt-get update
    sudo apt-get install -y iputils-ping net-tools iproute2
elif command -v yum &> /dev/null; then
    echo ""
    echo "Installing system dependencies..."
    sudo yum install -y iputils net-tools iproute
elif command -v pacman &> /dev/null; then
    echo ""
    echo "Installing system dependencies..."
    sudo pacman -S --noconfirm iputils net-tools iproute2
fi

echo ""
echo "========================================"
echo "Setup complete!"
echo ""
echo "Run the application with:"
echo "  python3 main.py"
echo "========================================"

