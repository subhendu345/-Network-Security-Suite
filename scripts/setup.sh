#!/bin/bash
# ======================================
# Complete Setup Script for Network Suite
# ======================================

echo "🚀 Setting up Network Security Suite..."

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
echo "📦 Installing system dependencies..."

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    
    # Install Python packages
    sudo apt-get install -y python3-pip python3-dev
    
    # Install network tools
    sudo apt-get install -y nmap net-tools whois dnsutils
    
    # Install additional tools
    sudo apt-get install -y htop iotop iftop tcpdump
    
    # Install Python packages
    sudo pip3 install -r requirements.txt
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # MacOS
    brew install python3 nmap net-tools whois
    pip3 install -r requirements.txt
else
    echo "Unsupported OS"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs reports

# Set permissions
echo "🔒 Setting permissions..."
chmod +x scripts/*.sh
chmod +x 01-Network-Monitor/*.py
chmod +x 02-Honeypot-Setup/*.py
chmod +x 03-Firewall-Manager/*.py
chmod +x 04-IP-Intelligence/*.py
chmod +x 05-Packet-Analyzer/*.py

# Check Python packages
echo "🐍 Installing Python packages..."
python3 -c "import scapy" 2>/dev/null || sudo pip3 install scapy
python3 -c "import nmap" 2>/dev/null || sudo pip3 install python-nmap
python3 -c "import psutil" 2>/dev/null || sudo pip3 install psutil

echo -e "${GREEN}✅ Setup complete!${NC}"
echo "Run: cd scripts && ./auto_network_scan.sh"
