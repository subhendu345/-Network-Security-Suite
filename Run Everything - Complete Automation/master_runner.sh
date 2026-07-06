#!/bin/bash
# ======================================
# Master Script - Run Everything
# ======================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    🚀 NETWORK SECURITY SUITE${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to run with highlight
run_with_highlight() {
    echo -e "${GREEN}▶ Running: $1${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    eval "$2"
    echo -e "${YELLOW}----------------------------------------${NC}"
    echo -e "${GREEN}✅ Completed: $1${NC}\n"
}

# Run all scripts
run_with_highlight "Network Monitor" "cd 01-Network-Monitor && sudo python3 network_monitor.py"
run_with_highlight "Honeypot" "cd 02-Honeypot-Setup && sudo python3 honeypot.py"
run_with_highlight "Firewall Manager" "cd 03-Firewall-Manager && sudo python3 firewall_manager.py"
run_with_highlight "IP Intelligence" "cd 04-IP-Intelligence && python3 ip_intelligence.py"
run_with_highlight "Packet Analyzer" "cd 05-Packet-Analyzer && sudo python3 packet_analyzer.py"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✅ All scripts completed!${NC}"
echo -e "${BLUE}========================================${NC}"
