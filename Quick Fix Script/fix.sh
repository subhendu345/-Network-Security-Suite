#!/bin/bash
echo "🛠️ Quick Fix All Issues"

# Fix permissions
find . -name "*.py" -exec chmod +x {} \;
find . -name "*.sh" -exec chmod +x {} \;

# Install dependencies
pip3 install -r requirements.txt

# Fix line endings
find . -name "*.sh" -exec dos2unix {} \;

echo "✅ Fixed all issues!"


---

## 📦 Requirements File

### `requirements.txt`

scapy>=2.4.5
python-nmap>=0.7.1
psutil>=5.9.0
requests>=2.28.0
dnspython>=2.2.1
whois>=0.8.0
colorama>=0.4.6
tabulate>=0.9.0


---

## 🚀 Quick Start

### Step 1: Clone and Set Up
```bash
# Clone or create a directory
mkdir Network-Security-Suite
cd Network-Security-Suite

# Make scripts executable
chmod +x scripts/*.sh

# Run setup
./scripts/setup.sh

### Step 2: Run Individual Projects
# Network Monitor
cd 01-Network-Monitor
sudo python3 network_monitor.py

# Honeypot
cd 02-Honeypot-Setup
sudo python3 honeypot.py

# Firewall Manager
cd 03-Firewall-Manager
sudo python3 firewall_manager.py

# IP Intelligence
cd 04-IP-Intelligence
python3 ip_intelligence.py

# Packet Analyzer
cd 05-Packet-Analyzer
sudo python3 packet_analyzer.py
### Step 3: Run Automation
# Run all automation scripts
cd scripts
./auto_network_scan.sh

# Fix common issues
./fix_common_issues.sh
