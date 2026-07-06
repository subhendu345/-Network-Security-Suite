# 1. Fix Permissions
chmod +x scripts/*.sh
sudo chmod +x 01-Network-Monitor/*.py
sudo chmod +x 02-Honeypot-Setup/*.py
sudo chmod +x 03-Firewall-Manager/*.py
sudo chmod +x 04-IP-Intelligence/*.py
sudo chmod +x 05-Packet-Analyzer/*.py

# 2. Install Dependencies
pip3 install -r requirements.txt

# 3. Run Setup
./scripts/setup.sh

# 4. Verify Setup
./scripts/verify_setup.sh

# 5. Run Individual Projects
cd 01-Network-Monitor && sudo python3 network_monitor.py
cd 02-Honeypot-Setup && sudo python3 honeypot.py
cd 03-Firewall-Manager && sudo python3 firewall_manager.py
cd 04-IP-Intelligence && python3 ip_intelligence.py
cd 05-Packet-Analyzer && sudo python3 packet_analyzer.py

# 6. Run Auto Scanner
cd scripts && ./auto_network_scan.sh

# 7. Run Everything
./master_runner.sh
