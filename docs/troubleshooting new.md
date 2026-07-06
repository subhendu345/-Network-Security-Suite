## Issue 2: ModuleNotFoundError
Error: ModuleNotFoundError: No module named 'scapy'

** Solution **:
sudo pip3 install scapy python-nmap psutil requests

## Issue 3: Interface Not Found
Error: No such device: eth0

** Solution **:
## 1. Find your interface:
ip addr show
ifconfig
## 2. Update scripts with correct interface name

### Issue 4: Port Already in Use
Error: Address already in use for honeypot

** Solution **:
# Find process using port
sudo lsof -i :2222

# Kill process
sudo kill -9 PID

### Issue 5: Script Not Running
** Solution ** :
# Check file permissions
ls -la *.sh

# Fix line endings
sudo apt-get install dos2unix
dos2unix scripts/*.sh

### Issue 6: Dependency Issues
** Solution **:
# Install all dependencies
pip3 install -r requirements.txt

# Or install individually
pip3 install scapy python-nmap psutil requests

## Issue 7: No Internet Connection
** Solution **:
Check network: ping -c 4 google.com
### Issue 8: Python Version Issues
# Check Python version
python3 --version

# Should be 3.6+

