#!/bin/bash
# ======================================
# Auto Network Scanner v1.0
# Complete network automation script
# ======================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="logs"
REPORT_DIR="reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create directories
mkdir -p $LOG_DIR $REPORT_DIR

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    🚀 AUTO NETWORK SCANNER v1.0${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to log messages
log_message() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_DIR/network_scan.log"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "${YELLOW}Warning: Not running as root${NC}"
        log_message "Some scans may have limited functionality"
    fi
}

# Function to detect network interface
detect_interface() {
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z $INTERFACE ]]; then
        INTERFACE="eth0"
    fi
    log_message "Using interface: $INTERFACE"
}

# Function to get local IP
get_local_ip() {
    LOCAL_IP=$(ip -4 addr show $INTERFACE | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1)
    echo $LOCAL_IP
}

# Function to get network range
get_network_range() {
    IP=$(get_local_ip)
    if [[ -z $IP ]]; then
        echo "192.168.1.0/24"
        return
    fi
    
    # Extract network
    NETWORK=$(echo $IP | cut -d. -f1-3)
    echo "${NETWORK}.0/24"
}

# Function to scan network
scan_network() {
    log_message "${BLUE}Starting network scan...${NC}"
    
    NETWORK=$(get_network_range)
    log_message "Scanning network: $NETWORK"
    
    # NMAP scan
    nmap -sn $NETWORK > "$REPORT_DIR/nmap_scan_$TIMESTAMP.txt"
    
    # Get active hosts
    ACTIVE_HOSTS=$(grep "Nmap scan report" "$REPORT_DIR/nmap_scan_$TIMESTAMP.txt" | awk '{print $5}')
    
    echo -e "\n${GREEN}Active Hosts:${NC}"
    for host in $ACTIVE_HOSTS; do
        echo "  ✅ $host"
    done
    
    # Save active hosts
    echo "$ACTIVE_HOSTS" > "$REPORT_DIR/active_hosts_$TIMESTAMP.txt"
    log_message "Scan completed. Found $(echo "$ACTIVE_HOSTS" | wc -l) active hosts"
}

# Function to scan ports
scan_ports() {
    log_message "${BLUE}Starting port scan...${NC}"
    
    TARGET=${1:-$(get_local_ip)}
    
    # Common ports
    PORTS="22,80,443,3306,5432,8080,8443"
    
    log_message "Scanning $TARGET for ports: $PORTS"
    
    nmap -p $PORTS -sV $TARGET > "$REPORT_DIR/port_scan_$TIMESTAMP.txt"
    
    echo -e "\n${GREEN}Open ports on $TARGET:${NC}"
    grep "open" "$REPORT_DIR/port_scan_$TIMESTAMP.txt" | while read line; do
        echo "  🔓 $line"
    done
}

# Function to check security
check_security() {
    log_message "${BLUE}Checking security...${NC}"
    
    SECURITY_REPORT="$REPORT_DIR/security_check_$TIMESTAMP.txt"
    
    {
        echo "Security Check Report - $(date)"
        echo "=================================="
        
        # Check for open ports
        echo -e "\n🔓 Open Ports:"
        netstat -tulpn | grep LISTEN || echo "No listening ports found"
        
        # Check firewall status
        echo -e "\n🛡️ Firewall Status:"
        ufw status || iptables -L -n | head -10
        
        # Check SSH configuration
        echo -e "\n🔑 SSH Configuration:"
        grep -E "PermitRootLogin|PasswordAuthentication|Port" /etc/ssh/sshd_config 2>/dev/null || echo "Cannot access SSH config"
        
        # Check for suspicious processes
        echo -e "\n⚠️ Suspicious Processes:"
        ps aux | grep -E "nc|nmap|hydra|john|sqlmap" | grep -v grep || echo "None found"
        
        # Check failed login attempts
        echo -e "\n🚫 Failed Login Attempts (last 10):"
        lastb | head -10 || echo "Cannot access lastb"
        
    } > $SECURITY_REPORT
    
    log_message "Security check completed: $SECURITY_REPORT"
    cat $SECURITY_REPORT
}

# Function to monitor network
monitor_network() {
    log_message "${BLUE}Starting network monitoring...${NC}"
    
    MONITOR_REPORT="$REPORT_DIR/network_monitor_$TIMESTAMP.txt"
    
    {
        echo "Network Monitoring Report - $(date)"
        echo "===================================="
        
        # Network statistics
        echo -e "\n📊 Network Statistics:"
        ifconfig $INTERFACE | grep -E "RX|TX"
        
        # Active connections
        echo -e "\n🌐 Active Connections:"
        ss -tunp | head -20
        
        # Bandwidth usage
        echo -e "\n📶 Bandwidth Usage:"
        ifstat -i $INTERFACE 1 2 2>/dev/null || echo "ifstat not installed"
        
        # DNS queries
        echo -e "\n🔍 DNS Queries (last 20):"
        dig google.com +short || echo "Cannot check DNS"
        
    } > $MONITOR_REPORT
    
    log_message "Monitoring completed: $MONITOR_REPORT"
}

# Function to check system health
system_health() {
    log_message "${BLUE}Checking system health...${NC}"
    
    HEALTH_REPORT="$REPORT_DIR/system_health_$TIMESTAMP.txt"
    
    {
        echo "System Health Report - $(date)"
        echo "================================"
        
        # CPU usage
        echo -e "\n💻 CPU Usage:"
        top -bn1 | head -5
        
        # Memory usage
        echo -e "\n🧠 Memory Usage:"
        free -h
        
        # Disk usage
        echo -e "\n💾 Disk Usage:"
        df -h
        
        # System load
        echo -e "\n📊 System Load:"
        uptime
        
        # Running services
        echo -e "\n⚙️ Running Services:"
        systemctl list-units --type=service --state=running | head -10
        
    } > $HEALTH_REPORT
    
    log_message "System health check completed"
}

# Function to detect attacks
detect_attacks() {
    log_message "${BLUE}🔍 Detecting attacks...${NC}"
    
    ATTACK_REPORT="$REPORT_DIR/attack_detection_$TIMESTAMP.txt"
    
    {
        echo "Attack Detection Report - $(date)"
        echo "=================================="
        
        # Check for SSH brute force
        echo -e "\n🔒 SSH Brute Force Attempts:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || echo "Cannot access auth.log"
        
        # Check for port scanning
        echo -e "\n📡 Port Scanning Attempts:"
        grep "Nmap" /var/log/auth.log 2>/dev/null | tail -10 || echo "No port scans detected"
        
        # Check for DoS attempts
        echo -e "\n🚫 DoS Attempts:"
        netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
        
        # Check for suspicious connections
        echo -e "\n🌐 Suspicious Connections:"
        netstat -tunap | grep -E "ESTABLISHED|SYN" | head -10
        
    } > $ATTACK_REPORT
    
    log_message "Attack detection completed: $ATTACK_REPORT"
}

# Function to generate final report
generate_full_report() {
    log_message "${BLUE}Generating complete report...${NC}"
    
    FINAL_REPORT="$REPORT_DIR/full_report_$TIMESTAMP.html"
    
    {
        echo "<!DOCTYPE html>"
        echo "<html>"
        echo "<head><title>Network Scan Report</title>"
        echo "<style>body{font-family:Arial;margin:40px;background:#f0f4f8;} h1{color:#2c3e50;} .section{background:white;padding:20px;margin:20px 0;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);} .badge{display:inline-block;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:bold;} .success{background:#27ae60;color:white;} .warning{background:#f39c12;color:white;} .danger{background:#e74c3c;color:white;}</style>"
        echo "</head><body>"
        echo "<h1>📊 Network Scan Report</h1>"
        echo "<p><strong>Generated:</strong> $(date)</p>"
        echo "<p><strong>Host:</strong> $(hostname)</p>"
        
        # Add sections
        echo "<div class='section'><h2>Network Information</h2>"
        echo "<pre>$(ifconfig $INTERFACE 2>/dev/null || ip addr show)</pre></div>"
        
        echo "<div class='section'><h2>Active Hosts</h2>"
        echo "<pre>$(cat $REPORT_DIR/active_hosts_$TIMESTAMP.txt 2>/dev/null || echo 'No hosts found')</pre></div>"
        
        echo "<div class='section'><h2>System Health</h2>"
        echo "<pre>$(cat $REPORT_DIR/system_health_$TIMESTAMP.txt 2>/dev/null | head -30)</pre></div>"
        
        echo "</body></html>"
    } > $FINAL_REPORT
    
    log_message "Complete report generated: $FINAL_REPORT"
}

# Function to setup automated monitoring
setup_auto_monitor() {
    log_message "${BLUE}Setting up automated monitoring...${NC}"
    
    # Create cron job
    CRON_SCRIPT="$HOME/auto_monitor.sh"
    
    cat > $CRON_SCRIPT << 'EOF'
#!/bin/bash
cd ~/Network-Security-Suite/scripts
./auto_network_scan.sh
EOF
    
    chmod +x $CRON_SCRIPT
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 */6 * * * $CRON_SCRIPT") | crontab -
    
    log_message "Automated monitoring configured (runs every 6 hours)"
}

# Function to fix common issues
fix_issues() {
    log_message "${BLUE}🔧 Fixing common issues...${NC}"
    
    echo -e "\n${GREEN}Fixing Issues:${NC}"
    
    # Fix 1: Check permissions
    echo "1. Checking permissions..."
    chmod +x *.sh
    
    # Fix 2: Check dependencies
    echo "2. Checking dependencies..."
    for cmd in nmap netstat ifconfig; do
        if ! command -v $cmd &> /dev/null; then
            echo "   Installing $cmd..."
            sudo apt-get install -y $cmd 2>/dev/null || echo "   Could not install $cmd"
        fi
    done
    
    # Fix 3: Check Python packages
    echo "3. Checking Python packages..."
    python3 -c "import scapy" 2>/dev/null || sudo pip3 install scapy
    
    # Fix 4: Create logs
    echo "4. Creating log directories..."
    mkdir -p /var/log/network-suite
    
    # Fix 5: Check firewall
    echo "5. Checking firewall..."
    sudo ufw status 2>/dev/null || echo "UFW not installed"
    
    log_message "Issues fixed successfully"
}

# Main menu
main_menu() {
    echo -e "\n${YELLOW}Select an option:${NC}"
    echo "1. Full Network Scan"
    echo "2. Port Scan"
    echo "3. Security Check"
    echo "4. Network Monitor"
    echo "5. System Health"
    echo "6. Detect Attacks"
    echo "7. Generate Report"
    echo "8. Setup Auto Monitor"
    echo "9. Fix Issues"
    echo "10. Run All"
    echo "0. Exit"
    echo -n "Choice: "
    read choice
    
    case $choice in
        1) scan_network ;;
        2) scan_ports ;;
        3) check_security ;;
        4) monitor_network ;;
        5) system_health ;;
        6) detect_attacks ;;
        7) generate_full_report ;;
        8) setup_auto_monitor ;;
        9) fix_issues ;;
        10) run_all ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
}

# Run all scans
run_all() {
    log_message "${BLUE}Running complete suite...${NC}"
    scan_network
    scan_ports "$(get_local_ip)"
    check_security
    monitor_network
    system_health
    detect_attacks
    generate_full_report
    log_message "${GREEN}All scans completed!${NC}"
}

# Main execution
main() {
    check_root
    detect_interface
    
    while true; do
        main_menu
        echo -e "\nPress Enter to continue..."
        read
    done
}

# Start script
main
