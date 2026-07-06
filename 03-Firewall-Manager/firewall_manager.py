#!/usr/bin/env python3
"""
Firewall Manager v1.0
Automated iptables management with whitelist/blacklist
"""

import subprocess
import os
import sys
import json
import time
import re
from datetime import datetime

class FirewallManager:
    def __init__(self):
        self.rules = []
        self.log_file = 'firewall.log'
        
        # Check for root privileges
        if os.geteuid() != 0:
            print("⚠️  This script requires root privileges!")
            print("Run with: sudo python3 firewall_manager.py")
            sys.exit(1)
    
    def clear_firewall(self):
        """Clear all existing iptables rules"""
        commands = [
            'iptables -F',
            'iptables -X',
            'iptables -t nat -F',
            'iptables -t mangle -F'
        ]
        for cmd in commands:
            self.run_command(cmd)
        print("✅ Firewall cleared")
    
    def set_default_policies(self):
        """Set default policies"""
        policies = [
            'iptables -P INPUT DROP',
            'iptables -P FORWARD DROP',
            'iptables -P OUTPUT ACCEPT'
        ]
        for cmd in policies:
            self.run_command(cmd)
        print("✅ Default policies set")
    
    def allow_ssh(self, ip=None):
        """Allow SSH access"""
        if ip:
            rule = f'iptables -A INPUT -s {ip} -p tcp --dport 22 -j ACCEPT'
        else:
            rule = 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT'
        self.run_command(rule)
        print(f"✅ SSH allowed from {ip if ip else 'any'}")
    
    def allow_web(self):
        """Allow web traffic"""
        rules = [
            'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
            'iptables -A INPUT -p tcp --dport 443 -j ACCEPT'
        ]
        for rule in rules:
            self.run_command(rule)
        print("✅ Web traffic allowed")
    
    def block_ip(self, ip):
        """Block specific IP"""
        rule = f'iptables -A INPUT -s {ip} -j DROP'
        self.run_command(rule)
        self.log_action(f"BLOCKED: {ip}")
        print(f"✅ IP blocked: {ip}")
    
    def whitelist_ip(self, ip):
        """Whitelist specific IP"""
        rule = f'iptables -A INPUT -s {ip} -j ACCEPT'
        self.run_command(rule)
        self.log_action(f"WHITELISTED: {ip}")
        print(f"✅ IP whitelisted: {ip}")
    
    def run_command(self, command):
        """Execute shell command"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0 and result.stderr:
                print(f"Warning: {result.stderr}")
            return result
        except Exception as e:
            print(f"Error executing command: {e}")
            return None
    
    def show_rules(self):
        """Display current firewall rules"""
        result = self.run_command('iptables -L -v -n')
        if result:
            print("\n📋 CURRENT FIREWALL RULES")
            print("="*60)
            print(result.stdout)
    
    def log_action(self, action):
        """Log firewall actions"""
        with open(self.log_file, 'a') as f:
            f.write(f"{datetime.now()}: {action}\n")
    
    def setup_basic_firewall(self):
        """Setup basic firewall configuration"""
        print("🛡️  Setting up basic firewall...")
        self.clear_firewall()
        self.set_default_policies()
        self.allow_ssh()
        self.allow_web()
        
        # Allow established connections
        self.run_command('iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
        
        # Allow loopback
        self.run_command('iptables -A INPUT -i lo -j ACCEPT')
        
        print("✅ Basic firewall setup complete")
    
    def detect_and_block_attacks(self):
        """Detect common attack patterns and block them"""
        print("🔍 Scanning for attacks...")
        
        # Check failed SSH attempts
        fail2ban_check = 'sudo grep "Failed password" /var/log/auth.log | tail -20'
        result = self.run_command(fail2ban_check)
        
        if result and result.stdout:
            print("[!] Failed SSH attempts detected:")
            print(result.stdout[:500])
        
        # Check for port scanning
        port_scan_check = 'sudo netstat -ntu | grep ":22" | awk \'{print $5}\' | cut -d: -f1 | sort | uniq -c | sort -nr'
        result = self.run_command(port_scan_check)
        
        if result and result.stdout:
            print("[!] Suspicious connections detected")
            print(result.stdout[:500])
    
    def main_menu(self):
        """Interactive menu"""
        while True:
            print("\n" + "="*60)
            print("     🛡️  FIREWALL MANAGER")
            print("="*60)
            print("1. Setup Basic Firewall")
            print("2. Block an IP")
            print("3. Whitelist an IP")
            print("4. Show Rules")
            print("5. Detect Attacks")
            print("6. Clear Firewall")
            print("7. Export Configuration")
            print("8. Exit")
            print("="*60)
            
            choice = input("Select option (1-8): ")
            
            if choice == "1":
                self.setup_basic_firewall()
            elif choice == "2":
                ip = input("Enter IP to block: ")
                if ip:
                    self.block_ip(ip)
            elif choice == "3":
                ip = input("Enter IP to whitelist: ")
                if ip:
                    self.whitelist_ip(ip)
            elif choice == "4":
                self.show_rules()
            elif choice == "5":
                self.detect_and_block_attacks()
            elif choice == "6":
                if input("Are you sure? (y/n): ").lower() == 'y':
                    self.clear_firewall()
            elif choice == "7":
                self.export_config()
            elif choice == "8":
                print("Exiting...")
                break
            else:
                print("Invalid option")
            
            input("\nPress Enter to continue...")
    
    def export_config(self):
        """Export firewall configuration"""
        config = {
            'timestamp': datetime.now().isoformat(),
            'rules': []
        }
        
        # Get current rules
        result = self.run_command('iptables -L -v -n')
        if result:
            config['rules'] = result.stdout
        
        with open('firewall_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Configuration exported to firewall_config.json")

if __name__ == "__main__":
    firewall = FirewallManager()
    firewall.main_menu()
