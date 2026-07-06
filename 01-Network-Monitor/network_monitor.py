#!/usr/bin/env python3
"""
Advanced Network Monitor v2.0
Features: Real-time monitoring, device discovery, bandwidth tracking
"""

import subprocess
import platform
import threading
import time
import json
import socket
import psutil
import nmap
import scapy.all as scapy
from datetime import datetime
import requests
import sys
import os

class NetworkMonitor:
    def __init__(self):
        self.system = platform.system()
        self.hosts = {}
        self.packet_count = 0
        self.alert_threshold = 100  # packets per second
        self.running = True
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def scan_network(self, network_cidr="192.168.1.0/24"):
        """Scan network for active devices"""
        print(f"[+] Scanning network: {network_cidr}")
        nm = nmap.PortScanner()
        
        try:
            nm.scan(hosts=network_cidr, arguments='-sn -v')
            active_hosts = []
            
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': nm[host].hostname() or 'Unknown',
                        'mac': nm[host]['addresses'].get('mac', 'N/A'),
                        'vendor': nm[host]['addresses'].get('vendor', 'N/A')
                    }
                    active_hosts.append(host_info)
                    self.hosts[host] = host_info
            
            return active_hosts
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []
    
    def monitor_packets(self, interface="eth0", count=100):
        """Capture and analyze network packets"""
        print(f"[+] Capturing {count} packets on {interface}")
        
        def packet_handler(packet):
            self.packet_count += 1
            if self.packet_count % 10 == 0:
                print(f"[*] Packets captured: {self.packet_count}")
                
            # Analyze packet
            try:
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    proto = packet[scapy.IP].proto
                    
                    # Check for suspicious patterns
                    if self.packet_count > self.alert_threshold:
                        self.trigger_alert(f"High packet rate: {self.packet_count}/sec")
                        
            except Exception as e:
                pass
        
        try:
            scapy.sniff(iface=interface, count=count, prn=packet_handler)
        except Exception as e:
            print(f"Packet capture error: {e}")
            print("Trying alternative capture method...")
            self.monitor_with_psutil()
    
    def monitor_with_psutil(self):
        """Monitor network using psutil (fallback method)"""
        print("[+] Monitoring network statistics...")
        old_stats = psutil.net_io_counters()
        
        while self.running:
            time.sleep(2)
            new_stats = psutil.net_io_counters()
            
            bytes_sent = new_stats.bytes_sent - old_stats.bytes_sent
            bytes_recv = new_stats.bytes_recv - old_stats.bytes_recv
            packets_sent = new_stats.packets_sent - old_stats.packets_sent
            packets_recv = new_stats.packets_recv - old_stats.packets_recv
            
            self.display_stats(bytes_sent, bytes_recv, packets_sent, packets_recv)
            
            old_stats = new_stats
    
    def display_stats(self, sent, recv, psent, precv):
        """Display network statistics"""
        self.clear_screen()
        print("="*60)
        print("     🌐 NETWORK MONITOR - LIVE STATISTICS")
        print("="*60)
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📶 Active Hosts: {len(self.hosts)}")
        print("-"*60)
        print(f"📤 Bytes Sent: {self.format_bytes(sent)}")
        print(f"📥 Bytes Received: {self.format_bytes(recv)}")
        print(f"📦 Packets Sent: {psent}")
        print(f"📦 Packets Received: {precv}")
        print("-"*60)
        
        # Display active hosts
        if self.hosts:
            print("🖥️  Active Devices:")
            for ip, info in list(self.hosts.items())[:10]:
                print(f"   ├─ {ip} ({info.get('hostname', 'Unknown')})")
        
        print("="*60)
    
    def format_bytes(self, bytes_count):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} TB"
    
    def trigger_alert(self, message):
        """Trigger security alerts"""
        print(f"⚠️  ALERT: {message}")
        # Send to log file
        with open('network_alerts.log', 'a') as f:
            f.write(f"{datetime.now()}: {message}\n")
        
        # Optional: Send email alert
        # self.send_email_alert(message)
    
    def check_port_scan(self, target_ip="127.0.0.1", ports=[22, 80, 443]):
        """Check for open ports"""
        print(f"[+] Checking open ports on {target_ip}")
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        return open_ports
    
    def main_menu(self):
        """Main interactive menu"""
        self.clear_screen()
        print("="*60)
        print("     🌐 ADVANCED NETWORK MONITOR")
        print("="*60)
        print("1. Scan Network for Devices")
        print("2. Real-time Packet Monitor")
        print("3. Check Open Ports")
        print("4. Bandwidth Monitor")
        print("5. Export Reports")
        print("6. Exit")
        print("="*60)
        
        choice = input("Select option (1-6): ")
        
        if choice == "1":
            self.scan_network()
            input("\nPress Enter to continue...")
        elif choice == "2":
            self.monitor_packets(count=50)
            input("\nPress Enter to continue...")
        elif choice == "3":
            ip = input("Enter target IP (default: localhost): ") or "127.0.0.1"
            ports = input("Enter ports (comma-separated, default: 22,80,443): ")
            if ports:
                ports = [int(p.strip()) for p in ports.split(',')]
            else:
                ports = [22, 80, 443]
            open_ports = self.check_port_scan(ip, ports)
            print(f"\n✅ Open Ports: {open_ports}")
            input("\nPress Enter to continue...")
        elif choice == "4":
            self.monitor_with_psutil()
        elif choice == "5":
            self.export_report()
        elif choice == "6":
            self.running = False
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid option!")
            time.sleep(1)
    
    def export_report(self):
        """Export network report to file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hosts': self.hosts,
            'packet_count': self.packet_count,
            'active_connections': len(self.hosts)
        }
        
        with open('network_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✅ Report exported to network_report.json")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("⚠️  Some features require root privileges!")
        print("Run with: sudo python3 network_monitor.py")
    
    while True:
        monitor.main_menu()
