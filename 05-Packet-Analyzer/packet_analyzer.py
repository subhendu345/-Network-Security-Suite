#!/usr/bin/env python3
"""
Advanced Packet Analyzer v1.0
Custom packet sniffer with protocol analysis and threat detection
"""

import scapy.all as scapy
from scapy.layers import http
import socket
import time
import json
import sys
import os
from datetime import datetime
import threading
import collections

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.packet_count = 0
        self.protocol_stats = collections.defaultdict(int)
        self.suspicious_ips = set()
        self.log_file = 'packet_analysis.log'
        self.capture_running = False
        
        # Threat patterns
        self.threat_patterns = [
            b"password", b"login", b"admin", b"root",
            b"SELECT", b"DROP", b"UNION", b"EXEC"
        ]
        
        print("🔄 Initializing Packet Analyzer...")
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        self.packet_count += 1
        self.packets.append(packet)
        
        # Analyze packet
        self.analyze_packet(packet)
        
        # Show progress
        if self.packet_count % 10 == 0:
            print(f"[*] Captured {self.packet_count} packets", end='\r')
    
    def analyze_packet(self, packet):
        """Analyze packet for threats and statistics"""
        try:
            # Get IP layer
            if packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                src_ip = ip.src
                dst_ip = ip.dst
                proto = ip.proto
                
                # Update protocol stats
                proto_name = self.get_protocol_name(proto)
                self.protocol_stats[proto_name] += 1
                
                # Check for suspicious patterns
                self.check_suspicious(packet, src_ip, dst_ip)
                
                # TCP analysis
                if packet.haslayer(scapy.TCP):
                    tcp = packet[scapy.TCP]
                    self.analyze_tcp(packet, src_ip, dst_ip, tcp)
                
                # HTTP analysis
                if packet.haslayer(http.HTTPRequest):
                    self.analyze_http(packet)
                
                # DNS analysis
                if packet.haslayer(scapy.DNS):
                    self.analyze_dns(packet)
                    
        except Exception as e:
            pass
    
    def get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP',
            2: 'IGMP', 50: 'ESP', 51: 'AH'
        }
        return protocols.get(proto_num, f'Proto-{proto_num}')
    
    def check_suspicious(self, packet, src_ip, dst_ip):
        """Check for suspicious patterns in packet payload"""
        try:
            raw = bytes(packet)
            
            # Check for threat patterns
            for pattern in self.threat_patterns:
                if pattern in raw:
                    self.suspicious_ips.add(src_ip)
                    self.log_threat(f"Suspicious pattern found in packet from {src_ip}")
                    break
            
            # Port scanning detection
            if packet.haslayer(scapy.TCP):
                flags = packet[scapy.TCP].flags
                if flags == 0x02:  # SYN flag
                    self.log_threat(f"Potential port scan from {src_ip}")
                    
        except:
            pass
    
    def analyze_tcp(self, packet, src_ip, dst_ip, tcp):
        """Analyze TCP packet"""
        # Check for SYN flood
        if tcp.flags == 0x02:  # SYN
            self.log_threat(f"SYN packet from {src_ip} to {dst_ip}:{tcp.dport}")
        
        # Check for unusual flags
        unusual_flags = [0x01, 0x04, 0x08, 0x10]  # FIN, RST, PUSH, ACK
        for flag in unusual_flags:
            if tcp.flags == flag:
                self.log_threat(f"Unusual TCP flag {flag} from {src_ip}")
    
    def analyze_http(self, packet):
        """Analyze HTTP request"""
        try:
            http_layer = packet[http.HTTPRequest]
            host = http_layer.Host.decode() if http_layer.Host else ''
            path = http_layer.Path.decode() if http_layer.Path else ''
            method = http_layer.Method.decode() if http_layer.Method else ''
            
            # Check for suspicious paths
            suspicious_paths = ['/admin', '/login', '/wp-admin', '/cpanel']
            for sus_path in suspicious_paths:
                if sus_path in path:
                    self.log_threat(f"Suspicious HTTP request to {host}{path}")
                    self.suspicious_ips.add(packet[scapy.IP].src)
            
            print(f"\n🌐 HTTP Request: {method} {host}{path}")
            
        except:
            pass
    
    def analyze_dns(self, packet):
        """Analyze DNS request"""
        try:
            dns = packet[scapy.DNS]
            if dns.qr == 0:  # Query
                qname = dns.qd.qname.decode() if dns.qd else ''
                print(f"\n🔍 DNS Query: {qname}")
                
                # Check for suspicious domains
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.su']
                for tld in suspicious_tlds:
                    if qname.endswith(tld):
                        self.log_threat(f"Suspicious DNS query to {qname}")
        except:
            pass
    
    def log_threat(self, message):
        """Log threat detection"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] ⚠️ {message}"
        
        with open('threats.log', 'a') as f:
            f.write(log_entry + '\n')
        
        print(f"\n⚠️ {message}")
    
    def start_capture(self, interface='eth0', packet_count=100):
        """Start packet capture"""
        print(f"\n📡 Starting capture on {interface}")
        print(f"Capturing {packet_count} packets...")
        
        self.capture_running = True
        try:
            scapy.sniff(
                iface=interface,
                count=packet_count,
                prn=self.packet_callback,
                timeout=60
            )
        except Exception as e:
            print(f"Error capturing: {e}")
            print("Trying with default interface...")
            try:
                scapy.sniff(count=packet_count, prn=self.packet_callback)
            except:
                print("Could not capture packets. Try running with sudo.")
        finally:
            self.capture_running = False
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n📊 PACKET ANALYSIS REPORT")
        print("="*60)
        print(f"Total Packets: {self.packet_count}")
        print(f"Suspicious IPs: {len(self.suspicious_ips)}")
        print("\n📈 Protocol Statistics:")
        
        # Sort by count
        sorted_protos = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)
        for proto, count in sorted_protos:
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            print(f"   {proto:8}: {count:4} packets ({percentage:.1f}%)")
        
        if self.suspicious_ips:
            print("\n⚠️  Suspicious IPs:")
            for ip in self.suspicious_ips:
                print(f"   {ip}")
        
        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'packet_count': self.packet_count,
            'protocols': dict(self.protocol_stats),
            'suspicious_ips': list(self.suspicious_ips)
        }
        
        with open('packet_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Report saved to packet_report.json")
    
    def live_monitor(self):
        """Real-time packet monitoring"""
        print("\n🔴 LIVE PACKET MONITORING")
        print("Press Ctrl+C to stop")
        print("="*60)
        
        try:
            scapy.sniff(prn=self.packet_callback, store=False, timeout=30)
        except KeyboardInterrupt:
            print("\nStopping capture...")
        except:
            pass
    
    def main_menu(self):
        """Interactive menu"""
        while True:
            print("\n" + "="*60)
            print("     📦 PACKET ANALYZER")
            print("="*60)
            print("1. Capture Packets")
            print("2. Live Monitor")
            print("3. Generate Report")
            print("4. View Threats")
            print("5. Analyze PCAP File")
            print("6. Exit")
            print("="*60)
            
            choice = input("Select option (1-6): ")
            
            if choice == "1":
                count = int(input("Number of packets to capture (default 100): ") or 100)
                interface = input("Interface (default: eth0): ") or 'eth0'
                self.start_capture(interface, count)
                self.generate_report()
            
            elif choice == "2":
                self.live_monitor()
            
            elif choice == "3":
                self.generate_report()
            
            elif choice == "4":
                self.view_threats()
            
            elif choice == "5":
                self.analyze_pcap()
            
            elif choice == "6":
                print("Exiting...")
                break
            
            input("\nPress Enter to continue...")
    
    def view_threats(self):
        """View detected threats"""
        try:
            with open('threats.log', 'r') as f:
                threats = f.readlines()
            
            print("\n📋 DETECTED THREATS")
            print("="*60)
            for threat in threats[-20:]:  # Last 20 threats
                print(threat.strip())
        except:
            print("No threats detected yet")
    
    def analyze_pcap(self):
        """Analyze existing PCAP file"""
        filename = input("Enter PCAP filename: ")
        
        try:
            packets = scapy.rdpcap(filename)
            print(f"📡 Analyzing {len(packets)} packets...")
            
            for packet in packets:
                self.analyze_packet(packet)
            
            self.generate_report()
        except:
            print("Error analyzing PCAP")

if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    
    if os.geteuid() != 0:
        print("⚠️  Some features require root privileges!")
        print("Run with: sudo python3 packet_analyzer.py")
    
    analyzer.main_menu()
