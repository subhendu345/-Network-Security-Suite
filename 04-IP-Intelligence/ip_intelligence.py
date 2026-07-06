#!/usr/bin/env python3
"""
IP Intelligence v1.0
Comprehensive IP reputation, geolocation, and threat analysis
"""

import requests
import socket
import json
import time
import sys
import re
from datetime import datetime
import dns.resolver
import whois
import subprocess

class IPIntelligence:
    def __init__(self):
        self.known_threats = []
        self.cache = {}
        self.api_keys = {
            'abuseipdb': '',  # Get free key from abuseipdb.com
            'virustotal': ''  # Get free key from virustotal.com
        }
        
        # Load local threat database
        self.load_threats()
    
    def load_threats(self):
        """Load known malicious IPs"""
        # Example threat patterns
        self.threat_patterns = [
            r'^10\.\d+\.\d+\.\d+$',  # Private
            r'^192\.168\.\d+\.\d+$',  # Private
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$'  # Private
        ]
    
    def get_ip_info(self, ip):
        """Get comprehensive IP information"""
        print(f"\n🔍 Analyzing IP: {ip}")
        print("="*60)
        
        info = {
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check cache first
        if ip in self.cache:
            print("📦 Using cached data")
            return self.cache[ip]
        
        # Get location
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                info['location'] = {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'timezone': data.get('timezone')
                }
        except:
            info['location'] = {'error': 'Could not fetch location'}
        
        # Check with AbuseIPDB
        info['reputation'] = self.check_abuseipdb(ip)
        
        # Check with VirusTotal
        info['virustotal'] = self.check_virustotal(ip)
        
        # DNS check
        info['dns_info'] = self.get_dns_info(ip)
        
        # WHOIS
        info['whois'] = self.get_whois(ip)
        
        # Port scan (basic)
        info['open_ports'] = self.basic_port_scan(ip)
        
        # Determine threat level
        info['threat_level'] = self.calculate_threat_level(info)
        
        # Cache the result
        self.cache[ip] = info
        
        return info
    
    def check_abuseipdb(self, ip):
        """Check IP reputation using AbuseIPDB"""
        print("📡 Checking AbuseIPDB...")
        
        try:
            # Using public API (no key needed for basic)
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                headers={
                    'Accept': 'application/json',
                    'Key': self.api_keys.get('abuseipdb', '')
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return {
                        'score': data['data'].get('abuseConfidenceScore', 0),
                        'reports': data['data'].get('totalReports', 0),
                        'last_reported': data['data'].get('lastReportedAt', ''),
                        'categories': data['data'].get('categories', [])
                    }
        except Exception as e:
            return {'error': str(e)}
        
        return {'error': 'Could not check reputation'}
    
    def check_virustotal(self, ip):
        """Check IP with VirusTotal"""
        print("📡 Checking VirusTotal...")
        
        try:
            # Public check (no key required for some info)
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': self.api_keys.get('virustotal', '')},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'attributes' in data['data']:
                    attrs = data['data']['attributes']
                    return {
                        'reputation': attrs.get('reputation', 0),
                        'country': attrs.get('country', ''),
                        'as_owner': attrs.get('as_owner', '')
                    }
        except:
            pass
        
        return {'error': 'Could not check'}
    
    def get_dns_info(self, ip):
        """Get DNS information"""
        print("📡 Checking DNS...")
        
        dns_info = {}
        
        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0]
            dns_info['hostname'] = hostname
        except:
            dns_info['hostname'] = 'No reverse DNS'
        
        try:
            # Check DNSBL (spam blacklists)
            reversed_ip = '.'.join(reversed(ip.split('.')))
            blacklists = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net'
            ]
            
            dns_info['blacklist_status'] = []
            for bl in blacklists:
                try:
                    query = f"{reversed_ip}.{bl}"
                    dns.resolver.resolve(query, 'A')
                    dns_info['blacklist_status'].append(f'{bl}: LISTED')
                except:
                    dns_info['blacklist_status'].append(f'{bl}: CLEAN')
        except:
            dns_info['blacklist_status'] = ['Error checking blacklists']
        
        return dns_info
    
    def get_whois(self, ip):
        """Get WHOIS information"""
        print("📡 Checking WHOIS...")
        
        try:
            return whois.whois(ip)
        except:
            return {'error': 'Could not get WHOIS'}
    
    def basic_port_scan(self, ip, ports=[22, 80, 443, 8080, 3306, 5432]):
        """Scan common ports"""
        print("📡 Scanning common ports...")
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def calculate_threat_level(self, info):
        """Calculate threat level based on collected data"""
        threat_score = 0
        
        # Check reputation
        if 'reputation' in info and 'score' in info['reputation']:
            threat_score += info['reputation']['score'] / 10
        
        # Check blacklists
        if 'dns_info' in info and 'blacklist_status' in info['dns_info']:
            listed = len([bl for bl in info['dns_info']['blacklist_status'] if 'LISTED' in bl])
            threat_score += listed * 10
        
        # Check open ports
        if 'open_ports' in info:
            if 22 in info['open_ports']:  # SSH
                threat_score += 10
            if 3306 in info['open_ports']:  # MySQL
                threat_score += 10
        
        # Determine level
        if threat_score < 20:
            return '🟢 LOW'
        elif threat_score < 50:
            return '🟡 MEDIUM'
        elif threat_score < 80:
            return '🟠 HIGH'
        else:
            return '🔴 CRITICAL'
    
    def display_ip_info(self, info):
        """Pretty print IP information"""
        print("\n" + "="*60)
        print(f"📊 IP ANALYSIS REPORT")
        print("="*60)
        print(f"IP Address: {info['ip']}")
        print(f"Analyzed: {info['timestamp']}")
        print(f"Threat Level: {info.get('threat_level', 'Unknown')}")
        print("-"*60)
        
        if 'location' in info and 'error' not in info['location']:
            loc = info['location']
            print("📍 Location:")
            print(f"   Country: {loc.get('country', 'N/A')}")
            print(f"   City: {loc.get('city', 'N/A')}")
            print(f"   ISP: {loc.get('isp', 'N/A')}")
        
        if 'reputation' in info:
            rep = info['reputation']
            print("-"*60)
            print("🛡️  Reputation:")
            print(f"   Abuse Score: {rep.get('score', 'N/A')}")
            print(f"   Reports: {rep.get('reports', 'N/A')}")
        
        if 'dns_info' in info:
            print("-"*60)
            print("🔍 DNS Info:")
            print(f"   Hostname: {info['dns_info'].get('hostname', 'N/A')}")
            if 'blacklist_status' in info['dns_info']:
                print("   Blacklists:")
                for bl in info['dns_info']['blacklist_status'][:3]:
                    print(f"      {bl}")
        
        if 'open_ports' in info and info['open_ports']:
            print("-"*60)
            print("🔓 Open Ports:")
            for port in info['open_ports']:
                print(f"   Port {port}")
        
        print("="*60)
    
    def batch_scan(self):
        """Scan multiple IPs from file"""
        filename = input("Enter filename with IPs (one per line): ")
        
        if not os.path.exists(filename):
            print(f"File {filename} not found")
            return
        
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        print(f"\n📡 Scanning {len(ips)} IPs...")
        
        results = []
        for ip in ips[:20]:  # Limit to 20 for demo
            info = self.get_ip_info(ip)
            results.append(info)
            self.display_ip_info(info)
            time.sleep(1)  # Avoid rate limiting
        
        # Save results
        with open('ip_scan_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✅ Results saved to ip_scan_results.json")
    
    def monitor_suspicious(self):
        """Monitor for suspicious activities"""
        print("🔍 Monitoring for suspicious IPs...")
        
        # Check auth logs for failed logins
        try:
            result = subprocess.run(
                "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                print("\n🚨 Top 10 IPs with failed logins:")
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        count = parts[0]
                        ip = parts[1]
                        print(f"   {ip}: {count} attempts")
                        
                        # Check if any are suspicious
                        info = self.get_ip_info(ip)
                        if info.get('threat_level') in ['🟠 HIGH', '🔴 CRITICAL']:
                            print(f"   ⚠️  HIGH RISK: {ip} - {info['threat_level']}")
        except:
            print("Could not access auth logs")
    
    def main_menu(self):
        """Main interactive menu"""
        while True:
            print("\n" + "="*60)
            print("     🌐 IP INTELLIGENCE")
            print("="*60)
            print("1. Check Single IP")
            print("2. Batch IP Scan")
            print("3. Monitor Suspicious IPs")
            print("4. Analyze Threat Database")
            print("5. Export Report")
            print("6. Exit")
            print("="*60)
            
            choice = input("Select option (1-6): ")
            
            if choice == "1":
                ip = input("Enter IP address to check: ")
                info = self.get_ip_info(ip)
                self.display_ip_info(info)
            elif choice == "2":
                self.batch_scan()
            elif choice == "3":
                self.monitor_suspicious()
            elif choice == "4":
                self.analyze_threat_db()
            elif choice == "5":
                self.export_report()
            elif choice == "6":
                break
            else:
                print("Invalid option")
            
            input("\nPress Enter to continue...")
    
    def analyze_threat_db(self):
        """Analyze local threat database"""
        print("\n📊 THREAT DATABASE ANALYSIS")
        print("="*60)
        
        # Count threats by type
        threat_counts = {}
        
        try:
            # Check local logs
            if os.path.exists('ip_scan_results.json'):
                with open('ip_scan_results.json', 'r') as f:
                    data = json.load(f)
                
                threats = [item for item in data if 'CRITICAL' in str(item.get('threat_level
