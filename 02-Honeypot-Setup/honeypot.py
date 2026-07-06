#!/usr/bin/env python3
"""
SSH Honeypot v1.0
Pretends to be an SSH server to capture attacker attempts
"""

import socket
import threading
import logging
import datetime
import json
import sys
import os
import time
from datetime import datetime

class SSH_Honeypot:
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        self.connections = 0
        self.log_file = 'honeypot_log.json'
        
        # Setup logging
        logging.basicConfig(
            filename='honeypot.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        
        # Create log directory
        os.makedirs('logs', exist_ok=True)
    
    def handle_client(self, client_socket, address):
        """Handle incoming SSH connections"""
        self.connections += 1
        ip, port = address
        
        print(f"[+] Connection from {ip}:{port} (Total: {self.connections})")
        logging.info(f"Connection from {ip}:{port}")
        
        try:
            # Send SSH banner
            client_socket.send(f"{self.banner}\n".encode())
            
            # Wait for client input
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            
            # Log the data
            self.log_attempt(ip, port, data)
            
            # Respond with fake SSH response
            response = "Permission denied (publickey,password)."
            client_socket.send(response.encode())
            
        except Exception as e:
            logging.error(f"Error handling {ip}:{port} - {e}")
        finally:
            client_socket.close()
    
    def log_attempt(self, ip, port, data):
        """Log connection attempts with details"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip,
            'source_port': port,
            'data': data[:500],  # Limit data size
            'banner': self.banner
        }
        
        # Save to JSON log
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
        
        # Also save to CSV for easy analysis
        try:
            with open('logs/honeypot.csv', 'a') as f:
                f.write(f"{datetime.now()},{ip},{port},{data[:100]}\n")
        except:
            pass
    
    def analyze_logs(self):
        """Analyze honeypot logs for patterns"""
        print("\n📊 HONEYPOT ANALYSIS")
        print("="*50)
        
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            total_attempts = len(lines)
            unique_ips = set()
            failed_attempts = 0
            
            for line in lines:
                try:
                    data = json.loads(line)
                    unique_ips.add(data['source_ip'])
                    
                    # Detect common attack patterns
                    if 'password' in data['data'].lower():
                        failed_attempts += 1
                except:
                    pass
            
            print(f"Total Connections: {total_attempts}")
            print(f"Unique Attackers: {len(unique_ips)}")
            print(f"Failed Login Attempts: {failed_attempts}")
            print(f"Log File: {self.log_file}")
            
        except FileNotFoundError:
            print("No logs found yet")
    
    def run(self):
        """Start the honeypot server"""
        print("="*60)
        print("     🍯 SSH HONEYPOT")
        print("="*60)
        print(f"Listening on: {self.host}:{self.port}")
        print(f"Log file: {self.log_file}")
        print("Press Ctrl+C to stop")
        print("="*60)
        
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(100)
            
            while True:
                client, address = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, address))
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            print("\n[!] Shutting down honeypot...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            server.close()
            self.analyze_logs()

if __name__ == "__main__":
    # Check if running as root (needed for ports < 1024)
    if os.geteuid() != 0:
        print("⚠️  Running as root is recommended for honeypot")
        print("   sudo python3 honeypot.py")
    
    honeypot = SSH_Honeypot(port=2222)  # Use port 2222 to avoid conflict
    honeypot.run()
