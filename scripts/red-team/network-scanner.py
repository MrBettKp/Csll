#!/usr/bin/env python3
"""
Advanced Network Scanner with Stealth Capabilities
Designed for Red Team operations
"""

import scapy.all as scapy
import socket
import threading
import ipaddress
import argparse
import time
from queue import Queue
from datetime import datetime

class AdvancedNetworkScanner:
    def __init__(self, target, ports=None, threads=100, stealth=True, os_detection=True, service_detection=True):
        self.target = target
        self.ports = ports or range(1, 1001)  # Default to top 1000 ports
        self.threads = threads
        self.stealth_mode = stealth
        self.os_detection = os_detection
        self.service_detection = service_detection
        self.open_ports = []
        self.host_os = {}
        self.services = {}
        self.print_lock = threading.Lock()
        
    def validate_target(self):
        """Validate the target IP or network range"""
        try:
            if '/' in self.target:
                # It's a network range
                network = ipaddress.ip_network(self.target, strict=False)
                return [str(ip) for ip in network.hosts()]
            else:
                # Single IP address
                return [str(ipaddress.ip_address(self.target))]
        except ValueError as e:
            print(f"Invalid target: {e}")
            return []
    
    def syn_scan(self, ip, port):
        """Perform a stealth SYN scan"""
        try:
            # Craft SYN packet
            syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
            # Send and receive with timeout
            resp = scapy.sr1(syn_packet, timeout=1, verbose=0)
            
            if resp and resp.haslayer(scapy.TCP):
                if resp.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R"), verbose=0)
                    return True
                elif resp.getlayer(scapy.TCP).flags == 0x14:  # RST-ACK
                    return False
            return False
        except Exception as e:
            return False
    
    def connect_scan(self, ip, port):
        """Traditional connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Scan a single port"""
        if self.stealth_mode:
            is_open = self.syn_scan(ip, port)
        else:
            is_open = self.connect_scan(ip, port)
        
        if is_open:
            with self.print_lock:
                print(f"[+] {ip}:{port} is open")
            self.open_ports.append((ip, port))
            
            # Service detection
            if self.service_detection:
                service = self.detect_service(ip, port)
                if service:
                    self.services[(ip, port)] = service
    
    def detect_service(self, ip, port):
        """Attempt to detect service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send a benign payload to elicit response
            if port == 80 or port == 443:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                sock.send(b"USER anonymous\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner.split('\n')[0] if banner else "Unknown"
        except:
            return "Unknown"
    
    def os_fingerprint(self, ip):
        """Attempt OS fingerprinting"""
        try:
            # TCP SYN packet
            syn_packet = scapy.IP(dst=ip)/scapy.TCP(dport=80, flags="S")
            resp = scapy.sr1(syn_packet, timeout=2, verbose=0)
            
            if resp:
                # Analyze TTL and window size for OS guess
                ttl = resp[scapy.IP].ttl
                window_size = resp[scapy.TCP].window
                
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Other"
                
                self.host_os[ip] = f"{os_guess} (TTL: {ttl}, Window: {window_size})"
                return self.host_os[ip]
        except:
            pass
        
        return "Unknown"
    
    def threader(self, q, ip):
        """Thread function for port scanning"""
        while not q.empty():
            port = q.get()
            self.scan_port(ip, port)
            q.task_done()
    
    def scan(self):
        """Main scan method"""
        targets = self.validate_target()
        if not targets:
            print("No valid targets to scan")
            return
        
        start_time = time.time()
        
        for ip in targets:
            print(f"\nScanning target: {ip}")
            self.open_ports = []
            
            # OS detection if enabled
            if self.os_detection:
                os_info = self.os_fingerprint(ip)
                print(f"[*] OS detection: {os_info}")
            
            # Create queue and add ports
            q = Queue()
            for port in self.ports:
                q.put(port)
            
            # Create threads
            for _ in range(self.threads):
                t = threading.Thread(target=self.threader, args=(q, ip))
                t.daemon = True
                t.start()
            
            # Wait for queue to empty
            q.join()
            
            # Print summary for this host
            print(f"\nScan results for {ip}:")
            print("-" * 40)
            for ip, port in self.open_ports:
                service = self.services.get((ip, port), "Unknown service")
                print(f"Port {port}/tcp open - {service}")
        
        # Print overall summary
        scan_duration = time.time() - start_time
        print(f"\nScan completed in {scan_duration:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Scanner')
    parser.add_argument('target', help='Target IP address or network range (CIDR notation)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443 or 1-1000)', default='1-1000')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads', default=100)
    parser.add_argument('--no-stealth', action='store_true', help='Disable stealth mode')
    parser.add_argument('--no-os', action='store_true', help='Disable OS detection')
    parser.add_argument('--no-service', action='store_true', help='Disable service detection')
    
    args = parser.parse_args()
    
    # Parse ports
    if '-' in args.ports:
        start, end = args.ports.split('-')
        ports = range(int(start), int(end) + 1)
    elif ',' in args.ports:
        ports = [int(p) for p in args.ports.split(',')]
    else:
        ports = [int(args.ports)]
    
    # Create scanner instance
    scanner = AdvancedNetworkScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        stealth=not args.no_stealth,
        os_detection=not args.no_os,
        service_detection=not args.no_service
    )
    
    # Start scan
    scanner.scan()

if __name__ == "__main__":
    main()
