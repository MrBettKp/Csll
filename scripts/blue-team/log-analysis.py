#!/usr/bin/env python3
"""
Advanced Log Analysis Script
Designed for Blue Team operations
Analyzes various log files for security incidents
"""

import re
import os
import sys
import gzip
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter

class LogAnalyzer:
    def __init__(self, log_dir="/var/log", output_file="/tmp/log_analysis_report.txt"):
        self.log_dir = log_dir
        self.output_file = output_file
        self.suspicious_activities = []
        self.stats = defaultdict(Counter)
        
    def analyze_auth_logs(self):
        """Analyze authentication logs for suspicious activities"""
        auth_patterns = {
            'failed_password': r'Failed password for',
            'invalid_user': r'Invalid user',
            'break-in_attempt': r'POSSIBLE BREAK-IN ATTEMPT',
            'accepted_password': r'Accepted password for',
            'session_opened': r'session opened',
            'session_closed': r'session closed',
        }
        
        auth_files = ['auth.log', 'secure']
        for auth_file in auth_files:
            log_path = os.path.join(self.log_dir, auth_file)
            if not os.path.exists(log_path):
                # Check for compressed versions
                if os.path.exists(log_path + '.1'):
                    log_path += '.1'
                elif os.path.exists(log_path + '.gz'):
                    log_path += '.gz'
                else:
                    continue
            
            try:
                if log_path.endswith('.gz'):
                    with gzip.open(log_path, 'rt') as f:
                        log_data = f.readlines()
                else:
                    with open(log_path, 'r') as f:
                        log_data = f.readlines()
                
                for line in log_data:
                    for pattern_name, pattern in auth_patterns.items():
                        if re.search(pattern, line):
                            self.stats[auth_file][pattern_name] += 1
                    
                    # Look for specific suspicious patterns
                    if 'Failed password for root' in line:
                        ip_match = re.search(r'from (\S+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            self.suspicious_activities.append({
                                'type': 'Root login attempt',
                                'ip': ip,
                                'log': line.strip(),
                                'file': auth_file
                            })
                
            except Exception as e:
                print(f"Error reading {log_path}: {e}")
    
    def analyze_apache_logs(self):
        """Analyze Apache/Nginx access logs for suspicious activities"""
        access_files = ['access.log', 'nginx/access.log', 'httpd/access_log']
        
        for access_file in access_files:
            log_path = os.path.join(self.log_dir, access_file)
            if not os.path.exists(log_path):
                continue
                
            try:
                if log_path.endswith('.gz'):
                    with gzip.open(log_path, 'rt') as f:
                        log_data = f.readlines()
                else:
                    with open(log_path, 'r') as f:
                        log_data = f.readlines()
                
                for line in log_data:
                    # Check for common attack patterns
                    if any(pattern in line for pattern in ['/etc/passwd', '/admin/', '/wp-admin/', 'union select', 'sleep(', 'eval(', 'base64_decode']):
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        ip = ip_match.group(1) if ip_match else 'unknown'
                        self.suspicious_activities.append({
                            'type': 'Web attack attempt',
                            'ip': ip,
                            'log': line.strip(),
                            'file': access_file
                        })
                    
                    # Count response codes
                    code_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
                    if code_match:
                        code = code_match.group(1)
                        self.stats[access_file][f'http_{code}'] += 1
                        
            except Exception as e:
                print(f"Error reading {log_path}: {e}")
    
    def generate_report(self):
        """Generate a comprehensive security report"""
        report = []
        report.append("=" * 60)
        report.append("SECURITY LOG ANALYSIS REPORT")
        report.append("Generated at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report.append("=" * 60)
        
        report.append("\nSTATISTICS SUMMARY:")
        report.append("-" * 40)
        for log_file, counts in self.stats.items():
            report.append(f"\n{log_file}:")
            for event, count in counts.most_common():
                report.append(f"  {event}: {count}")
        
        report.append("\nSUSPICIOUS ACTIVITIES:")
        report.append("-" * 40)
        if not self.suspicious_activities:
            report.append("No suspicious activities detected.")
        else:
            for activity in self.suspicious_activities:
                report.append(f"\nType: {activity['type']}")
                report.append(f"IP: {activity['ip']}")
                report.append(f"File: {activity['file']}")
                report.append(f"Log: {activity['log']}")
        
        # Write report to file
        with open(self.output_file, 'w') as f:
            f.write("\n".join(report))
        
        print(f"Report generated: {self.output_file}")
        return report

def main():
    parser = argparse.ArgumentParser(description='Security Log Analyzer')
    parser.add_argument('-d', '--log-dir', default='/var/log', help='Log directory path')
    parser.add_argument('-o', '--output', default='/tmp/log_analysis_report.txt', help='Output file path')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_dir, args.output)
    print("Analyzing authentication logs...")
    analyzer.analyze_auth_logs()
    
    print("Analyzing web server logs...")
    analyzer.analyze_apache_logs()
    
    print("Generating report...")
    report = analyzer.generate_report()
    
    # Print report to console
    print("\n".join(report))

if __name__ == "__main__":
    main()
