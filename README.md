# Cybersecurity Labs & Scripts Collection

A comprehensive collection of professional cybersecurity scripts for Blue Team, Red Team, and Ethical Hacking operations.

## Script Categories

### Blue Team
- **siem-automation.sh** - Advanced SIEM automation with real-time alerting and response
- **log-analysis.py** - Comprehensive log analysis for security incidents
- **intrusion-detection.js** - Intrusion Detection System with file integrity monitoring

### Red Team
- **network-scanner.py** - Advanced network scanner with stealth capabilities
- **vulnerability-scanner.js** - Comprehensive vulnerability assessment tool
- **exploit-framework.py** - Modular exploit framework for various vulnerabilities

### Ethical Hacking
- **web-scanner.py** - Advanced web vulnerability scanner
- **password-cracker.js** - Password cracking tool with multiple attack modes
- **wireless-audit.sh** - Wireless security assessment toolkit

## Requirements

- Kali Linux or Parrot OS recommended
- Python 3.8+
- Node.js 14+
- Aircrack-ng suite (for wireless audit)
- Various Python packages (install with `pip install -r requirements.txt`)

## Installation

Clone this repository:
`git clone https://github.com/ArapKBett/Csl.git
cd Csl`

Install python dependencies 
`pip install -r requirements.txt`


NodeJs Dependencies 
`npm install`

Wireless scripts
`sudo apt update && sudo apt install aircrack-ng`

Every script has a specific usage script within it's code. for example 
```# Network scanning
python scripts/red-team/network-scanner.py 192.168.1.0/24

# Web vulnerability scanning
python scripts/ethical-hacking/web-scanner.py http://example.com

# Password cracking
node scripts/ethical-hacking/password-cracker.js dictionary 5f4dcc3b5aa765d61d8327deb882cf99```
