#!/bin/bash
# Advanced SIEM Automation Script
# For Splunk, Elasticsearch, and QRadar
# Provides real-time alerting and automated response

# Configuration
LOG_DIR="/var/log/siem/"
ALERT_DIR="/opt/siem/alerts/"
THRESHOLD_FAILED_LOGINS=10
THRESHOLD_PORT_SCAN=20
THRESHOLD_BRUTEFORCE=15
EMAIL_NOTIFICATIONS=true
EMAIL_ADDRESS="admin@yourdomain.com"
AUTO_BLOCK=true
WHITELIST_IPS=("192.168.1.0/24" "10.0.0.0/8")

# Initialize environment
mkdir -p $ALERT_DIR
current_date=$(date +"%Y-%m-%d")
alert_file="$ALERT_DIR/critical_alerts_$current_date.log"

# Function to check if IP is whitelisted
check_whitelist() {
    local ip=$1
    for subnet in "${WHITELIST_IPS[@]}"; do
        if ipcalc -n "$subnet" | grep -q "$(ipcalc -n $ip | cut -d'=' -f2)"; then
            return 0
        fi
    done
    return 1
}

# Monitor failed SSH login attempts
monitor_failed_logins() {
    echo "[$(date)] Starting SSH failed login monitor..." | tee -a $alert_file
    tail -f /var/log/auth.log /var/log/secure 2>/dev/null | grep --line-buffered "Failed password" | while read line; do
        username=$(echo "$line" | grep -oP 'for \K\S+')
        ip=$(echo "$line" | grep -oP 'from \K\S+')
        
        # Check if IP is whitelisted
        if check_whitelist "$ip"; then
            continue
        fi
        
        # Count attempts
        count=$(grep -c "Failed password for $username from $ip" /var/log/auth.log /var/log/secure 2>/dev/null | awk '{sum += $1} END {print sum}')
        
        if [ "$count" -gt $THRESHOLD_FAILED_LOGINS ]; then
            alert_msg="$(date): Brute force attempt detected: User: $username, IP: $ip, Attempts: $count"
            echo "$alert_msg" | tee -a $alert_file
            
            if [ "$AUTO_BLOCK" = true ]; then
                iptables -A INPUT -s $ip -j DROP
                echo "$(date): IP $ip automatically blocked via iptables" | tee -a $alert_file
            fi
            
            if [ "$EMAIL_NOTIFICATIONS" = true ]; then
                echo "Brute force attempt detected. IP $ip has made $count failed login attempts as $username." | \
                mail -s "SIEM Alert: Brute Force Attempt" $EMAIL_ADDRESS
            fi
        fi
    done
}

# Monitor port scanning activity
monitor_port_scans() {
    echo "[$(date)] Starting port scan monitor..." | tee -a $alert_file
    tail -f /var/log/kern.log /var/log/syslog 2>/dev/null | grep --line-buffered "iptables" | grep --line-buffered "DPT=" | while read line; do
        ip=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
        port=$(echo "$line" | grep -oP 'DPT=\K[0-9]+')
        
        # Check if IP is whitelisted
        if check_whitelist "$ip"; then
            continue
        fi
        
        # Count connection attempts to different ports
        count=$(grep "SRC=$ip" /var/log/kern.log /var/log/syslog 2>/dev/null | grep -c "DPT=")
        
        if [ "$count" -gt $THRESHOLD_PORT_SCAN ]; then
            alert_msg="$(date): Port scan detected from IP: $ip, Unique ports: $count"
            echo "$alert_msg" | tee -a $alert_file
            
            if [ "$EMAIL_NOTIFICATIONS" = true ]; then
                echo "Port scan detected from IP $ip. They have attempted connections to $count different ports." | \
                mail -s "SIEM Alert: Port Scan" $EMAIL_ADDRESS
            fi
        fi
    done
}

# Monitor for DDoS attempts
monitor_ddos() {
    echo "[$(date)] Starting DDoS monitor..." | tee -a $alert_file
    netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n | while read connection; do
        count=$(echo $connection | awk '{print $1}')
        ip=$(echo $connection | awk '{print $2}')
        
        # Check if IP is whitelisted
        if check_whitelist "$ip"; then
            continue
        fi
        
        if [ "$count" -gt $THRESHOLD_BRUTEFORCE ]; then
            alert_msg="$(date): Possible DDoS attempt from IP: $ip, Connections: $count"
            echo "$alert_msg" | tee -a $alert_file
            
            if [ "$AUTO_BLOCK" = true ]; then
                iptables -A INPUT -s $ip -j DROP
                echo "$(date): IP $ip automatically blocked due to excessive connections" | tee -a $alert_file
            fi
            
            if [ "$EMAIL_NOTIFICATIONS" = true ]; then
                echo "Possible DDoS attempt from IP $ip. They have $count simultaneous connections." | \
                mail -s "SIEM Alert: DDoS Attempt" $EMAIL_ADDRESS
            fi
        fi
    done
}

# Main execution
echo "==============================================" | tee -a $alert_file
echo "SIEM Automation Script Started at $(date)" | tee -a $alert_file
echo "==============================================" | tee -a $alert_file

# Start monitoring in background
monitor_failed_logins &
monitor_port_scans &
monitor_ddos &

# Keep script running
wait
