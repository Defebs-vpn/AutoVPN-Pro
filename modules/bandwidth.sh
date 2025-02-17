#!/bin/bash
# Bandwidth Monitoring Module
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:05:04

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Monitor Bandwidth
monitor_bandwidth() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           BANDWIDTH MONITOR                 ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Install vnstat if not exists
    if ! which vnstat > /dev/null; then
        apt install -y vnstat
        systemctl enable vnstat
        systemctl start vnstat
    fi
    
    # Show bandwidth usage
    echo -e "\n${YELLOW}Today's Bandwidth Usage:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    vnstat -d | grep "today"
    
    echo -e "\n${YELLOW}Monthly Bandwidth Usage:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    vnstat -m | grep "`date +"%Y-%m"`"
    
    # Show XRay Statistics
    echo -e "\n${YELLOW}XRay Traffic Statistics:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    # Get statistics for each protocol
    for proto in vmess vless trojan; do
        upload=$(xray api stats -server=127.0.0.1:10085 -name "user>>>${proto}>>>traffic>>>uplink" 2>/dev/null)
        download=$(xray api stats -server=127.0.0.1:10085 -name "user>>>${proto}>>>traffic>>>downlink" 2>/dev/null)
        
        echo -e "${proto^^}:"
        echo -e "Upload   : $(numfmt --to=iec --suffix=B ${upload:-0})"
        echo -e "Download : $(numfmt --to=iec --suffix=B ${download:-0})"
        echo -e "━━━━━━━━━━━━━━━━━━━━━"
    done
}

# Function: Set Bandwidth Limit
set_bandwidth_limit() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           BANDWIDTH LIMITER                 ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    read -p "Enter username: " user
    read -p "Enter bandwidth limit (in GB): " limit
    
    # Convert GB to bytes
    limit_bytes=$((limit * 1024 * 1024 * 1024))
    
    # Set limit in XRay config
    jq --arg user "$user" --arg limit "$limit_bytes" \
        '.inbounds[].settings.clients[] | select(.email == $user) += {"totalGB": $limit}' \
        /usr/local/etc/xray/config.json > /tmp/xray.json
    
    mv /tmp/xray.json /usr/local/etc/xray/config.json
    systemctl restart xray
    
    echo -e "${GREEN}Bandwidth limit set for user $user: ${limit}GB${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Bandwidth Management:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Monitor Bandwidth"
    echo -e " [${GREEN}2${NC}] Set Bandwidth Limit"
    echo -e " [${GREEN}3${NC}] Reset Statistics"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Main Function
main() {
    while true; do
        show_menu
        read -p "Select menu: " choice
        case $choice in
            1) monitor_bandwidth ;;
            2) set_bandwidth_limit ;;
            3) vnstat --reset; systemctl restart vnstat ;;
            x) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
        read -n 1 -s -r -p "Press any key to continue"
    done
}

# Run main if execute directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi