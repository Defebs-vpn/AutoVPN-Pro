#!/bin/bash
# System Monitoring Module
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:06:42

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Monitor System Resources
monitor_resources() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SYSTEM MONITOR                    ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # System Information
    echo -e "\n${YELLOW}System Information:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "OS        : $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)"
    echo -e "Kernel    : $(uname -r)"
    echo -e "Uptime    : $(uptime -p)"
    echo -e "CPU Load  : $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
    
    # Memory Usage
    echo -e "\n${YELLOW}Memory Usage:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    free -h | grep -v "Swap"
    
    # Disk Usage
    echo -e "\n${YELLOW}Disk Usage:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    df -h / | tail -n 1
    
    # Network Usage
    echo -e "\n${YELLOW}Network Usage:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    vnstat -h 1 | tail -n 3
    
    # Service Status
    echo -e "\n${YELLOW}Service Status:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    services=("nginx" "xray" "ws-tls" "ws-nontls" "fail2ban")
    for service in "${services[@]}"; do
        status=$(systemctl is-active $service)
        if [ "$status" == "active" ]; then
            echo -e "$service : ${GREEN}Running${NC}"
        else
            echo -e "$service : ${RED}Stopped${NC}"
        fi
    done
}

# Function: Monitor Online Users
monitor_users() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           USER MONITOR                      ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # SSH Users
    echo -e "\n${YELLOW}SSH Online Users:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    who | awk '{print $1, "from", $5}' | sed 's/(//' | sed 's/)//'
    
    # XRay Users
    echo -e "\n${YELLOW}XRay Online Users:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    # Check each protocol
    for proto in vmess vless trojan; do
        echo -e "${CYAN}${proto^^} Users:${NC}"
        xray api statsquery -server=127.0.0.1:10085 | grep "${proto}" | grep "user" | \
        while read line; do
            user=$(echo $line | awk -F>>> '{print $3}')
            echo "- $user"
        done
    done
}

# Function: Monitor Traffic
monitor_traffic() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           TRAFFIC MONITOR                   ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Live traffic monitoring
    echo -e "\n${YELLOW}Live Traffic Monitor:${NC}"
    echo -e "Press Ctrl+C to stop"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    iftop -n -P
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Monitor Menu:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] System Resources"
    echo -e " [${GREEN}2${NC}] Online Users"
    echo -e " [${GREEN}3${NC}] Traffic Monitor"
    echo -e " [${GREEN}4${NC}] Service Status"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Main Function
main() {
    while true; do
        show_menu
        read -p "Select menu: " choice
        case $choice in
            1) monitor_resources ;;
            2) monitor_users ;;
            3) monitor_traffic ;;
            4) systemctl status nginx xray ws-tls ws-nontls ;;
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