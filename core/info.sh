#!/bin/bash
# Core Information Script
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:18:02

# System Information
SCRIPT_VERSION="1.0"
SCRIPT_AUTHOR="Defebs-vpn"
SCRIPT_CREATE_DATE="2025-02-17"
SCRIPT_CREATE_TIME="08:18:02"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function: Show System Info
show_system_info() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SYSTEM INFORMATION               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo -e " Script Version : $SCRIPT_VERSION"
    echo -e " Author        : $SCRIPT_AUTHOR"
    echo -e " Created Date  : $SCRIPT_CREATE_DATE"
    echo -e " Created Time  : $SCRIPT_CREATE_TIME"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e " OS Name       : $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)"
    echo -e " Architecture  : $(uname -m)"
    echo -e " Kernel       : $(uname -r)"
    echo -e " Hostname     : $(hostname)"
    echo -e " IP Address   : $(curl -s ipv4.icanhazip.com)"
    echo -e " Domain       : $(cat /etc/xray/domain 2>/dev/null || echo "Not Set")"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
}

# Function: Show Service Status
show_service_status() {
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SERVICE STATUS                   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    
    services=("nginx" "ssh" "xray" "fail2ban" "cron")
    
    for service in "${services[@]}"; do
        status=$(systemctl is-active $service)
        if [[ $status == "active" ]]; then
            echo -e " $service : ${GREEN}Running${NC}"
        else
            echo -e " $service : ${RED}Not Running${NC}"
        fi
    done
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
}

# Function: Show Resource Usage
show_resource_usage() {
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           RESOURCE USAGE                   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo -e " CPU Usage    : $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo -e " Memory Usage : $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
    echo -e " Disk Usage   : $(df -h / | awk 'NR==2{print $5}')"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
}

# Main Function
main() {
    show_system_info
    echo
    show_service_status
    echo
    show_resource_usage
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi