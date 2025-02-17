#!/bin/bash
# AutoVPN-Pro Uninstaller
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:09:38

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function: Show Banner
show_banner() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           AUTOVPN-PRO UNINSTALLER          ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
}

# Function: Confirm Uninstall
confirm_uninstall() {
    echo -e "\n${RED}WARNING: This will remove all AutoVPN-Pro files and configurations!${NC}"
    read -p "Are you sure you want to continue? (y/n): " confirm
    if [[ $confirm != "y" ]]; then
        echo -e "${YELLOW}Uninstallation cancelled.${NC}"
        exit 0
    fi
}

# Function: Remove Services
remove_services() {
    echo -e "\n${YELLOW}Removing services...${NC}"
    
    # Stop services
    systemctl stop xray ws-tls ws-nontls
    systemctl disable xray ws-tls ws-nontls
    
    # Remove service files
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/systemd/system/ws-tls.service
    rm -f /etc/systemd/system/ws-nontls.service
    
    systemctl daemon-reload
}

# Function: Remove Files
remove_files() {
    echo -e "\n${YELLOW}Removing files...${NC}"
    
    # Remove installation directory
    rm -rf /etc/AutoVPN-Pro
    
    # Remove XRay files
    rm -rf /usr/local/etc/xray
    rm -rf /var/log/xray
    
    # Remove WebSocket files
    rm -rf /usr/local/bin/websocket
    
    # Remove menu files
    rm -f /usr/local/bin/menu
    
    # Remove configuration backup
    rm -rf /root/backup
}

# Function: Clean System
clean_system() {
    echo -e "\n${YELLOW}Cleaning system...${NC}"
    
    # Remove packages
    apt remove -y xray nginx fail2ban
    apt autoremove -y
    
    # Remove SSL certificates
    certbot delete --cert-name $DOMAIN
}

# Main Function
main() {
    show_banner
    confirm_uninstall
    remove_services
    remove_files
    clean_system
    echo -e "\n${GREEN}AutoVPN-Pro has been successfully uninstalled!${NC}"
}

# Run main function
main