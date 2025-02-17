#!/bin/bash
# System Management Menu
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:01:19

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Show Header
show_header() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SYSTEM MANAGEMENT                ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}System Manager:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Change Domain"
    echo -e " [${GREEN}2${NC}] Change Port"
    echo -e " [${GREEN}3${NC}] Restart Service"
    echo -e " [${GREEN}4${NC}] Server Information"
    echo -e " [${GREEN}5${NC}] Speed Test"
    echo -e " [${GREEN}6${NC}] System Update"
    echo -e " [${GREEN}7${NC}] BBR Settings"
    echo -e " [${GREEN}8${NC}] Check Service Status"
    echo -e " [${GREEN}9${NC}] Memory Usage"
    echo -e " [${GREEN}10${NC}] Bandwidth Monitor"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Function: Change Domain
change_domain() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           CHANGE DOMAIN                     ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    read -p "Input your domain: " domain
    echo "$domain" > /root/domain
    
    # Update certificates
    certbot --nginx -d $domain --non-interactive --agree-tos --email admin@$domain
    
    # Restart services
    systemctl restart nginx
    systemctl restart xray
    
    echo -e "${GREEN}Domain successfully changed to ${domain}${NC}"
}

# Function: Change Port
change_port() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           CHANGE PORT                       ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Current Ports:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " SSH      : $PORT_SSH"
    echo -e " SSL      : $PORT_SSL"
    echo -e " VMess    : $PORT_VMESS"
    echo -e " VLESS    : $PORT_VLESS"
    echo -e " Trojan   : $PORT_TROJAN"
    echo -e " gRPC     : $PORT_GRPC"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    echo -e "\n${YELLOW}Select service to change port:${NC}"
    echo -e " [1] SSH"
    echo -e " [2] SSL"
    echo -e " [3] VMess"
    echo -e " [4] VLESS"
    echo -e " [5] Trojan"
    echo -e " [6] gRPC"
    
    read -p "Select service: " service
    read -p "Input new port: " new_port
    
    case $service in
        1) sed -i "s/PORT_SSH=.*/PORT_SSH=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        2) sed -i "s/PORT_SSL=.*/PORT_SSL=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        3) sed -i "s/PORT_VMESS=.*/PORT_VMESS=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        4) sed -i "s/PORT_VLESS=.*/PORT_VLESS=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        5) sed -i "s/PORT_TROJAN=.*/PORT_TROJAN=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        6) sed -i "s/PORT_GRPC=.*/PORT_GRPC=\"$new_port\"/" $CORE_DIR/vars.conf ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
    
    # Restart services
    restart_services
}

# Function: Restart Services
restart_services() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           RESTART SERVICES                  ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    systemctl restart ssh
    systemctl restart nginx
    systemctl restart xray
    systemctl restart ws-tls
    systemctl restart ws-nontls
    
    echo -e "${GREEN}All services have been restarted!${NC}"
}

# Function: Process Menu Choice
process_choice() {
    read -p "Select menu: " choice
    case $choice in
        1) change_domain ;;
        2) change_port ;;
        3) restart_services ;;
        4) show_server_info ;;
        5) speedtest ;;
        6) system_update ;;
        7) bbr_settings ;;
        8) check_services ;;
        9) show_memory ;;
        10) monitor_bandwidth ;;
        x) return ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
}

# Main Function
main() {
    while true; do
        show_header
        show_menu
        process_choice
        read -n 1 -s -r -p "Press any key to continue"
    done
}

# Run main function
main