#!/bin/bash
# Main Panel Menu
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:58:59

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Show Panel Header
show_header() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             AUTOVPN-PRO PANEL              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    echo -e " Created by: ${GREEN}Defebs-vpn${NC}"
    echo -e " Version  : ${GREEN}1.0${NC}"
    echo -e "${BLUE}═════════════════════════════════════════════${NC}"
}

# Function: Show System Information
show_system_info() {
    echo -e "\n${YELLOW}System Information:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " OS       : $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d'"' -f2)"
    echo -e " CPU      : $(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2)"
    echo -e " Memory   : $(free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }')"
    echo -e " Storage  : $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    echo -e " Domain   : $(cat /root/domain)"
    echo -e " IP       : $(curl -s ipv4.icanhazip.com)"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Main Menu:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Account Manager"
    echo -e " [${GREEN}2${NC}] System Manager"
    echo -e " [${GREEN}3${NC}] Tools Manager"
    echo -e " [${GREEN}x${NC}] Exit"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Function: Process Menu Choice
process_choice() {
    read -p "Select menu: " choice
    case $choice in
        1)
            /etc/AutoVPN-Pro/menu/account.sh
            ;;
        2)
            /etc/AutoVPN-Pro/menu/system.sh
            ;;
        3)
            /etc/AutoVPN-Pro/menu/tools.sh
            ;;
        x)
            clear
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice!${NC}"
            sleep 2
            ;;
    esac
}

# Main Function
main() {
    while true; do
        show_header
        show_system_info
        show_menu
        process_choice
    done
}

# Run main function
main