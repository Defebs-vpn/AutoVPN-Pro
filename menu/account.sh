#!/bin/bash
# Account Management Menu
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:58:59

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Show Header
show_header() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           ACCOUNT MANAGEMENT                ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Account Manager:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Create Account"
    echo -e " [${GREEN}2${NC}] Delete Account"
    echo -e " [${GREEN}3${NC}] Extend Account"
    echo -e " [${GREEN}4${NC}] List Account"
    echo -e " [${GREEN}5${NC}] Monitor Account"
    echo -e " [${GREEN}6${NC}] Backup Account"
    echo -e " [${GREEN}7${NC}] Restore Account"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Function: Create Account
create_account() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           CREATE NEW ACCOUNT                ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Select Protocol:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] SSH & WebSocket"
    echo -e " [${GREEN}2${NC}] XRay VMess"
    echo -e " [${GREEN}3${NC}] XRay VLESS"
    echo -e " [${GREEN}4${NC}] XRay Trojan"
    echo -e " [${GREEN}5${NC}] XRay gRPC"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    read -p "Select protocol: " protocol
    case $protocol in
        1) create_ssh ;;
        2) create_vmess ;;
        3) create_vless ;;
        4) create_trojan ;;
        5) create_grpc ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
}

# Function: Delete Account
delete_account() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           DELETE ACCOUNT                    ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Select Protocol:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] SSH & WebSocket"
    echo -e " [${GREEN}2${NC}] XRay VMess"
    echo -e " [${GREEN}3${NC}] XRay VLESS"
    echo -e " [${GREEN}4${NC}] XRay Trojan"
    echo -e " [${GREEN}5${NC}] XRay gRPC"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    
    read -p "Select protocol: " protocol
    case $protocol in
        1) delete_ssh ;;
        2) delete_vmess ;;
        3) delete_vless ;;
        4) delete_trojan ;;
        5) delete_grpc ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
}

# Function: Process Menu Choice
process_choice() {
    read -p "Select menu: " choice
    case $choice in
        1) create_account ;;
        2) delete_account ;;
        3) extend_account ;;
        4) list_account ;;
        5) monitor_account ;;
        6) backup_account ;;
        7) restore_account ;;
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