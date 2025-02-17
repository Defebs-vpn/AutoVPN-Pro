#!/bin/bash
# Tools Management Menu
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:01:19

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Show Header
show_header() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           TOOLS MANAGEMENT                  ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Tools Manager:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Backup Config"
    echo -e " [${GREEN}2${NC}] Restore Config"
    echo -e " [${GREEN}3${NC}] Anti-DDoS Settings"
    echo -e " [${GREEN}4${NC}] Configure Firewall"
    echo -e " [${GREEN}5${NC}] DNS Changer"
    echo -e " [${GREEN}6${NC}] Network Optimizer"
    echo -e " [${GREEN}7${NC}] Reset Services"
    echo -e " [${GREEN}8${NC}] Clear Cache"
    echo -e " [${GREEN}9${NC}] Auto-Kill Multi Login"
    echo -e " [${GREEN}10${NC}] Log Cleaner"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Function: Backup Configuration
backup_config() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           BACKUP CONFIGURATION              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Create backup directory
    backup_dir="/root/backup"
    mkdir -p $backup_dir
    
    # Backup date
    backup_date=$(date +%Y-%m-%d_%H-%M-%S)
    
    # Create backup
    tar -czf $backup_dir/backup_${backup_date}.tar.gz \
        /etc/AutoVPN-Pro \
        /etc/nginx \
        /usr/local/etc/xray \
        /etc/systemd/system/ws-tls.service \
        /etc/systemd/system/ws-nontls.service
        
    echo -e "${GREEN}Backup completed: ${backup_dir}/backup_${backup_date}.tar.gz${NC}"
}

# Function: Restore Configuration
restore_config() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           RESTORE CONFIGURATION             ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # List backups
    echo -e "\n${YELLOW}Available Backups:${NC}"
    ls -1 /root/backup/*.tar.gz 2>/dev/null
    
    # Select backup
    read -p "Enter backup file name: " backup_file
    
    if [ -f "/root/backup/$backup_file" ]; then
        tar -xzf "/root/backup/$backup_file" -C /
        systemctl restart nginx xray ws-tls ws-nontls
        echo -e "${GREEN}Configuration restored successfully!${NC}"
    else
        echo -e "${RED}Backup file not found!${NC}"
    fi
}

# Function: Anti-DDoS Settings
antiddos_settings() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           ANTI-DDOS SETTINGS                ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Configure iptables rules
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables.rules
    
    echo -e "${GREEN}Anti-DDoS rules have been configured!${NC}"
}

# Function: Network Optimizer
network_optimizer() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           NETWORK OPTIMIZER                 ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Optimize sysctl settings
    cat > /etc/sysctl.d/99-network-performance.conf << END
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_syn_backlog = 4096
END
    
    # Apply settings
    sysctl -p /etc/sysctl.d/99-network-performance.conf
    
    echo -e "${GREEN}Network settings optimized!${NC}"
}

# Function: Process Menu Choice
process_choice() {
    read -p "Select menu: " choice
    case $choice in
        1) backup_config ;;
        2) restore_config ;;
        3) antiddos_settings ;;
        4) configure_firewall ;;
        5) dns_changer ;;
        6) network_optimizer ;;
        7) reset_services ;;
        8) clear_cache ;;
        9) auto_kill ;;
        10) log_cleaner ;;
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