#!/bin/bash
# Backup & Restore Module
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:05:04

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Backup Directory
BACKUP_DIR="/root/backup"
RCLONE_CONFIG="/root/.config/rclone/rclone.conf"

# Function: Create Backup
create_backup() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           CREATE BACKUP                     ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Create backup directory
    mkdir -p $BACKUP_DIR
    
    # Backup timestamp
    backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    
    # Files to backup
    echo -e "\n${YELLOW}Creating backup...${NC}"
    tar -czf $BACKUP_DIR/${backup_name}.tar.gz \
        /etc/AutoVPN-Pro \
        /etc/nginx \
        /usr/local/etc/xray \
        /etc/passwd \
        /etc/shadow \
        /etc/gshadow \
        /etc/group \
        /etc/crontab \
        /var/lib/vnstat
        
    # Encrypt backup
    echo -e "\n${YELLOW}Encrypting backup...${NC}"
    openssl enc -aes-256-cbc -salt -in $BACKUP_DIR/${backup_name}.tar.gz \
        -out $BACKUP_DIR/${backup_name}.enc -k "${BACKUP_PASSWORD:-default_password}"
        
    # Remove unencrypted backup
    rm $BACKUP_DIR/${backup_name}.tar.gz
    
    echo -e "${GREEN}Backup created: ${backup_name}.enc${NC}"
}

# Function: Restore Backup
restore_backup() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           RESTORE BACKUP                    ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # List available backups
    echo -e "\n${YELLOW}Available backups:${NC}"
    ls -1 $BACKUP_DIR/*.enc 2>/dev/null || echo "No backups found"
    
    # Select backup
    read -p "Enter backup filename: " backup_file
    
    if [ -f "$BACKUP_DIR/$backup_file" ]; then
        # Decrypt backup
        echo -e "\n${YELLOW}Decrypting backup...${NC}"
        openssl enc -aes-256-cbc -d -in $BACKUP_DIR/$backup_file \
            -out $BACKUP_DIR/restore.tar.gz -k "${BACKUP_PASSWORD:-default_password}"
            
        # Extract backup
        echo -e "\n${YELLOW}Restoring files...${NC}"
        tar -xzf $BACKUP_DIR/restore.tar.gz -C /
        
        # Clean up
        rm $BACKUP_DIR/restore.tar.gz
        
        # Restart services
        systemctl restart nginx xray ws-tls ws-nontls
        
        echo -e "${GREEN}Backup restored successfully!${NC}"
    else
        echo -e "${RED}Backup file not found!${NC}"
    fi
}

# Function: Configure Cloud Backup
configure_cloud_backup() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           CLOUD BACKUP CONFIG               ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Install rclone if not exists
    if ! which rclone > /dev/null; then
        echo -e "\n${YELLOW}Installing rclone...${NC}"
        curl https://rclone.org/install.sh | bash
    fi
    
    # Configure rclone
    echo -e "\n${YELLOW}Configuring rclone...${NC}"
    rclone config
    
    # Set up automatic backup
    cat > /etc/cron.daily/autobackup << END
#!/bin/bash
/etc/AutoVPN-Pro/modules/backup.sh --auto-cloud
END
    chmod +x /etc/cron.daily/autobackup
    
    echo -e "${GREEN}Cloud backup configured!${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Backup Management:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Create Backup"
    echo -e " [${GREEN}2${NC}] Restore Backup"
    echo -e " [${GREEN}3${NC}] Configure Cloud Backup"
    echo -e " [${GREEN}4${NC}] List Backups"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Main Function
main() {
    while true; do
        show_menu
        read -p "Select menu: " choice
        case $choice in
            1) create_backup ;;
            2) restore_backup ;;
            3) configure_cloud_backup ;;
            4) ls -lh $BACKUP_DIR/*.enc 2>/dev/null || echo "No backups found" ;;
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