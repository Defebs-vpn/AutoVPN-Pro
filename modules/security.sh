#!/bin/bash
# Security Management Module
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:06:42

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Configure Firewall
configure_firewall() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           FIREWALL CONFIGURATION            ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Reset iptables
    iptables -F
    iptables -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Allow XRay ports
    iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # VMess
    iptables -A INPUT -p tcp --dport 8442 -j ACCEPT  # VLESS
    iptables -A INPUT -p tcp --dport 8441 -j ACCEPT  # Trojan
    iptables -A INPUT -p tcp --dport 8444 -j ACCEPT  # gRPC
    
    # Save rules
    iptables-save > /etc/iptables.rules
    
    echo -e "${GREEN}Firewall configured successfully!${NC}"
}

# Function: Configure Fail2Ban
configure_fail2ban() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           FAIL2BAN CONFIGURATION            ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Install fail2ban if not exists
    if ! which fail2ban-client > /dev/null; then
        apt install -y fail2ban
    fi
    
    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << END
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh,22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-bad-request]
enabled = true
filter = nginx-bad-request
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 3
END
    
    # Restart fail2ban
    systemctl restart fail2ban
    
    echo -e "${GREEN}Fail2Ban configured successfully!${NC}"
}

# Function: SSL Security
configure_ssl() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SSL SECURITY CONFIG               ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Generate strong DH params
    openssl dhparam -out /etc/nginx/dhparam.pem 2048
    
    # Configure SSL in Nginx
    cat > /etc/nginx/conf.d/ssl.conf << END
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_dhparam /etc/nginx/dhparam.pem;
END
    
    # Restart Nginx
    systemctl restart nginx
    
    echo -e "${GREEN}SSL security configured successfully!${NC}"
}

# Function: Show Menu
show_menu() {
    echo -e "\n${YELLOW}Security Menu:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e " [${GREEN}1${NC}] Configure Firewall"
    echo -e " [${GREEN}2${NC}] Configure Fail2Ban"
    echo -e " [${GREEN}3${NC}] SSL Security"
    echo -e " [${GREEN}4${NC}] Show Banned IPs"
    echo -e " [${GREEN}5${NC}] Unban IP"
    echo -e " [${GREEN}x${NC}] Back to Main Menu"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Main Function
main() {
    while true; do
        show_menu
        read -p "Select menu: " choice
        case $choice in
            1) configure_firewall ;;
            2) configure_fail2ban ;;
            3) configure_ssl ;;
            4) fail2ban-client status ;;
            5) 
                read -p "Enter IP to unban: " ip
                fail2ban-client set sshd unbanip $ip
                ;;
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