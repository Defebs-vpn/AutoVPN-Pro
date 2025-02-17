#!/bin/bash
# AutoVPN-Pro Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 09:09:38

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation Directory
INSTALL_DIR="/etc/AutoVPN-Pro"
CORE_DIR="$INSTALL_DIR/core"

# Function: Show Banner
show_banner() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           AUTOVPN-PRO INSTALLER            ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    echo -e " Created by: ${GREEN}Defebs-vpn${NC}"
    echo -e " Version  : ${GREEN}1.0${NC}"
    echo -e "${BLUE}═════════════════════════════════════════════${NC}"
}

# Function: Check Requirements
check_requirements() {
    echo -e "\n${YELLOW}Checking Requirements...${NC}"
    
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root!${NC}"
        exit 1
    fi
    
    # Check OS
    if [[ ! -e /etc/debian_version ]]; then
        echo -e "${RED}This script only works on Debian/Ubuntu!${NC}"
        exit 1
    fi
    
    # Check Domain
    if [[ -z $DOMAIN ]]; then
        read -p "Enter your domain: " DOMAIN
        echo $DOMAIN > /root/domain
    fi
}

# Function: Install Dependencies
install_dependencies() {
    echo -e "\n${YELLOW}Installing Dependencies...${NC}"
    
    apt update
    apt upgrade -y
    apt install -y \
        curl wget jq uuid-runtime certbot python3-certbot-nginx \
        nginx socat netfilter-persistent vnstat fail2ban \
        iptables-persistent net-tools neofetch chrony \
        python3 python3-pip
        
    pip3 install speedtest-cli
}

# Function: Install SSL Certificate
install_ssl() {
    echo -e "\n${YELLOW}Installing SSL Certificate...${NC}"
    
    systemctl stop nginx
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --email admin@$DOMAIN -d $DOMAIN
    systemctl start nginx
}

# Function: Install Core Services
install_core() {
    echo -e "\n${YELLOW}Installing Core Services...${NC}"
    
    # Create installation directory
    mkdir -p $INSTALL_DIR/{core,install,config,menu,modules}
    
    # Install XRay
    bash install/xray/core.sh
    bash install/xray/vmess.sh
    bash install/xray/vless.sh
    bash install/xray/trojan.sh
    bash install/xray/grpc.sh
    
    # Install WebSocket
    bash install/websocket/tls.sh
    bash install/websocket/nontls.sh
    
    # Configure Services
    cp -r config/nginx/* /etc/nginx/
    cp -r config/xray/* /usr/local/etc/xray/
    cp -r config/websocket/* /usr/local/bin/websocket/
}

# Function: Configure System
configure_system() {
    echo -e "\n${YELLOW}Configuring System...${NC}"
    
    # Set timezone
    timedatectl set-timezone Asia/Jakarta
    
    # Enable BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    
    # Configure firewall
    bash modules/security.sh --configure-firewall
    
    # Configure fail2ban
    bash modules/security.sh --configure-fail2ban
    
    # Configure SSL security
    bash modules/security.sh --configure-ssl
}

# Function: Create Menu
create_menu() {
    echo -e "\n${YELLOW}Creating Menu...${NC}"
    
    # Copy menu files
    cp -r menu/* /usr/local/bin/
    chmod +x /usr/local/bin/*
    
    # Create menu command
    echo '#!/bin/bash' > /usr/local/bin/menu
    echo 'bash /etc/AutoVPN-Pro/menu/panel.sh' >> /usr/local/bin/menu
    chmod +x /usr/local/bin/menu
}

# Function: Show Installation Complete
show_complete() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLATION COMPLETED              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    echo -e "\n${YELLOW}Installation Details:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain    : $DOMAIN"
    echo -e "IP        : $(curl -s ipv4.icanhazip.com)"
    echo -e "\n${YELLOW}Service Ports:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "SSH       : 22"
    echo -e "SSL/TLS   : 443"
    echo -e "VMess     : 8443"
    echo -e "VLESS     : 8442"
    echo -e "Trojan    : 8441"
    echo -e "gRPC      : 8444"
    echo -e "\n${YELLOW}Command:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Type ${GREEN}menu${NC} to access control panel"
    echo -e "${BLUE}═════════════════════════════════════════════${NC}"
}

# Main Function
main() {
    # Show banner
    show_banner
    
    # Start installation
    check_requirements
    install_dependencies
    install_ssl
    install_core
    configure_system
    create_menu
    show_complete
}

# Run main function
main