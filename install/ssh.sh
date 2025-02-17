#!/bin/bash
# SSH Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:25:01

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function: Configure SSH
configure_ssh() {
    echo -e "${CYAN}[INFO]${NC} Configuring SSH..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << END
Port 22
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem   sftp    /usr/lib/openssh/sftp-server
END
    
    # Restart SSH
    systemctl restart ssh
    
    # Enable SSH service
    systemctl enable ssh
}

# Function: Configure Dropbear
install_dropbear() {
    echo -e "${CYAN}[INFO]${NC} Installing Dropbear..."
    
    # Install Dropbear
    apt install -y dropbear
    
    # Configure Dropbear
    cat > /etc/default/dropbear << END
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RECEIVE_WINDOW=65536
END
    
    # Create banner
    cat > /etc/banner << END
<b>AutoVPN-Pro Premium Server</b>
Created by: Defebs-vpn
Created on: 2025-02-17 08:25:01

- NO SPAM
- NO DDOS
- NO HACKING
- NO CARDING
- NO TORRENT
- NO MULTI LOGIN
- NO PORN/18+

Breaking any rules will result in account termination
END
    
    # Restart Dropbear
    systemctl restart dropbear
}

# Function: Configure Stunnel
install_stunnel() {
    echo -e "${CYAN}[INFO]${NC} Installing Stunnel..."
    
    # Install Stunnel
    apt install -y stunnel4
    
    # Get certificate
    domain=$(cat /root/domain)
    
    # Configure Stunnel
    cat > /etc/stunnel/stunnel.conf << END
pid = /var/run/stunnel.pid
cert = /etc/letsencrypt/live/$domain/fullchain.pem
key = /etc/letsencrypt/live/$domain/privkey.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 447
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:22
END
    
    # Enable Stunnel
    sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    
    # Restart Stunnel
    systemctl restart stunnel4
}

# Main Function
main() {
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    }
    
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLING SSH SERVICE              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    configure_ssh
    install_dropbear
    install_stunnel
    
    echo -e "${GREEN}[OK]${NC} SSH Installation Completed!"
    
    # Show SSH Information
    echo -e "\nSSH Information:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "SSH Port     : 22"
    echo -e "Dropbear    : 109, 143"
    echo -e "SSL/TLS     : 447, 777"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Run main function
main