#!/bin/bash
# Dependencies Installer
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

# Function: Update System
update_system() {
    echo -e "${CYAN}[INFO]${NC} Updating System..."
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    apt autoremove -y
    apt clean -y
}

# Function: Install Required Packages
install_packages() {
    echo -e "${CYAN}[INFO]${NC} Installing Required Packages..."
    apt install -y \
        curl \
        wget \
        uuid-runtime \
        net-tools \
        zip \
        unzip \
        tar \
        git \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        lsb-release \
        ca-certificates \
        gnupg \
        iptables \
        iptables-persistent \
        netfilter-persistent \
        fail2ban \
        socat \
        cron \
        pwgen \
        python3 \
        python3-pip \
        python3-certbot-nginx \
        htop \
        software-properties-common \
        openssl \
        rclone \
        vnstat \
        tree \
        speedtest-cli \
        jq \
        rsync \
        screen \
        cmake \
        libsqlite3-dev \
        sqlite3
}

# Function: Configure Timezone
configure_timezone() {
    echo -e "${CYAN}[INFO]${NC} Configuring Timezone..."
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
}

# Function: Configure Locale
configure_locale() {
    echo -e "${CYAN}[INFO]${NC} Configuring Locale..."
    locale-gen en_US.UTF-8
    update-locale LANG=en_US.UTF-8
}

# Function: Configure BBR
configure_bbr() {
    echo -e "${CYAN}[INFO]${NC} Configuring BBR..."
    cat > /etc/sysctl.conf << END
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
END
    sysctl -p
}

# Function: Configure Fail2Ban
configure_fail2ban() {
    echo -e "${CYAN}[INFO]${NC} Configuring Fail2Ban..."
    cat > /etc/fail2ban/jail.local << END
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[ssh]
enabled = true
port = ssh,22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[ssh-ddos]
enabled = true
port = ssh,22
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
END
    systemctl restart fail2ban
}

# Main Function
main() {
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLING DEPENDENCIES              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    update_system
    install_packages
    configure_timezone
    configure_locale
    configure_bbr
    configure_fail2ban
    
    echo -e "${GREEN}[OK]${NC} Dependencies Installation Completed!"
}

# Run main function
main