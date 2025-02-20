#!/bin/bash
# Multi-Protocol VPN Auto Installation Script
# Created by: Defebs-vpn
# Created on: 2025-02-20 15:21:05
# Version: 4.0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global Variables
MYIP=$(curl -sS ipv4.icanhazip.com)
MYDATE=$(date '+%Y-%m-%d %H:%M:%S')
DOMAIN=""
EMAIL=""

# Installation Paths
BASE_DIR="/etc/Defebs-vpn"
XRAY_DIR="/usr/local/etc/xray"
NGINX_DIR="/etc/nginx/conf.d"
SSL_DIR="/etc/ssl"
LOG_DIR="/var/log/vpn-service"
BACKUP_DIR="/backup"

# Port Configuration
declare -A PORTS=(
    [SSH]=22
    [SSH_WS]=80
    [SSH_WSS]=443
    [DROPBEAR]=85
    [STUNNEL]=443
    [SQUID]=8080
    [XRAY_VMESS_TLS]=443
    [XRAY_VMESS_NONTLS]=80
    [XRAY_VLESS_TLS]=443
    [XRAY_VLESS_NONTLS]=80
    [XRAY_TROJAN_TLS]=443
    [XRAY_VMESS_GRPC]=443
    [XRAY_VLESS_GRPC]=443
    [XRAY_TROJAN_GRPC]=443
)

# Function to show banner
show_banner() {
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ${YELLOW}DEFEBS-VPN AUTO INSTALLER V4.0${GREEN}         ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ ${BLUE}Server     : $MYIP${GREEN}                        ║${NC}"
    echo -e "${GREEN}║ ${BLUE}Date       : $MYDATE${GREEN}            ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
}

# Function to check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Function install Dependensi 
install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    # Update package list
    apt update

    # Upgrade system packages
    echo -e "${YELLOW}Upgrading system packages...${NC}"
    apt upgrade -y
    
    # Install required packages
    echo -e "${YELLOW}Installing essential packages...${NC}"
    apt install -y \
        curl \
        wget \
        git \
        zip \
        unzip \
        tar \
        jq \
        uuid-runtime \
        socat \
        netcat \
        net-tools \
        openssl \
        ca-certificates \
        gnupg \
        gnupg2 \
        software-properties-common \
        apt-transport-https \
        lsb-release \
        nginx \
        python3 \
        python3-pip \
        python3-certbot-nginx \
        cron \
        iptables \
        iptables-persistent \
        fail2ban \
        sysstat \
        vnstat \
        tmux \
        screen \
        neofetch \
        speedtest-cli \
        htop \
        nload \
        tcpdump \
        openssh-server \
        dropbear \
        stunnel4 \
        squid \
        cmake \
        make \
        gcc \
        g++ \
        build-essential \
        mlocate \
        libpcre3 \
        libpcre3-dev \
        zlib1g-dev \
        libssl-dev \
        libsqlite3-dev \
        sqlite3 \
        libxml2-dev \
        libxslt1-dev \
        libjpeg-dev \
        libpng-dev \
        libfreetype6-dev \
        libzip-dev \
        libc6 \
        dbus

    # Install BBR
    echo -e "${YELLOW}Installing BBR...${NC}"
    cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system

    # Install Python packages
    echo -e "${YELLOW}Installing Python packages...${NC}"
    pip3 install \
        requests \
        flask \
        pymysql \
        websockets \
        cryptography \
        python-dotenv \
        psutil

    # Configure Fail2Ban
    echo -e "${YELLOW}Configuring Fail2Ban...${NC}"
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh,22,143
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

    # Configure UFW
    echo -e "${YELLOW}Configuring Firewall...${NC}"
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 143/tcp
    ufw allow 8080/tcp
    ufw allow 8880/tcp
    ufw allow 2082/tcp
    ufw allow 2096/tcp
    echo "y" | ufw enable

    # Configure timezone
    echo -e "${YELLOW}Configuring timezone...${NC}"
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Configure chrony
    echo -e "${YELLOW}Configuring NTP...${NC}"
    apt install -y chrony
    cat > /etc/chrony/chrony.conf <<EOF
pool pool.ntp.org iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
EOF
    systemctl restart chrony

    # Configure system limits
    echo -e "${YELLOW}Configuring system limits...${NC}"
    cat > /etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
* soft nproc 65535
* hard nproc 65535
root soft nproc 65535
root hard nproc 65535
EOF

    # Configure sysctl
    echo -e "${YELLOW}Optimizing system parameters...${NC}"
    cat > /etc/sysctl.d/99-optimizer.conf <<EOF
# Network optimization
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# Security optimization
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Performance optimization
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF
    sysctl --system

    # Create necessary directories
    echo -e "${YELLOW}Creating system directories...${NC}"
    mkdir -p \
        ${BASE_DIR}/{config,scripts,logs,backup,monitor,users} \
        ${XRAY_DIR} \
        ${SSL_DIR} \
        ${LOG_DIR} \
        ${BACKUP_DIR}

    # Set proper permissions
    chmod 755 ${BASE_DIR}
    chmod 700 ${BASE_DIR}/{config,backup}

    # Create log files
    touch ${LOG_DIR}/access.log
    touch ${LOG_DIR}/error.log
    chmod 644 ${LOG_DIR}/*.log

    # Install & Configure vnStat
    echo -e "${YELLOW}Configuring vnStat...${NC}"
    systemctl enable vnstat
    vnstat -u -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    systemctl restart vnstat

    # Enable & start services
    echo -e "${YELLOW}Starting services...${NC}"
    systemctl enable fail2ban
    systemctl enable cron
    systemctl enable nginx
    
    systemctl restart fail2ban
    systemctl restart cron
    systemctl restart nginx

    echo -e "${GREEN}Dependencies installation completed!${NC}"
    echo -e "${YELLOW}System has been optimized and secured${NC}"
}

# Function to get domain
get_domain() {
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ${YELLOW}DOMAIN SETUP AND VALIDATION${GREEN}            ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"

    # Function to validate domain
    validate_domain() {
        local domain=$1
        # Check domain format
        if [[ ! $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${RED}Invalid domain format!${NC}"
            return 1
        }
        
        # Check DNS resolution
        echo -e "${YELLOW}Checking DNS resolution...${NC}"
        local domain_ip=$(dig +short $domain A)
        local current_ip=$(curl -s ipv4.icanhazip.com)
        
        if [[ -z "$domain_ip" ]]; then
            echo -e "${RED}Domain cannot be resolved!${NC}"
            return 1
        fi
        
        if [[ "$domain_ip" != "$current_ip" ]]; then
            echo -e "${RED}Domain IP ($domain_ip) does not match server IP ($current_ip)!${NC}"
            return 1
        }
        
        return 0
    }

    # Function to validate email
    validate_email() {
        local email=$1
        if [[ ! $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
            echo -e "${RED}Invalid email format!${NC}"
            return 1
        fi
        return 0
    }

    # Main domain setup
    while true; do
        echo -e "${YELLOW}Please enter your domain name:${NC}"
        read -p "Domain: " DOMAIN
        
        if validate_domain $DOMAIN; then
            break
        else
            echo -e "${YELLOW}Would you like to:"
            echo -e "1) Try another domain"
            echo -e "2) Create CloudFlare DNS record"
            echo -e "3) Exit${NC}"
            read -p "Choose an option [1-3]: " option
            
            case $option in
                1) continue ;;
                2)
                    echo -e "${YELLOW}Please enter your CloudFlare credentials:${NC}"
                    read -p "Email: " CF_EMAIL
                    read -sp "API Key: " CF_API_KEY
                    echo
                    
                    # Create CloudFlare DNS record
                    echo -e "${YELLOW}Creating DNS record...${NC}"
                    curl -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
                        -H "Authorization: Bearer $CF_API_KEY" \
                        -H "Content-Type: application/json" \
                        --data "{
                            \"type\":\"A\",
                            \"name\":\"$DOMAIN\",
                            \"content\":\"$MYIP\",
                            \"proxied\":false
                        }"
                    
                    echo -e "${YELLOW}Waiting for DNS propagation (60 seconds)...${NC}"
                    sleep 60
                    continue
                    ;;
                3) exit 1 ;;
            esac
        fi
    done

    # Email setup
    while true; do
        echo -e "${YELLOW}Please enter your email address for SSL certificate:${NC}"
        read -p "Email: " EMAIL
        
        if validate_email $EMAIL; then
            break
        fi
    done

    # Save domain information
    echo -e "${YELLOW}Saving domain configuration...${NC}"
    
    # Create domain config directory
    mkdir -p ${BASE_DIR}/config/domain
    
    # Save domain information
    cat > ${BASE_DIR}/config/domain/domain.conf <<EOF
# Domain Configuration
# Created by: Defebs-vpn
# Date: $(date '+%Y-%m-%d %H:%M:%S')
# Last Updated: $(date '+%Y-%m-%d %H:%M:%S')

DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
SERVER_IP="$MYIP"
INSTALLATION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
EOF

    # Create domain check script
    cat > ${BASE_DIR}/scripts/check-domain.sh <<EOF
#!/bin/bash
# Domain Check Script
# Created by: Defebs-vpn
# Date: $(date '+%Y-%m-%d %H:%M:%S')

source ${BASE_DIR}/config/domain/domain.conf

check_domain() {
    local domain_ip=\$(dig +short \$DOMAIN A)
    local current_ip=\$(curl -s ipv4.icanhazip.com)
    
    echo "Domain Check Results"
    echo "==================="
    echo "Domain: \$DOMAIN"
    echo "Expected IP: \$current_ip"
    echo "Resolved IP: \$domain_ip"
    
    if [[ "\$domain_ip" == "\$current_ip" ]]; then
        echo "Status: OK"
    else
        echo "Status: FAILED - IP mismatch!"
    fi
}

check_ssl() {
    if [ -f "${SSL_DIR}/\${DOMAIN}/fullchain.crt" ]; then
        echo -e "\nSSL Certificate Status"
        echo "===================="
        openssl x509 -in "${SSL_DIR}/\${DOMAIN}/fullchain.crt" -text -noout | grep -A 2 "Validity"
    else
        echo -e "\nSSL Certificate not found!"
    fi
}

check_domain
check_ssl
EOF

    chmod +x ${BASE_DIR}/scripts/check-domain.sh

    # Create cron job for domain checking
    echo "0 */6 * * * root ${BASE_DIR}/scripts/check-domain.sh > ${LOG_DIR}/domain-check.log 2>&1" > /etc/cron.d/domain-check

    # Configure hosts file
    echo "$MYIP $DOMAIN" >> /etc/hosts

    echo -e "${GREEN}Domain configuration completed successfully!${NC}"
    echo -e "${YELLOW}Domain: $DOMAIN${NC}"
    echo -e "${YELLOW}Email: $EMAIL${NC}"
    echo -e "${YELLOW}Server IP: $MYIP${NC}"
    echo -e "${YELLOW}Configuration saved to: ${BASE_DIR}/config/domain/domain.conf${NC}"
    echo -e "${YELLOW}Domain checker script: ${BASE_DIR}/scripts/check-domain.sh${NC}"
}

# Function to install SSL
install_ssl() {
    echo -e "${YELLOW}Starting SSL Certificate Installation...${NC}"
    
    # Create directories
    mkdir -p ${SSL_DIR}/${DOMAIN}
    mkdir -p /root/.acme.sh
    
    # Stop services using port 80
    systemctl stop nginx
    systemctl stop apache2 2>/dev/null
    kill $(lsof -t -i:80) 2>/dev/null
    
    echo -e "${YELLOW}Installing acme.sh...${NC}"
    
    # Install socat if not installed
    if ! command -v socat &>/dev/null; then
        apt-get install -y socat
    fi
    
    # Install acme.sh
    curl https://get.acme.sh | sh -s email=${EMAIL}
    
    echo -e "${YELLOW}Obtaining SSL Certificate...${NC}"
    
    # First attempt - Standalone mode
    ~/.acme.sh/acme.sh --issue --standalone \
        -d ${DOMAIN} \
        --keylength ec-384 \
        --server letsencrypt \
        --force

    # Check if certificate was obtained
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Certificate obtained successfully!${NC}"
    else
        echo -e "${RED}Failed to obtain certificate in standalone mode. Trying alternative method...${NC}"
        
        # Second attempt - Webroot mode
        mkdir -p /var/www/html/.well-known/acme-challenge
        chmod -R 755 /var/www/html
        
        ~/.acme.sh/acme.sh --issue \
            -d ${DOMAIN} \
            --webroot /var/www/html \
            --keylength ec-384 \
            --server letsencrypt \
            --force
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to obtain SSL certificate. Please check your domain configuration.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${YELLOW}Installing certificate...${NC}"
    
    # Install certificate
    ~/.acme.sh/acme.sh --install-cert -d ${DOMAIN} \
        --key-file ${SSL_DIR}/${DOMAIN}/private.key \
        --fullchain-file ${SSL_DIR}/${DOMAIN}/fullchain.crt \
        --ecc \
        --reloadcmd "systemctl restart nginx xray"
    
    # Verify certificate installation
    if [ -f "${SSL_DIR}/${DOMAIN}/fullchain.crt" ] && [ -f "${SSL_DIR}/${DOMAIN}/private.key" ]; then
        echo -e "${GREEN}Certificate installed successfully!${NC}"
        
        # Create backup of certificates
        mkdir -p ${BACKUP_DIR}/ssl
        cp ${SSL_DIR}/${DOMAIN}/fullchain.crt ${BACKUP_DIR}/ssl/
        cp ${SSL_DIR}/${DOMAIN}/private.key ${BACKUP_DIR}/ssl/
        
        # Set proper permissions
        chmod 644 ${SSL_DIR}/${DOMAIN}/fullchain.crt
        chmod 600 ${SSL_DIR}/${DOMAIN}/private.key
        
        # Setup auto-renewal
        echo -e "${YELLOW}Setting up auto-renewal...${NC}"
        
        # Create renewal script
        cat > ${BASE_DIR}/scripts/ssl-renew.sh <<EOF
#!/bin/bash
# SSL Certificate Renewal Script
# Created by: Defebs-vpn
# Date: $(date '+%Y-%m-%d %H:%M:%S')

# Stop services
systemctl stop nginx
systemctl stop xray

# Renew certificate
~/.acme.sh/acme.sh --renew -d ${DOMAIN} --force

# Install renewed certificate
~/.acme.sh/acme.sh --install-cert -d ${DOMAIN} \
    --key-file ${SSL_DIR}/${DOMAIN}/private.key \
    --fullchain-file ${SSL_DIR}/${DOMAIN}/fullchain.crt \
    --ecc

# Backup renewed certificates
cp ${SSL_DIR}/${DOMAIN}/fullchain.crt ${BACKUP_DIR}/ssl/
cp ${SSL_DIR}/${DOMAIN}/private.key ${BACKUP_DIR}/ssl/

# Set permissions
chmod 644 ${SSL_DIR}/${DOMAIN}/fullchain.crt
chmod 600 ${SSL_DIR}/${DOMAIN}/private.key

# Start services
systemctl start nginx
systemctl start xray

# Log renewal
echo "Certificate renewed on $(date '+%Y-%m-%d %H:%M:%S')" >> ${LOG_DIR}/ssl-renewal.log
EOF
        
        chmod +x ${BASE_DIR}/scripts/ssl-renew.sh
        
        # Add renewal cron job
        echo "0 0 1 * * root ${BASE_DIR}/scripts/ssl-renew.sh >/dev/null 2>&1" > /etc/cron.d/ssl-renewal
        
        # Create SSL info file
        cat > ${BASE_DIR}/config/ssl-info.txt <<EOF
SSL Certificate Information
=========================
Domain: ${DOMAIN}
Installation Date: $(date '+%Y-%m-%d %H:%M:%S')
Certificate Path: ${SSL_DIR}/${DOMAIN}/fullchain.crt
Private Key Path: ${SSL_DIR}/${DOMAIN}/private.key
Auto-renewal: Enabled (Monthly)
Backup Location: ${BACKUP_DIR}/ssl/
EOF
        
        # Create SSL check function
        cat > ${BASE_DIR}/scripts/check-ssl.sh <<EOF
#!/bin/bash
# SSL Certificate Check Script

domain="${DOMAIN}"
cert="${SSL_DIR}/${DOMAIN}/fullchain.crt"

if [ -f "\$cert" ]; then
    end_date=\$(openssl x509 -enddate -noout -in "\$cert" | cut -d= -f2)
    end_epoch=\$(date -d "\$end_date" +%s)
    current_epoch=\$(date +%s)
    days_left=\$(( (\$end_epoch - \$current_epoch) / 86400 ))
    
    echo "SSL Certificate Status for \$domain"
    echo "================================="
    echo "Expires: \$end_date"
    echo "Days until expiration: \$days_left"
    
    if [ \$days_left -lt 30 ]; then
        echo "WARNING: Certificate will expire soon!"
        ${BASE_DIR}/scripts/ssl-renew.sh
    fi
else
    echo "Certificate file not found!"
fi
EOF
        
        chmod +x ${BASE_DIR}/scripts/check-ssl.sh
        
        # Add daily SSL check
        echo "0 0 * * * root ${BASE_DIR}/scripts/check-ssl.sh >/dev/null 2>&1" > /etc/cron.d/ssl-check
        
        echo -e "${GREEN}SSL installation and configuration completed successfully!${NC}"
        echo -e "${YELLOW}Certificate will be automatically renewed monthly${NC}"
        echo -e "${YELLOW}Daily certificate checks are enabled${NC}"
        echo -e "${YELLOW}SSL information saved to: ${BASE_DIR}/config/ssl-info.txt${NC}"
    else
        echo -e "${RED}Failed to install certificate. Please check the installation logs.${NC}"
        exit 1
    fi
}

# Function to setup SSH WebSocket
setup_ssh_websocket() {
    echo -e "${YELLOW}Setting up SSH WebSocket Service...${NC}"

    # Generate SSH Keys if not exist
    if [ ! -f "/etc/ssh/ssh_host_rsa_key" ]; then
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    fi
    if [ ! -f "/etc/ssh/ssh_host_ed25519_key" ]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi

    # Configure SSH
    cat > /etc/ssh/sshd_config <<EOF
# SSH Server Configuration
Port 22
Port 143
Protocol 2

# HostKeys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
MaxAuthTries 6
MaxSessions 10
LoginGraceTime 2m
ClientAliveInterval 120
ClientAliveCountMax 2
AllowTcpForwarding yes
X11Forwarding yes
PrintMotd no

# Network
AddressFamily any
ListenAddress 0.0.0.0
TCPKeepAlive yes

# Features
Compression yes
UseDNS no

# Logging
SyslogFacility AUTH
LogLevel INFO

# Banner
Banner /etc/issue.net

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Environment
AcceptEnv LANG LC_*
EOF

    # Create SSH WebSocket Python Script
    cat > /usr/local/bin/ws-ssh <<EOF
#!/usr/bin/python3
# SSH WebSocket Proxy
# Created by: Defebs-vpn
# Date: 2025-02-20 15:50:47

import socket
import threading
import select
import sys
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Configuration:
    LISTENING_ADDR = '0.0.0.0'
    LISTENING_PORT_WS = 80
    LISTENING_PORT_WSS = 443
    SSH_PORT = 22
    BUFLEN = 4096 * 4
    TIMEOUT = 300
    DEFAULT_HOST = f'127.0.0.1:{SSH_PORT}'
    RESPONSE = 'HTTP/1.1 101 WebSocket Protocol Handshake\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        try:
            self.soc.bind((self.host, self.port))
            self.soc.listen(0)
            self.running = True
            logger.info(f'Starting server on {self.host}:{self.port}')
        except Exception as e:
            logger.error(f'Error binding to {self.host}:{self.port}: {e}')
            return

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                    logger.info(f'Client connected from {addr}')
                    t = threading.Thread(target=self.handle_client, args=(c, addr))
                    t.start()
                except socket.timeout:
                    continue
        except Exception as e:
            logger.error(f'Error in server loop: {e}')

        self.running = False
        self.soc.close()

    def handle_client(self, client, address):
        try:
            data = client.recv(Configuration.BUFLEN)
            if not data:
                return

            if b'HTTP' in data:
                if b'websocket' in data.lower():
                    client.send(Configuration.RESPONSE.encode())
                    self.handle_websocket(client)
                else:
                    logger.warning(f'Non-WebSocket request from {address}')
                    client.close()
            else:
                self.handle_ssh(client, data)
        except Exception as e:
            logger.error(f'Error handling client {address}: {e}')
            client.close()

    def handle_websocket(self, client):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(('127.0.0.1', Configuration.SSH_PORT))
            
            while True:
                r, w, e = select.select([client, remote], [], [], Configuration.TIMEOUT)
                if not r:
                    break

                for sock in r:
                    other = remote if sock is client else client
                    try:
                        data = sock.recv(Configuration.BUFLEN)
                        if not data:
                            return
                        other.send(data)
                    except:
                        return
        finally:
            client.close()
            remote.close()

    def handle_ssh(self, client, initial_data):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(('127.0.0.1', Configuration.SSH_PORT))
            remote.send(initial_data)

            while True:
                r, w, e = select.select([client, remote], [], [], Configuration.TIMEOUT)
                if not r:
                    break

                for sock in r:
                    other = remote if sock is client else client
                    try:
                        data = sock.recv(Configuration.BUFLEN)
                        if not data:
                            return
                        other.send(data)
                    except:
                        return
        finally:
            client.close()
            remote.close()

def main():
    logger.info('Starting SSH WebSocket Proxy')
    
    # Start WS Server
    server_ws = Server(Configuration.LISTENING_ADDR, Configuration.LISTENING_PORT_WS)
    server_ws.start()
    
    # Start WSS Server
    server_wss = Server(Configuration.LISTENING_ADDR, Configuration.LISTENING_PORT_WSS)
    server_wss.start()
    
    while True:
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            break

    server_ws.running = False
    server_wss.running = False

if __name__ == '__main__':
    main()
EOF

    # Make WebSocket script executable
    chmod +x /usr/local/bin/ws-ssh

    # Create systemd service for SSH WebSocket
    cat > /etc/systemd/system/ws-ssh.service <<EOF
[Unit]
Description=SSH WebSocket Service
After=network.target
Documentation=https://github.com/Defebs-vpn

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ssh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Create SSH Banner
    cat > /etc/issue.net <<EOF
<font color="blue"><b>================================</b></font><br>
<font color="red"><b> PREMIUM SSH WEBSOCKET SERVICE</b></font><br> 
<font color="blue"><b>================================</b></font><br>
<font color="green"><b> Rules: </b></font><br>
<font color="green"><b> ► No DDOS </b></font><br>
<font color="green"><b> ► No Spam </b></font><br>
<font color="green"><b> ► No Bot </b></font><br>
<font color="green"><b> ► Max 2 Device </b></font><br>
<font color="blue"><b>================================</b></font><br>
<font color="red"><b> Auto Reboot Server : 00.00 </b></font><br>
<font color="blue"><b>================================</b></font><br>
<font color="green"><b> Created By: Defebs-vpn </b></font><br>
<font color="blue"><b>================================</b></font><br>
EOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable ssh
    systemctl enable ws-ssh
    systemctl restart ssh
    systemctl restart ws-ssh

    # Save port configurations
    echo "SSH_PORT=22" >> ${BASE_DIR}/config/ports.conf
    echo "SSH_WS_PORT=80" >> ${BASE_DIR}/config/ports.conf
    echo "SSH_WSS_PORT=443" >> ${BASE_DIR}/config/ports.conf

    echo -e "${GREEN}SSH WebSocket installation completed!${NC}"
    echo -e "${YELLOW}SSH Ports: 22, 143${NC}"
    echo -e "${YELLOW}WebSocket Ports: 80 (WS), 443 (WSS)${NC}"
}

# Function to setup Xray with multiple protocols
setup_xray() {
    echo -e "${YELLOW}Setting up Xray Multi-Protocol Service...${NC}"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Generate random UUIDs
    UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_TROJAN=$(openssl rand -hex 16)
    
    # Create Xray config directory
    mkdir -p /usr/local/etc/xray
    
    # Create Xray config
    cat > /usr/local/etc/xray/config.json <<EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "api": {
        "tag": "api",
        "services": [
            "HandlerService",
            "LoggerService",
            "StatsService"
        ]
    },
    "stats": {},
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": true,
                "statsUserDownlink": true,
                "bufferSize": 64
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VMESS}",
                        "alterId": 0,
                        "email": "vmess@${DOMAIN}",
                        "security": "auto"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ],
                    "minVersion": "1.2",
                    "cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                },
                "wsSettings": {
                    "path": "/vmess",
                    "headers": {
                        "Host": "${DOMAIN}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 80,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VMESS}",
                        "alterId": 0,
                        "email": "vmess-nontls@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess-nontls"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VLESS}",
                        "email": "vless@${DOMAIN}",
                        "encryption": "none"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${UUID_VLESS}",
                        "email": "vless-grpc@${DOMAIN}"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "vless-grpc"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${UUID_TROJAN}",
                        "email": "trojan@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${UUID_TROJAN}",
                        "email": "trojan-grpc@${DOMAIN}"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/${DOMAIN}/fullchain.crt",
                            "keyFile": "/etc/ssl/${DOMAIN}/private.key"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "trojan-grpc"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF

    # Create client config file
    cat > ${BASE_DIR}/config/xray-clients.txt <<EOF
X-ray Configuration Details
==========================
Domain: ${DOMAIN}
Last Update: $(date '+%Y-%m-%d %H:%M:%S')

VMess Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VMESS}
AlterID: 0
Security: auto
Network: ws
Path: /vmess
TLS: yes

VMess (Non-TLS):
--------------
Address: ${DOMAIN}
Port: 80
UUID: ${UUID_VMESS}
AlterID: 0
Security: auto
Network: ws
Path: /vmess-nontls
TLS: no

VLESS Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VLESS}
Network: ws
Path: /vless
TLS: yes

VLESS gRPC:
----------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VLESS}
Network: grpc
ServiceName: vless-grpc
TLS: yes

Trojan Configuration:
------------------
Address: ${DOMAIN}
Port: 443
Password: ${UUID_TROJAN}
Network: tcp
TLS: yes

Trojan gRPC:
----------
Address: ${DOMAIN}
Port: 443
Password: ${UUID_TROJAN}
Network: grpc
ServiceName: trojan-grpc
TLS: yes
EOF

    # Set proper permissions
    chmod 644 /usr/local/etc/xray/config.json
    chmod 644 ${BASE_DIR}/config/xray-clients.txt

    # Create log directory
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray

    # Start Xray service
    systemctl enable xray
    systemctl restart xray

    echo -e "${GREEN}Xray has been installed and configured successfully!${NC}"
    echo -e "${YELLOW}Client configuration saved to: ${BASE_DIR}/config/xray-clients.txt${NC}"
}

# Main installation function
main() {
    show_banner
    check_root
    get_domain
    
    echo -e "${YELLOW}Starting installation...${NC}"
    
    install_dependencies
    install_ssl
    setup_ssh_websocket
    setup_xray
    setup_nginx
    setup_additional_services
    
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}Please check /root/vpn-config/credentials.txt for configuration details${NC}"
}

# Start installation
main
