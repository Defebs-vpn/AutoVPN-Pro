#!/bin/bash
# Auto Script Install VPN - Full Service
# Created by: Defebs-vpn
# Created on: 2025-02-17 19:47:57
# Version: 9.0 Enterprise

# Installation Directory
INSTALL_DIR="/etc/AutoVPN-Pro"
DOMAIN="sc.defebs-vpn.my.id"
MYIP=$(curl -sS ipv4.icanhazip.com)
UUID1=$(cat /proc/sys/kernel/random/uuid)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
clear
echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        AUTO SCRIPT INSTALL VPN             ║${NC}"
echo -e "${BLUE}║     SSH WS - XRAY - MULTI PROTOCOL        ║${NC}"
echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
echo -e "${YELLOW}Created by${NC}: Defebs-vpn"
echo -e "${YELLOW}Version${NC}   : 9.0 Enterprise"
echo -e "${YELLOW}Date${NC}      : 2025-02-17 19:47:57"

# Check Root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Initial Setup
initial_setup() {
    # Update System
    apt update
    apt upgrade -y
    apt install -y wget curl jq unzip git

    # Set Timezone
    timedatectl set-timezone Asia/Jakarta

    # Install Required Packages
    apt install -y \
        apache2 php php-mysql mariadb-server \
        nginx certbot python3-certbot-nginx \
        fail2ban net-tools vnstat \
        build-essential nodejs npm \
        iptables-persistent netfilter-persistent \
        speedtest-cli neofetch htop

    # Enable and start services
    systemctl enable apache2
    systemctl enable nginx
    systemctl enable mariadb
    systemctl enable fail2ban

    # Create Installation Directory
    mkdir -p ${INSTALL_DIR}/{conf,cert,xray,ssh,backup}
}

# Domain Setup
setup_domain() {
    echo -e "\n${CYAN}[INFO]${NC} Setting up domain..."
    
    # Ask for domain
    read -p "Enter your domain: " DOMAIN
    
    # Update DNS A record
    echo -e "${YELLOW}Please ensure your domain's A record points to: ${MYIP}${NC}"
    echo -e "${YELLOW}Press enter when ready...${NC}"
    read
    
    # Install SSL Certificate
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email dedefebriansyah402@gmail.com \
        --redirect --hsts --staple-ocsp
    
    # Create SSL Directory
    mkdir -p /etc/ssl/$DOMAIN
    cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/ssl/$DOMAIN/
    cp /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/ssl/$DOMAIN/
}

# Install SSH WebSocket
setup_ssh_ws() {
    echo -e "\n${CYAN}[INFO]${NC} Setting up SSH WebSocket..."
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << END
Port 22
Port 2222
AddressFamily inet
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/ssh/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
END

    # Create SSH Banner
    cat > /etc/ssh/banner << END
═══════════════════════════════════════════
          PREMIUM SSH SERVICE
        Created by: Defebs-vpn
═══════════════════════════════════════════
END

    # Setup WebSocket
    cat > /etc/nginx/conf.d/ws.conf << END
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    location / {
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
END

    # Create WebSocket Service
    cat > /usr/local/bin/ws-service << END
#!/usr/bin/python3
import socket, threading, _thread, select, signal, sys, time
LISTENING_PORT = 2082
LISTENING_ADDR = '0.0.0.0'
PASS = ''

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
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print('- No X-Real-Host!')
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
            pass
        finally:
            self.close()
            self.server.removeConn(self)

def main():
    print("\n:-------PythonProxy-------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('\nStopping...')
            server.close()
            break

if __name__ == '__main__':
    main()
END
    chmod +x /usr/local/bin/ws-service

    # Create Service
    cat > /etc/systemd/system/ws-service.service << END
[Unit]
Description=SSH WebSocket Service
Documentation=https://defebs-vpn.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 /usr/local/bin/ws-service
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

    systemctl daemon-reload
    systemctl enable ws-service
    systemctl restart ws-service
}

#!/bin/bash
# X-Ray Installation and Configuration
# Created by: Defebs-vpn
# Created on: 2025-02-17 19:52:23

# Install X-Ray Core
install_xray() {
    echo -e "\n${CYAN}[INFO]${NC} Installing X-Ray Core..."

    # Download X-Ray Core
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # Create X-Ray Directories
    mkdir -p /usr/local/etc/xray
    mkdir -p /var/log/xray
    
    # Generate Random UUIDs
    UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid)
    UUID_SS=$(cat /proc/sys/kernel/random/uuid)
    
    # Generate Random Paths
    VMESS_PATH="/$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
    VLESS_PATH="/$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
    TROJAN_PATH="/$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
    SS_PATH="/$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"

    # Configure X-Ray
    cat > /usr/local/etc/xray/config.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VMESS}",
            "alterId": 0,
            "email": "vmess@${DOMAIN}"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "${VMESS_PATH}",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8442,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS}",
            "email": "vless@${DOMAIN}"
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
              "certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "${VLESS_PATH}",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8441,
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
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "${TROJAN_PATH}",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8444,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "chacha20-poly1305",
            "password": "${UUID_SS}",
            "email": "ss@${DOMAIN}"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
            }
          ]
        },
        "wsSettings": {
          "path": "${SS_PATH}",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
END

    # Configure Nginx for X-Ray
    cat > /etc/nginx/conf.d/xray.conf << END
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.2 TLSv1.3;

    location ${VMESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location ${VLESS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8442;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location ${TROJAN_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8441;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location ${SS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
END

    # Start Services
    systemctl restart xray
    systemctl restart nginx
    
    # Save Configurations
    echo "Saving configurations..."
    mkdir -p ${INSTALL_DIR}/xray
    cat > ${INSTALL_DIR}/xray/config.txt << END
Domain: ${DOMAIN}
Port Details:
------------
VMess: 8443
VLESS: 8442
Trojan: 8441
Shadowsocks: 8444

VMess Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VMESS}
AlterID: 0
Security: auto
Network: ws
Path: ${VMESS_PATH}
TLS: true

VLESS Configuration:
------------------
Address: ${DOMAIN}
Port: 443
UUID: ${UUID_VLESS}
Network: ws
Path: ${VLESS_PATH}
TLS: true

Trojan Configuration:
-------------------
Address: ${DOMAIN}
Port: 443
Password: ${UUID_TROJAN}
Network: ws
Path: ${TROJAN_PATH}
TLS: true

Shadowsocks Configuration:
-----------------------
Address: ${DOMAIN}
Port: 443
Method: chacha20-poly1305
Password: ${UUID_SS}
Path: ${SS_PATH}
TLS: true
END

    echo -e "${GREEN}X-Ray installation completed!${NC}"
}

#!/bin/bash
# Final Setup and Configuration
# Created by: Defebs-vpn
# Created on: 2025-02-17 19:59:32

# Setup Additional Features and Finalization
setup_additional() {
    echo -e "\n${CYAN}[INFO]${NC} Setting up additional features..."

    # Setup Database
    mysql -e "CREATE DATABASE IF NOT EXISTS vpn_panel;"
    mysql -e "CREATE USER IF NOT EXISTS 'vpnadmin'@'localhost' IDENTIFIED BY 'DefebsVPN2025!';"
    mysql -e "GRANT ALL PRIVILEGES ON vpn_panel.* TO 'vpnadmin'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"

    # Create Database Tables
    mysql vpn_panel << EOF
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(128),
    protocol ENUM('ssh', 'vmess', 'vless', 'trojan', 'ss') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TIMESTAMP NOT NULL,
    bandwidth_limit BIGINT DEFAULT 0,
    bandwidth_used BIGINT DEFAULT 0,
    status ENUM('active', 'suspended', 'expired') DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    upload BIGINT DEFAULT 0,
    download BIGINT DEFAULT 0,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS connection_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45),
    protocol VARCHAR(20),
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
EOF

    # Setup Auto Backup
    cat > /usr/local/bin/auto-backup << END
#!/bin/bash
# Backup Script
BACKUP_DIR="/root/backup"
DATE=\$(date +"%Y-%m-%d_%H-%M-%S")
RETENTION_DAYS=7

# Create backup directory
mkdir -p \$BACKUP_DIR

# Backup Database
mysqldump -u vpnadmin -pDefebsVPN2025! vpn_panel > \$BACKUP_DIR/database_\${DATE}.sql

# Backup Configurations
zip -r \$BACKUP_DIR/config_\${DATE}.zip \
    /etc/xray \
    /etc/nginx \
    /etc/ssh \
    ${INSTALL_DIR} \
    /usr/local/etc/xray

# Remove old backups
find \$BACKUP_DIR -type f -mtime +\$RETENTION_DAYS -delete

# Log backup
echo "Backup completed on \$(date)" >> /var/log/vpn_backup.log
END
    chmod +x /usr/local/bin/auto-backup

    # Schedule Auto Backup
    echo "0 0 * * * root /usr/local/bin/auto-backup" > /etc/cron.d/auto-backup

    # Setup Auto Clean
    cat > /usr/local/bin/auto-clean << END
#!/bin/bash
# Auto Clean Script

# Clean expired users
mysql -u vpnadmin -pDefebsVPN2025! vpn_panel -e "
    UPDATE users SET status = 'expired' 
    WHERE expired_at < NOW() AND status = 'active';"

# Remove expired users from services
mysql -u vpnadmin -pDefebsVPN2025! vpn_panel -N -e "
    SELECT username, protocol FROM users 
    WHERE status = 'expired'" | while read username protocol; do
    case \$protocol in
        "ssh")
            pkill -u \$username
            userdel -f \$username
            ;;
        *)
            # Remove from XRay config
            sed -i "/\$username/d" /usr/local/etc/xray/config.json
            ;;
    esac
done

# Restart services
systemctl restart xray

# Clear system cache
sync; echo 3 > /proc/sys/vm/drop_caches
END
    chmod +x /usr/local/bin/auto-clean

    # Schedule Auto Clean
    echo "0 * * * * root /usr/local/bin/auto-clean" > /etc/cron.d/auto-clean

    # Create Restore Script
    cat > /usr/local/bin/restore-system << END
#!/bin/bash
# System Restore Script

if [ -z "\$1" ]; then
    echo "Usage: \$0 <backup_file>"
    exit 1
fi

BACKUP_FILE="\$1"

if [ ! -f "\$BACKUP_FILE" ]; then
    echo "Backup file not found!"
    exit 1
fi

# Stop services
systemctl stop nginx xray

# Restore configurations
unzip -o "\$BACKUP_FILE" -d /

# Restore database
mysql -u vpnadmin -pDefebsVPN2025! vpn_panel < database_*.sql

# Restart services
systemctl restart nginx xray

echo "System restored successfully!"
END
    chmod +x /usr/local/bin/restore-system

    # Create Update Script
    cat > /usr/local/bin/update-system << END
#!/bin/bash
# System Update Script

# Update system packages
apt update
apt upgrade -y

# Update X-Ray
bash -c "\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Update SSL certificates
certbot renew --force-renewal

# Restart services
systemctl restart nginx xray

echo "System updated successfully!"
END
    chmod +x /usr/local/bin/update-system

    # Schedule System Update
    echo "0 0 * * 0 root /usr/local/bin/update-system" > /etc/cron.d/update-system
}

# Show completion message and credentials
show_complete() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        INSTALLATION COMPLETED!              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    echo -e "Domain          : ${DOMAIN}"
    echo -e "IP Address      : ${MYIP}"
    echo -e ""
    echo -e "Port Information:"
    echo -e "- SSH           : 22, 2222"
    echo -e "- SSH WS        : 80, 443"
    echo -e "- VMess         : 8443"
    echo -e "- VLESS         : 8442"
    echo -e "- Trojan        : 8441"
    echo -e "- Shadowsocks   : 8444"
    echo -e ""
    echo -e "Credentials have been saved to:"
    echo -e "${INSTALL_DIR}/credentials.txt"
    echo -e ""
    echo -e "Panel URL       : http://${DOMAIN}/panel"
    echo -e "Panel Username  : admin"
    echo -e "Panel Password  : ${UUID1}"
    echo -e ""
    echo -e "Created by      : Defebs-vpn"
    echo -e "Created on      : 2025-02-17 19:59:32"
    echo -e "${BLUE}═════════════════════════════════════════════${NC}"
}

# Main Installation Process
main() {
    initial_setup
    setup_domain
    setup_ssh_ws
    install_xray
    setup_additional
    setup_security
    create_main_menu
    show_complete
}

# Start Installation
main
