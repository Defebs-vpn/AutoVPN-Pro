#!/bin/bash
# AutoVPN-Pro Premium Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 13:48:07

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global Variables
MYIP=$(wget -qO- ipinfo.io/ip)
GITHUB_CMD="https://raw.githubusercontent.com/Defebs-vpn/AutoVPN-Pro/main"
INSTALL_DIR="/etc/AutoVPN-Pro"
TIMEZONE="Asia/Jakarta"
INSTALL_DATE="2025-02-17 13:48:07"

# Banner Function
show_banner() {
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       AUTOVPN-PRO PREMIUM INSTALLER        ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    echo -e " ${YELLOW}Created by${NC}: Defebs-vpn"
    echo -e " ${YELLOW}Version${NC}   : 4.0 Premium"
    echo -e " ${YELLOW}Date${NC}      : $INSTALL_DATE"
    echo -e "${BLUE}═════════════════════════════════════════════${NC}"
}

# Initial Setup
setup_initial() {
    echo -e "\n${CYAN}[INFO]${NC} Performing initial setup..."
    
    # Set timezone
    timedatectl set-timezone $TIMEZONE
    
    # Disable IPv6
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    
    # Update System
    apt update
    apt upgrade -y
    apt dist-upgrade -y
    apt autoremove -y
    
    # Install Dependencies
    apt install -y \
        curl wget jq uuid-runtime certbot python3-certbot-nginx \
        nginx socat netfilter-persistent vnstat fail2ban \
        iptables-persistent net-tools neofetch chrony \
        python3 python3-pip zip unzip tar cron \
        squid stunnel4 ruby screen cmake make \
        gcc automake autoconf build-essential \
        resolvconf pwgen openssl iftop htop \
        speedtest-cli nload dropbear openssh-server
}

# Domain Setup
setup_domain() {
    echo -e "\n${CYAN}[INFO]${NC} Setting up domain..."
    
    read -p "Enter your domain: " domain
    if [[ -z $(dig +short $domain) ]]; then
        echo -e "${RED}Error: Invalid domain or DNS not propagated${NC}"
        exit 1
    fi
    
    echo "$domain" > /root/domain
    DOMAIN=$domain
    
    # Install SSL
    systemctl stop nginx
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --email dedefebriansyah402@gmail.com -d $DOMAIN
    systemctl start nginx
}

# SSH WebSocket Setup
setup_ssh_ws() {
    echo -e "\n${CYAN}[INFO]${NC} Setting up SSH WebSocket..."
    
    # Generate SSH Keys
    ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa
    ssh-keygen -f /etc/ssh/ssh_host_dsa_key -N '' -t dsa
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << END
Port 22
Port 2222
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
END
    
    # Setup WebSocket
    cat > /usr/local/bin/ws-ssh << END
#!/usr/bin/python3
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 2082

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
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
        intport = int(self.port)
        self.soc.bind((self.host, intport))
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

    def printLog(self, log):
        self.logLock.acquire()
        print(log)
        self.logLock.release()

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

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
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

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print("\n:-------PythonProxy-------:\n")
    print("Listening addr: " + LISTENING_ADDR)
    print("Listening port: " + str(LISTENING_PORT) + "\n")
    print(":-------------------------:\n")
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

    chmod +x /usr/local/bin/ws-ssh
    
    # Create Service
    cat > /etc/systemd/system/ws-ssh.service << END
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
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ssh
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

    systemctl daemon-reload
    systemctl enable ws-ssh
    systemctl restart ws-ssh
}

# XRay Installation
setup_xray() {
    echo -e "\n${CYAN}[INFO]${NC} Installing XRay Multi Protocol..."
    
    # Install XRay Core
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Create XRay Config Directory
    mkdir -p /usr/local/etc/xray
    
    # Generate UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Create XRay Main Config
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
            "id": "${UUID}",
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
          "path": "/vmess",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      }
    },
    {
      "port": 8442,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
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
          "path": "/vless",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      }
    },
    {
      "port": 8441,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${UUID}",
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
          "path": "/trojan",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
      }
    },
    {
      "port": 8444,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "chacha20-poly1305",
            "password": "${UUID}",
            "email": "shadowsocks@${DOMAIN}"
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
          "path": "/shadowsocks",
          "headers": {
            "Host": "${DOMAIN}"
          }
        }
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

# Create XRay Service
    cat > /etc/systemd/system/xray.service << END
[Unit]
Description=XRay Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END

    # Start XRay Service
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
}

    # Create Client Configs
    mkdir -p /etc/AutoVPN-Pro/client-config
    
    # VMess Config
    cat > /etc/AutoVPN-Pro/client-config/vmess-config.json << END
{
  "v": "2",
  "ps": "VMess-${DOMAIN}",
  "add": "${DOMAIN}",
  "port": "443",
  "id": "${UUID}",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "${DOMAIN}",
  "path": "/vmess",
  "tls": "tls",
  "sni": "${DOMAIN}"
}
END

    # VLESS Config
    cat > /etc/AutoVPN-Pro/client-config/vless-config.txt << END
====== VLESS Configuration ======
Protocol: VLESS
Address: ${DOMAIN}
Port: 443
UUID: ${UUID}
Network: ws
Security: tls
Path: /vless
SNI: ${DOMAIN}
TLS: Required
============================
END

    # Trojan Config
    cat > /etc/AutoVPN-Pro/client-config/trojan-config.txt << END
====== Trojan Configuration ======
Protocol: Trojan
Address: ${DOMAIN}
Port: 443
Password: ${UUID}
Network: ws
Security: tls
Path: /trojan
SNI: ${DOMAIN}
TLS: Required
============================
END

    # Shadowsocks Config
    cat > /etc/AutoVPN-Pro/client-config/shadowsocks-config.txt << END
====== Shadowsocks Configuration ======
Server: ${DOMAIN}
Port: 443
Password: ${UUID}
Method: chacha20-poly1305
Path: /shadowsocks
Plugin: v2ray-plugin
Plugin-Opts: tls;host=${DOMAIN};path=/shadowsocks
============================
END

    # Configure Nginx for XRay
    cat > /etc/nginx/conf.d/xray.conf << END
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.2 TLSv1.3;

    # WebSocket
    location /ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # VMess
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    # VLESS
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8442;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    # Trojan
    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8441;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    # Shadowsocks
    location /shadowsocks {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
END

    # Restart Services
    systemctl restart xray
    systemctl restart nginx
}

# System Configuration
setup_system() {
    echo -e "\n${CYAN}[INFO]${NC} Configuring system optimization..."
    
    # BBR Configuration
    cat > /etc/sysctl.conf << END
# TCP BBR Configuration
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_default = 524288
net.core.wmem_default = 524288
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_slow_start_after_idle = 0
END

    sysctl -p

    # Configure Fail2Ban
    cat > /etc/fail2ban/jail.local << END
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh,22,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-badbots]
enabled = true
filter = nginx-badbots
port = http,https
logpath = /var/log/nginx/access.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log

[nginx-deny]
enabled = true
filter = nginx-deny
port = http,https
logpath = /var/log/nginx/error.log
END

    systemctl restart fail2ban

    # Configure Speedtest Schedule
    cat > /usr/local/bin/speedtest-cron << END
#!/bin/bash
echo "=============================================="
echo "Speed Test - \$(date)"
echo "=============================================="
speedtest-cli --simple
echo "=============================================="
END

    chmod +x /usr/local/bin/speedtest-cron
    
    # Add to crontab
    echo "0 */6 * * * root /usr/local/bin/speedtest-cron >> /var/log/speedtest.log" > /etc/cron.d/speedtest

    # Configure Auto Backup
    cat > /usr/local/bin/autobackup << END
#!/bin/bash
# AutoVPN-Pro Backup Script
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Backup Directory
BACKUP_DIR="/root/backup"
mkdir -p \$BACKUP_DIR

# Timestamp
DATE=\$(date +"%Y-%m-%d_%H-%M-%S")

# Create backup
cd \$BACKUP_DIR
zip -r "backup_\${DATE}.zip" /etc/AutoVPN-Pro /etc/nginx/conf.d /usr/local/etc/xray /etc/cron.d
find \$BACKUP_DIR -type f -mtime +7 -name '*.zip' -delete

# Log
echo "Backup completed: backup_\${DATE}.zip" >> /var/log/vpn-backup.log
END

    chmod +x /usr/local/bin/autobackup
    echo "0 0 * * * root /usr/local/bin/autobackup" > /etc/cron.d/autobackup
}

# Menu System
setup_menu() {
    echo -e "\n${CYAN}[INFO]${NC} Creating menu system..."
    
    # Main Menu
    cat > /usr/local/bin/menu << END
#!/bin/bash
# AutoVPN-Pro Main Menu
clear
echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             AUTOVPN-PRO MENU               ║${NC}"
echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
echo -e " ${YELLOW}1${NC}. User Management"
echo -e " ${YELLOW}2${NC}. Server Information"
echo -e " ${YELLOW}3${NC}. Monitor Bandwidth"
echo -e " ${YELLOW}4${NC}. Speed Test"
echo -e " ${YELLOW}5${NC}. Backup & Restore"
echo -e " ${YELLOW}6${NC}. System Settings"
echo -e " ${YELLOW}7${NC}. Security Settings"
echo -e " ${YELLOW}8${NC}. Update Script"
echo -e " ${YELLOW}x${NC}. Exit"
echo -e "${BLUE}═════════════════════════════════════════════${NC}"
read -p "Select menu: " menu_option

case \$menu_option in
    1) user-menu ;;
    2) server-info ;;
    3) bw-monitor ;;
    4) speedtest-cli --simple ;;
    5) backup-menu ;;
    6) system-menu ;;
    7) security-menu ;;
    8) update-script ;;
    x) exit ;;
    *) echo -e "${RED}Invalid option!${NC}" ; sleep 2 ; menu ;;
esac
END

    # User Management Menu
    cat > /usr/local/bin/user-menu << END
#!/bin/bash
clear
echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           USER MANAGEMENT MENU              ║${NC}"
echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
echo -e " ${YELLOW}1${NC}. Add User"
echo -e " ${YELLOW}2${NC}. Delete User"
echo -e " ${YELLOW}3${NC}. List Users"
echo -e " ${YELLOW}4${NC}. Monitor Users"
echo -e " ${YELLOW}5${NC}. Lock User"
echo -e " ${YELLOW}6${NC}. Unlock User"
echo -e " ${YELLOW}7${NC}. Back to Main Menu"
echo -e "${BLUE}═════════════════════════════════════════════${NC}"
read -p "Select menu: " user_option

case \$user_option in
    1) add-user ;;
    2) del-user ;;
    3) list-user ;;
    4) monitor-user ;;
    5) lock-user ;;
    6) unlock-user ;;
    7) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" ; sleep 2 ; user-menu ;;
esac
END

    # Make all scripts executable
    chmod +x /usr/local/bin/{menu,user-menu}
}

# Main Installation Function
main() {
    # Show Banner
    show_banner
    
    # Create Installation Directory
    mkdir -p ${INSTALL_DIR}/{core,install,config,menu,modules}
    
    # Run Installation Steps
    setup_initial
    setup_domain
    setup_ssh_ws
    setup_xray
    setup_system
    setup_menu
    
    # Show Installation Complete
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLATION COMPLETED              ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${YELLOW}Installation Details:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain    : ${DOMAIN}"
    echo -e "IP        : ${MYIP}"
    echo -e "Date      : $(date)"
    
    echo -e "\n${YELLOW}Service Ports:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "SSH       : 22, 2222"
    echo -e "SSL/TLS   : 443"
    echo -e "WS-SSH    : 2082"
    echo -e "VMess     : 8443"
    echo -e "VLESS     : 8442"
    echo -e "Trojan    : 8441"
    echo -e "SS        : 8444"
    
    echo -e "\n${YELLOW}Features Installed:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "✓ Multi Protocol Support"
    echo -e "✓ WebSocket + TLS"
    echo -e "✓ Auto SSL Certificate"
    echo -e "✓ BBR Optimization"
    echo -e "✓ Anti-DDoS Protection"
    echo -e "✓ Fail2Ban Security"
    echo -e "✓ Auto Backup System"
    echo -e "✓ Bandwidth Monitor"
    echo -e "✓ User Management"
    echo -e "✓ Speed Test Tool"
    
    echo -e "\n${YELLOW}Command Menu:${NC}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Type ${GREEN}menu${NC} to access control panel"
    
    echo -e "\n${BLUE}═════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation completed! System will reboot in 15 seconds...${NC}"
    
    # Save installation log
    cat > ${INSTALL_DIR}/installed.txt << END
Installation Date: $(date)
Domain: ${DOMAIN}
IP: ${MYIP}
Version: 4.0
Created by: Defebs-vpn
END

    sleep 15
    reboot
}

# Run main installation
main 2>&1 | tee -a /root/vpn-install.log
