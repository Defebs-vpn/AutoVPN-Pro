#!/bin/bash
# Xray Multi-Protocol Installer Script
# Author: Defebs-vpn
# Created: 2025-02-19 15:01:57 UTC

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored text
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root"
    exit 1
fi

# Update system
print_status "Updating system..."
apt-get update
apt-get upgrade -y

# Install required packages
print_status "Installing required packages..."
apt-get install -y \
    curl \
    socat \
    wget \
    apt-transport-https \
    gnupg2 \
    cron \
    nginx \
    unzip \
    qrencode \
    python3 \
    python3-pip

# Install acme.sh
print_status "Installing acme.sh..."
curl https://get.acme.sh | sh
source ~/.bashrc

# Get domain name
read -p "Enter your domain name: " DOMAIN

# Install SSL certificate
print_status "Installing SSL certificate for $DOMAIN..."
mkdir -p /usr/local/etc/xray/ssl
~/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d ${DOMAIN} \
    --key-file /usr/local/etc/xray/ssl/${DOMAIN}.key \
    --fullchain-file /usr/local/etc/xray/ssl/${DOMAIN}.crt \
    --ecc

# Setup auto renewal for SSL
cat > /etc/cron.d/acme-renew << EOF
0 0 * * * root /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null
EOF

# Install Xray Core
print_status "Installing Xray Core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Create necessary directories
mkdir -p /usr/local/etc/xray
mkdir -p /var/log/xray

# Generate UUIDs for different services
UUID_VMESS_WS_TLS=$(xray uuid)
UUID_VMESS_WS_NONTLS=$(xray uuid)
UUID_VMESS_GRPC=$(xray uuid)
UUID_VLESS_WS_TLS=$(xray uuid)
UUID_VLESS_WS_NONTLS=$(xray uuid)
UUID_VLESS_GRPC=$(xray uuid)
UUID_TROJAN_WS=$(xray uuid)
UUID_TROJAN_GFW=$(xray uuid)
UUID_TROJAN_GRPC=$(xray uuid)
UUID_SS=$(xray uuid)
UUID_SS_GRPC=$(xray uuid)

# Generate a random password for Shadowsocks
SS_PASSWORD=$(openssl rand -base64 16)
SS_METHOD="chacha20-ietf-poly1305"

# Create Xray config
cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VMESS_WS_TLS}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess-ws-tls"
        }
      }
    },
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VMESS_WS_NONTLS}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VMESS_GRPC}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      }
    },
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS_WS_TLS}"
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
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless-ws-tls"
        }
      }
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS_WS_NONTLS}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      }
    },
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_VLESS_GRPC}"
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
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      }
    },
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${UUID_TROJAN_WS}"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    },
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${UUID_TROJAN_GFW}"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        }
      }
    },
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${UUID_TROJAN_GRPC}"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      }
    },
    {
      "port": 443,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "password": "${SS_PASSWORD}",
            "method": "${SS_METHOD}"
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        }
      }
    },
    {
      "port": 443,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "password": "${SS_PASSWORD}",
            "method": "${SS_METHOD}"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/ssl/${DOMAIN}.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "ss-grpc"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

# Configure Nginx
cat > /etc/nginx/conf.d/${DOMAIN}.conf << EOF
server {
    listen 80;
    listen [::]:80;
    return 301 https://${DOMAIN}\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    
    ssl_certificate /usr/local/etc/xray/ssl/${DOMAIN}.crt;
    ssl_certificate_key /usr/local/etc/xray/ssl/${DOMAIN}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # All WebSocket Paths
    location /vmess-ws-tls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /vless-ws-tls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # gRPC configuration
    location ^~ /vmess-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:443;
    }

    location ^~ /vless-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:443;
    }

    location ^~ /trojan-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host \$http_host;
        grpc_pass grpc://127.0.0.1:443;
    }

    location ^~ /ss-grpc {
        proxy_redirect off;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Host $http_host;
        grpc_pass grpc://127.0.0.1:443;
    }
}
EOF

# Set proper permissions
chmod 644 /usr/local/etc/xray/config.json
chmod 644 /etc/nginx/conf.d/${DOMAIN}.conf

# Enable and start services
systemctl enable nginx
systemctl enable xray
systemctl restart nginx
systemctl restart xray

print_status "Installation completed successfully!"
