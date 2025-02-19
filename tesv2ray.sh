#!/bin/bash
# Auto Script Install VPN
# (c) 2025 Defebs-vpn
# Installation Date: 2025-02-19 19:02:19

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'

# System Settings
MYIP=$(wget -qO- ipinfo.io/ip)
DOMAIN=""
UUID=$(cat /proc/sys/kernel/random/uuid)
TROJAN_UUID=$(cat /proc/sys/kernel/random/uuid)

# Installation paths
V2RAY_CONFIG="/usr/local/etc/v2ray"
NGINX_CONFIG="/etc/nginx"
CERT_DIR="/etc/v2ray/cert"
V2RAY_LOG="/var/log/v2ray"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Initial system setup
apt update
apt upgrade -y
apt install -y curl socat nginx unzip python3-pip uuid-runtime wget netfilter-persistent

# Install V2Ray
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Create directories
mkdir -p ${V2RAY_CONFIG}
mkdir -p ${CERT_DIR}
mkdir -p ${V2RAY_LOG}

# Setup domain
echo -e "${YELLOW}Enter your domain:${NC}"
read -rp "Domain: " -e DOMAIN
echo "$DOMAIN" > /etc/v2ray/domain

# Install SSL certificate
curl https://get.acme.sh | sh -s email=admin@${DOMAIN}
~/.acme.sh/acme.sh --register-account -m admin@${DOMAIN}
~/.acme.sh/acme.sh --issue -d ${DOMAIN} --standalone --keylength ec-256
~/.acme.sh/acme.sh --install-cert -d ${DOMAIN} \
    --key-file ${CERT_DIR}/v2ray.key \
    --fullchain-file ${CERT_DIR}/v2ray.crt \
    --ecc

chmod 644 ${CERT_DIR}/v2ray.crt
chmod 644 ${CERT_DIR}/v2ray.key

# Configure V2Ray
cat > ${V2RAY_CONFIG}/config.json << EOF
{
  "log": {
    "access": "${V2RAY_LOG}/access.log",
    "error": "${V2RAY_LOG}/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": "${UUID}"}]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vmess"}
      }
    },
    {
      "port": 10001,
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": "${UUID}"}]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "wsSettings": {"path": "/vmess"}
      }
    },
    {
      "port": 10004,
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": "${UUID}"}]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "grpcSettings": {"serviceName": "vmess-grpc"}
      }
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vless"}
      }
    },
    {
      "port": 10002,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "wsSettings": {"path": "/vless"}
      }
    },
    {
      "port": 10005,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${UUID}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "grpcSettings": {"serviceName": "vless-grpc"}
      }
    },
    {
      "port": 10007,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": "${TROJAN_UUID}"}]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        }
      }
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": "${TROJAN_UUID}"}]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "wsSettings": {"path": "/trojan"}
      }
    },
    {
      "port": 10006,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": "${TROJAN_UUID}"}]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "${CERT_DIR}/v2ray.crt",
            "keyFile": "${CERT_DIR}/v2ray.key"
          }]
        },
        "grpcSettings": {"serviceName": "trojan-grpc"}
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
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Configure Nginx
cat > ${NGINX_CONFIG}/conf.d/v2ray.conf << EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_DIR}/v2ray.crt;
    ssl_certificate_key ${CERT_DIR}/v2ray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # WebSocket (VMess, VLESS, Trojan)
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_buffering off;
    }

    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_buffering off;
    }

    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_buffering off;
    }

    # gRPC (VMess, VLESS, Trojan)
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:10004;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }

    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:10005;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }

    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10006;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }

 stream {
    upstream trojan_backend {
        server 127.0.0.1:10007;
    }

    server {
        listen 443;
        proxy_pass trojan_backend;
        proxy_protocol on;
    }
}
EOF

# Start services
systemctl enable v2ray
systemctl restart v2ray
systemctl restart nginx

# Show installation info
clear
echo -e "${GREEN}V2Ray Installation Completed!${NC}"
echo -e "${YELLOW}=========================${NC}"
echo -e "Domain: ${DOMAIN}"
echo -e "UUID: ${UUID}"
echo -e "Trojan Password: ${TROJAN_UUID}"
echo -e "\nVMess Configuration:"
echo -e "- Non-TLS: ws://${DOMAIN}:80/vmess"
echo -e "- TLS: wss://${DOMAIN}:443/vmess"
echo -e "- gRPC: grpc://${DOMAIN}:443/vmess-grpc"
echo -e "\nVLESS Configuration:"
echo -e "- Non-TLS: ws://${DOMAIN}:80/vless"
echo -e "- TLS: wss://${DOMAIN}:443/vless"
echo -e "- gRPC: grpc://${DOMAIN}:443/vless-grpc"
echo -e "\nTrojan Configuration:"
echo -e "- TCP: trojan://${DOMAIN}:443"
echo -e "- WebSocket: trojan://${DOMAIN}:443/trojan"
echo -e "- gRPC: trojan://${DOMAIN}:443/trojan-grpc"
echo -e "\nInstallation Date: 2025-02-19 19:02:19"
echo -e "${YELLOW}=========================${NC}"
