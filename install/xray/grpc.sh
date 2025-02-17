#!/bin/bash
# XRay gRPC Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:38:19

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install gRPC
install_grpc() {
    echo -e "${CYAN}[INFO]${NC} Configuring gRPC..."
    
    # Get domain and UUID
    domain=$(cat /root/domain)
    uuid=$(cat /usr/local/etc/xray/uuid.txt)
    
    # Create gRPC Configuration
    cat > /usr/local/etc/xray/grpc.json << END
{
    "inbounds": [
        {
            "port": 8444,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "alterId": 0,
                        "email": "vmess-grpc@${domain}"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/${domain}/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/${domain}/privkey.pem"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "vmess-grpc"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        },
        {
            "port": 8445,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "email": "vless-grpc@${domain}"
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
                            "certificateFile": "/etc/letsencrypt/live/${domain}/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/${domain}/privkey.pem"
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
            "port": 8446,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "trojan-grpc@${domain}"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/${domain}/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/${domain}/privkey.pem"
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
    ]
}
END

    # Merge Configuration
    cat /usr/local/etc/xray/grpc.json | jq -s '.[0].inbounds + .[1].inbounds' > /tmp/inbounds.json
    jq --argjson inbounds "$(cat /tmp/inbounds.json)" '.inbounds = $inbounds' /usr/local/etc/xray/config.json > /tmp/config.json
    mv /tmp/config.json /usr/local/etc/xray/config.json

    # Configure Nginx for gRPC
    cat > /etc/nginx/conf.d/grpc.conf << END
server {
    listen 443 ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:8444;
        grpc_set_header X-Real-IP \$remote_addr;
    }

    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:8445;
        grpc_set_header X-Real-IP \$remote_addr;
    }

    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:8446;
        grpc_set_header X-Real-IP \$remote_addr;
    }
}
END

    # Restart Services
    systemctl restart nginx
    systemctl restart xray
    
    echo -e "${GREEN}[OK]${NC} gRPC Configuration Completed!"
    
    # Show Configuration
    echo -e "\ngRPC Configuration:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain          : ${domain}"
    echo -e "VMess Port     : 8444"
    echo -e "VLESS Port     : 8445"
    echo -e "Trojan Port    : 8446"
    echo -e "UUID/Password  : ${uuid}"
    echo -e "Network        : grpc"
    echo -e "ServiceName    : vmess-grpc"
    echo -e "               : vless-grpc"
    echo -e "               : trojan-grpc"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
}

# Main Function
main() {
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    }
    
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLING GRPC SERVICE             ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_grpc
}

# Run main function
main