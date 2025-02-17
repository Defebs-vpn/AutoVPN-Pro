#!/bin/bash
# XRay VLESS Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:32:29

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install VLESS
install_vless() {
    echo -e "${CYAN}[INFO]${NC} Configuring VLESS..."
    
    # Get domain and UUID
    domain=$(cat /root/domain)
    uuid=$(cat /usr/local/etc/xray/uuid.txt)
    
    # Create VLESS Configuration
    cat > /usr/local/etc/xray/vless.json << END
{
    "inbounds": [
        {
            "port": 8442,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": "xtls-rprx-direct",
                        "email": "vless@${domain}"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 80
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/${domain}/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/${domain}/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless",
                    "headers": {
                        "Host": "${domain}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "email": "vless@${domain}"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless",
                    "headers": {
                        "Host": "${domain}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ]
}
END

    # Merge Configuration
    cat /usr/local/etc/xray/vless.json | jq -s '.[0].inbounds + .[1].inbounds' > /tmp/inbounds.json
    jq --argjson inbounds "$(cat /tmp/inbounds.json)" '.inbounds = $inbounds' /usr/local/etc/xray/config.json > /tmp/config.json
    mv /tmp/config.json /usr/local/etc/xray/config.json

    # Restart XRay
    systemctl restart xray
    
    echo -e "${GREEN}[OK]${NC} VLESS Configuration Completed!"
    
    # Show Configuration
    echo -e "\nVLESS Configuration:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain       : ${domain}"
    echo -e "Port TLS    : 8442"
    echo -e "Port NTLS   : 80"
    echo -e "UUID        : ${uuid}"
    echo -e "Network     : ws"
    echo -e "Path        : /vless"
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
    echo -e "${BLUE}║         INSTALLING VLESS SERVICE            ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_vless
}

# Run main function
main