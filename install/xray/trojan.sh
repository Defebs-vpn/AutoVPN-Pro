#!/bin/bash
# XRay Trojan Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:38:19

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install Trojan
install_trojan() {
    echo -e "${CYAN}[INFO]${NC} Configuring Trojan..."
    
    # Get domain and UUID
    domain=$(cat /root/domain)
    uuid=$(cat /usr/local/etc/xray/uuid.txt)
    
    # Create Trojan Configuration
    cat > /usr/local/etc/xray/trojan.json << END
{
    "inbounds": [
        {
            "port": 8443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "trojan@${domain}"
                    }
                ],
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
                    "path": "/trojan",
                    "headers": {
                        "Host": "${domain}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        },
        {
            "port": 2083,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "trojan-ws@${domain}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/trojan-ws",
                    "headers": {
                        "Host": "${domain}"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ]
}
END

    # Merge Configuration
    cat /usr/local/etc/xray/trojan.json | jq -s '.[0].inbounds + .[1].inbounds' > /tmp/inbounds.json
    jq --argjson inbounds "$(cat /tmp/inbounds.json)" '.inbounds = $inbounds' /usr/local/etc/xray/config.json > /tmp/config.json
    mv /tmp/config.json /usr/local/etc/xray/config.json

    # Restart XRay
    systemctl restart xray
    
    echo -e "${GREEN}[OK]${NC} Trojan Configuration Completed!"
    
    # Show Configuration
    echo -e "\nTrojan Configuration:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain       : ${domain}"
    echo -e "Port TLS    : 8443"
    echo -e "Port WS     : 2083"
    echo -e "Password    : ${uuid}"
    echo -e "Network     : ws"
    echo -e "Path        : /trojan, /trojan-ws"
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
    echo -e "${BLUE}║         INSTALLING TROJAN SERVICE           ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_trojan
}

# Run main function
main