#!/bin/bash
# XRay VMess Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:32:29

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install VMess
install_vmess() {
    echo -e "${CYAN}[INFO]${NC} Configuring VMess..."
    
    # Get domain and UUID
    domain=$(cat /root/domain)
    uuid=$(cat /usr/local/etc/xray/uuid.txt)
    
    # Create VMess Configuration
    cat > /usr/local/etc/xray/vmess.json << END
{
    "inbounds": [
        {
            "port": 8443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "alterId": 0,
                        "email": "vmess@${domain}"
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
                    "path": "/vmess",
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
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "alterId": 0,
                        "email": "vmess@${domain}"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess",
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
    cat /usr/local/etc/xray/vmess.json | jq -s '.[0].inbounds + .[1].inbounds' > /tmp/inbounds.json
    jq --argjson inbounds "$(cat /tmp/inbounds.json)" '.inbounds = $inbounds' /usr/local/etc/xray/config.json > /tmp/config.json
    mv /tmp/config.json /usr/local/etc/xray/config.json

    # Restart XRay
    systemctl restart xray
    
    echo -e "${GREEN}[OK]${NC} VMess Configuration Completed!"
    
    # Show Configuration
    echo -e "\nVMess Configuration:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Domain       : ${domain}"
    echo -e "Port TLS    : 8443"
    echo -e "Port NTLS   : 80"
    echo -e "UUID        : ${uuid}"
    echo -e "Alter ID    : 0"
    echo -e "Network     : ws"
    echo -e "Path        : /vmess"
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
    echo -e "${BLUE}║         INSTALLING VMESS SERVICE            ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_vmess
}

# Run main function
main