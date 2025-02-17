#!/bin/bash
# XRay Core Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:32:29

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install XRay Core
install_xray() {
    echo -e "${CYAN}[INFO]${NC} Installing XRay Core..."
    
    # Download XRay Core Installer
    wget -q -O /root/xray.sh "https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"
    chmod +x /root/xray.sh
    bash /root/xray.sh install
    
    # Create XRay Config Directory
    mkdir -p /usr/local/etc/xray
    mkdir -p /var/log/xray
    
    # Generate UUID
    uuid=$(cat /proc/sys/kernel/random/uuid)
    echo "$uuid" > /usr/local/etc/xray/uuid.txt
    
    # Configure XRay Core
    cat > /usr/local/etc/xray/config.json << END
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
                "statsUserUplink": true,
                "statsUserDownlink": true
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    },
    "inbounds": [],
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

# Main Function
main() {
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    }
    
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLING XRAY CORE                ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_xray
    
    echo -e "${GREEN}[OK]${NC} XRay Core Installation Completed!"
}

# Run main function
main