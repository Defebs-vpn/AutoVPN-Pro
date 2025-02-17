#!/bin/bash
# WebSocket Non-TLS Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:42:40

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Function: Install WebSocket Non-TLS
install_ws_nontls() {
    echo -e "${CYAN}[INFO]${NC} Configuring WebSocket Non-TLS..."
    
    # Create WebSocket Service Directory
    mkdir -p /usr/local/bin/websocket
    
    # Create WebSocket Non-TLS Service
    cat > /usr/local/bin/websocket/ws-nontls.py << END
import asyncio
import websockets
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='/var/log/websocket-nontls.log'
)

LISTEN_PORT = 80
SSH_PORT = 22

async def ssh_proxy(websocket, path):
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', SSH_PORT)
        
        async def forward_ws_to_ssh():
            try:
                while True:
                    data = await websocket.recv()
                    writer.write(data)
                    await writer.drain()
            except Exception as e:
                logging.error(f"Error forwarding WS to SSH: {e}")
                writer.close()
                
        async def forward_ssh_to_ws():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await websocket.send(data)
            except Exception as e:
                logging.error(f"Error forwarding SSH to WS: {e}")
                await websocket.close()
                
        await asyncio.gather(
            forward_ws_to_ssh(),
            forward_ssh_to_ws()
        )
    except Exception as e:
        logging.error(f"Connection error: {e}")

start_server = websockets.serve(
    ssh_proxy,
    '0.0.0.0',
    LISTEN_PORT,
    ping_interval=None,
    compression=None
)

logging.info(f"WebSocket Non-TLS Server starting on port {LISTEN_PORT}")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
END

    # Create Service
    cat > /etc/systemd/system/ws-nontls.service << END
[Unit]
Description=WebSocket Non-TLS Service
Documentation=https://github.com/Defebs-vpn/AutoVPN-Pro
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 /usr/local/bin/websocket/ws-nontls.py
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END

    # Start Service
    systemctl daemon-reload
    systemctl enable ws-nontls
    systemctl start ws-nontls
    
    echo -e "${GREEN}[OK]${NC} WebSocket Non-TLS Configuration Completed!"
    
    # Show Configuration
    echo -e "\nWebSocket Non-TLS Configuration:"
    echo -e "━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Port       : 80"
    echo -e "Path       : /websocket"
    echo -e "TLS        : false"
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
    echo -e "${BLUE}║    INSTALLING WEBSOCKET NON-TLS SERVICE     ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_ws_nontls
}

# Run main function
main