#!/bin/bash
# AutoVPN-Pro Installer
# Created by: Defebs-vpn
# Created on: 2025-02-16 22:59:35

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
INFO="${BLUE}[INFO]${NC}"
ERROR="${RED}[ERROR]${NC}"
OKEY="${GREEN}[OKEY]${NC}"

# Repository URL
REPO="https://raw.githubusercontent.com/Defebs-vpn/AutoVPN-Pro/main"

# Directories
SCRIPT_DIR="/etc/AutoVPN-Pro"
CORE_DIR="$SCRIPT_DIR/core"
INSTALL_DIR="$SCRIPT_DIR/install"
CONFIG_DIR="$SCRIPT_DIR/config"
MENU_DIR="$SCRIPT_DIR/menu"
MODULES_DIR="$SCRIPT_DIR/modules"

# Create required directories
mkdir -p "$SCRIPT_DIR"
mkdir -p "$CORE_DIR"
mkdir -p "$INSTALL_DIR"/{xray,websocket}
mkdir -p "$CONFIG_DIR"/{nginx,xray,websocket}
mkdir -p "$MENU_DIR"
mkdir -p "$MODULES_DIR"

# Download Core Files
echo -e "${INFO} Downloading core files..."
wget -q "$REPO/core/info.sh" -O "$CORE_DIR/info.sh"
wget -q "$REPO/core/vars.conf" -O "$CORE_DIR/vars.conf"
wget -q "$REPO/core/version.conf" -O "$CORE_DIR/version.conf"

# Download Installation Files
echo -e "${INFO} Downloading installation files..."
wget -q "$REPO/install/dependencies.sh" -O "$INSTALL_DIR/dependencies.sh"
wget -q "$REPO/install/nginx.sh" -O "$INSTALL_DIR/nginx.sh"
wget -q "$REPO/install/ssh.sh" -O "$INSTALL_DIR/ssh.sh"

# Download XRay Installation Files
echo -e "${INFO} Downloading XRay files..."
wget -q "$REPO/install/xray/core.sh" -O "$INSTALL_DIR/xray/core.sh"
wget -q "$REPO/install/xray/vmess.sh" -O "$INSTALL_DIR/xray/vmess.sh"
wget -q "$REPO/install/xray/vless.sh" -O "$INSTALL_DIR/xray/vless.sh"
wget -q "$REPO/install/xray/trojan.sh" -O "$INSTALL_DIR/xray/trojan.sh"
wget -q "$REPO/install/xray/grpc.sh" -O "$INSTALL_DIR/xray/grpc.sh"

# Download WebSocket Files
echo -e "${INFO} Downloading WebSocket files..."
wget -q "$REPO/install/websocket/tls.sh" -O "$INSTALL_DIR/websocket/tls.sh"
wget -q "$REPO/install/websocket/nontls.sh" -O "$INSTALL_DIR/websocket/nontls.sh"

# Download Config Files Nginx
echo -e "${INFO} Downloading Config files Nginx..."
wget -q "$REPO/config/nginx/nginx.conf" -O "$CONFIG_DIR/nginx/nginx.conf"
wget -q "$REPO/config/nginx/xray.conf" -O "$CONFIG_DIR/nginx/xray.conf"
wget -q "$REPO/config/nginx/ws.conf" -O "$CONFIG_DIR/nginx/ws.conf"

# Download Config Files Xray
echo -e "${INFO} Downloading Config files Xray..."
wget -q "$REPO/config/xray/config.json" -O "$CONFIG_DIR/xray/config.json"
wget -q "$REPO/config/xray/vmess.json" -O "$CONFIG_DIR/xray/vmess.json"
wget -q "$REPO/config/xray/vless.json" -O "$CONFIG_DIR/xray/vless.json"
wget -q "$REPO/config/xray/trojan.json" -O "$CONFIG_DIR/xray/trojan.json"
wget -q "$REPO/config/xray/grpc.json" -O "$CONFIG_DIR/xray/grpc.json"

# Download Config Files Websocket
echo -e "${INFO} Downloading Config files Websocket..."
wget -q "$REPO/config/websocket/tls.json" -O "$CONFIG_DIR/websocket/tls.json"
wget -q "$REPO/config/websocket/nontls.json" -O "$CONFIG_DIR/websocket/nontls.json"

# Download Menu Files
echo -e "${INFO} Downloading menu files..."
wget -q "$REPO/menu/panel.sh" -O "$MENU_DIR/panel.sh"
wget -q "$REPO/menu/account.sh" -O "$MENU_DIR/account.sh"
wget -q "$REPO/menu/system.sh" -O "$MENU_DIR/system.sh"
wget -q "$REPO/menu/tools.sh" -O "$MENU_DIR/tools.sh"

# Download Module Files
echo -e "${INFO} Downloading module files..."
wget -q "$REPO/modules/bandwidth.sh" -O "$MODULES_DIR/bandwidth.sh"
wget -q "$REPO/modules/backup.sh" -O "$MODULES_DIR/backup.sh"
wget -q "$REPO/modules/monitor.sh" -O "$MODULES_DIR/monitor.sh"
wget -q "$REPO/modules/security.sh" -O "$MODULES_DIR/security.sh"

# Set permissions
chmod +x "$CORE_DIR"/*.sh
chmod +x "$INSTALL_DIR"/*.sh
chmod +x "$INSTALL_DIR"/xray/*.sh
chmod +x "$INSTALL_DIR"/websocket/*.sh
chmod +x "$CONFIG_DIR"/nginx/*.conf
chmod +x "$CONFIG_DIR"/xray/*.json
chmod +x "$CONFIG_DIR"/websocket/*.json
chmod +x "$MENU_DIR"/*.sh
chmod +x "$MODULES_DIR"/*.sh

# Run installation
clear
echo -e "${CYAN}╔═════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         AUTOVPN-PRO INSTALLER              ║${NC}"
echo -e "${CYAN}╚═════════════════════════════════════════════╝${NC}"
echo -e " Version    : $(cat $CORE_DIR/version.conf)"
echo -e " Created by : Defebs-vpn"
echo -e " Created on : 2025-02-16 22:59:35"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"

# Get domain
echo -ne "\nEnter your domain: "
read domain
echo "$domain" > "$CONFIG_DIR/domain"

# Start installation
echo -e "\n${INFO} Starting installation...\n"

# Install dependencies
bash "$INSTALL_DIR/dependencies.sh"

# Install Nginx
bash "$INSTALL_DIR/nginx.sh"

# Install SSH
bash "$INSTALL_DIR/ssh.sh"

# Install XRay
bash "$INSTALL_DIR/xray/core.sh"
bash "$INSTALL_DIR/xray/vmess.sh"
bash "$INSTALL_DIR/xray/vless.sh"
bash "$INSTALL_DIR/xray/trojan.sh"
bash "$INSTALL_DIR/xray/grpc.sh"

# Install WebSocket
bash "$INSTALL_DIR/websocket/tls.sh"
bash "$INSTALL_DIR/websocket/nontls.sh"

# Configure Security
bash "$MODULES_DIR/bandwidth.sh"
bash "$MODULES_DIR/backup.sh"
bash "$MODULES_DIR/monitor.sh"
bash "$MODULES_DIR/security.sh"

# Create menu shortcut
cat > /usr/local/bin/menu <<EOF
#!/bin/bash
bash "$MENU_DIR/panel.sh"
EOF
chmod +x /usr/local/bin/menu

# Installation completed
clear
echo -e "${CYAN}╔═════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         INSTALLATION COMPLETED              ║${NC}"
echo -e "${CYAN}╚═════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${GREEN}AutoVPN-Pro has been installed successfully!${NC}"
echo -e ""
echo -e "Type ${GREEN}menu${NC} to access VPN Manager"
echo -e ""
echo -e "Server will reboot in 10 seconds..."
sleep 10
reboot
