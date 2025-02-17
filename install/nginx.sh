#!/bin/bash
# Nginx Installer
# Created by: Defebs-vpn
# Created on: 2025-02-17 08:25:01

# Source variable
source /etc/AutoVPN-Pro/core/vars.conf

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function: Install Nginx
install_nginx() {
    echo -e "${CYAN}[INFO]${NC} Installing Nginx..."
    apt install -y nginx
    
    # Configure Nginx
    cat > /etc/nginx/nginx.conf << END
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
END
    
    # Create default virtual host
    cat > /etc/nginx/conf.d/default.conf << END
server {
    listen 81;
    listen [::]:81;
    
    root /var/www/html;
    index index.html index.htm;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
END
    
    # Create custom error pages
    cat > /var/www/html/index.html << END
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to AutoVPN-Pro</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>
    <h1>Welcome to AutoVPN-Pro</h1>
    <p>Server is online and running.</p>
    <p><em>Created by Defebs-vpn</em></p>
</body>
</html>
END
    
    # Test Nginx configuration
    nginx -t
    
    # Restart Nginx
    systemctl restart nginx
}

# Function: Install SSL
install_ssl() {
    echo -e "${CYAN}[INFO]${NC} Installing SSL Certificate..."
    
    # Get domain
    domain=$(cat /root/domain)
    
    # Stop Nginx
    systemctl stop nginx
    
    # Get SSL certificate
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --email admin@$domain -d $domain
    
    # Start Nginx
    systemctl start nginx
}

# Main Function
main() {
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}"
        exit 1
    }
    
    echo -e "${BLUE}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         INSTALLING NGINX SERVER             ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════╝${NC}"
    
    # Start Installation
    install_nginx
    install_ssl
    
    echo -e "${GREEN}[OK]${NC} Nginx Installation Completed!"
}

# Run main function
main