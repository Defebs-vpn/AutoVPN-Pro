#!/bin/bash
# Nginx Reverse Proxy Configuration
# Created by: Defebs-vpn
# Date: 2025-02-20 14:25:25
# Version: 4.0

# Set variables
NGINX_CONFIG="/etc/nginx/conf.d"
SSL_DIR="/etc/ssl/${DOMAIN}"
LOG_DIR="/var/log/nginx"

# Create Nginx configuration
cat > ${NGINX_CONFIG}/${DOMAIN}.conf <<EOF
# Main Configuration
log_format proxy '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                '\$status \$body_bytes_sent "\$http_referer" '
                '"\$http_user_agent" "\$http_x_forwarded_for"';

# HTTP Server (Redirect to HTTPS)
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    access_log ${LOG_DIR}/access.log proxy;
    error_log ${LOG_DIR}/error.log;
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
    
    # Allow WebSocket without TLS
    location /vmess-nontls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    
    access_log ${LOG_DIR}/access-ssl.log proxy;
    error_log ${LOG_DIR}/error-ssl.log;
    
    # SSL Configuration
    ssl_certificate ${SSL_DIR}/fullchain.crt;
    ssl_certificate_key ${SSL_DIR}/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Root Directory
    root /var/www/html;
    index index.html index.htm;
    
    # Default Location
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # SSH WebSocket
    location /ssh-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60;
        proxy_send_timeout 60;
        proxy_read_timeout 60;
        proxy_buffer_size 64k;
        proxy_buffers 8 64k;
        proxy_busy_buffers_size 128k;
    }
    
    # VMess WebSocket
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60;
        proxy_send_timeout 60;
        proxy_read_timeout 60;
    }
    
    # VLESS WebSocket
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8442;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60;
        proxy_send_timeout 60;
        proxy_read_timeout 60;
    }
    
    # Trojan WebSocket
    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 60;
        proxy_send_timeout 60;
        proxy_read_timeout 60;
    }
    
    # gRPC Configuration
    location ^~ /vless-grpc {
        grpc_pass grpc://127.0.0.1:8444;
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location ^~ /vmess-grpc {
        grpc_pass grpc://127.0.0.1:8445;
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location ^~ /trojan-grpc {
        grpc_pass grpc://127.0.0.1:8446;
        grpc_connect_timeout 60s;
        grpc_read_timeout 60s;
        grpc_send_timeout 60s;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Status Page (Protected)
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
    
    # PHP Configuration (if needed)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}

# Additional Server Block for Control Panel (Optional)
server {
    listen 8585 ssl http2;
    server_name ${DOMAIN};
    
    ssl_certificate ${SSL_DIR}/fullchain.crt;
    ssl_certificate_key ${SSL_DIR}/private.key;
    
    root /var/www/html/panel;
    index index.php index.html;
    
    # Basic Authentication
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
    }
}
EOF

# Create optimized Nginx main configuration
cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Logging Settings
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    
    # Buffer Settings
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    proxy_buffer_size 64k;
    proxy_buffers 8 64k;
    proxy_busy_buffers_size 128k;
    
    # Timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
EOF

# Create basic authentication for panel
echo -n "admin:" > /etc/nginx/.htpasswd
openssl passwd -apr1 "your_password" >> /etc/nginx/.htpasswd

# Set proper permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# Test and reload Nginx
nginx -t && systemctl reload nginx

echo "Nginx configuration completed successfully!"