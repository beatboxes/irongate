#!/bin/bash
# Irongate Emergency Fix - Fixes all web UI issues
# Run with: sudo bash irongate-fix.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  Irongate Emergency Fix${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Must be root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Run as root: sudo bash irongate-fix.sh${NC}"
    exit 1
fi

# Detect PHP version
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
if [ -z "$PHP_VERSION" ]; then
    echo -e "${RED}PHP not found!${NC}"
    exit 1
fi
echo -e "PHP Version: ${GREEN}$PHP_VERSION${NC}"

PHP_FPM_SERVICE="php${PHP_VERSION}-fpm"
PHP_SOCK="/run/php/php${PHP_VERSION}-fpm.sock"

# Fix 1: Ensure PHP-FPM is running
echo -e "${YELLOW}[1/5] Starting PHP-FPM...${NC}"
systemctl enable $PHP_FPM_SERVICE 2>/dev/null
systemctl restart $PHP_FPM_SERVICE
sleep 2

if [ ! -S "$PHP_SOCK" ]; then
    echo -e "${RED}  Socket not found at $PHP_SOCK${NC}"
    echo -e "${YELLOW}  Checking for socket...${NC}"
    PHP_SOCK=$(find /run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
    if [ -z "$PHP_SOCK" ]; then
        PHP_SOCK=$(find /var/run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
    fi
    if [ -n "$PHP_SOCK" ]; then
        echo -e "${GREEN}  Found socket: $PHP_SOCK${NC}"
    else
        echo -e "${RED}  No PHP-FPM socket found! Check: systemctl status $PHP_FPM_SERVICE${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}  ✓ PHP-FPM running, socket: $PHP_SOCK${NC}"

# Fix 2: Fix nginx config with correct socket path
echo -e "${YELLOW}[2/5] Fixing nginx config...${NC}"
cat > /etc/nginx/sites-available/irongate << EOF
server {
    listen 80;
    server_name _;
    root /var/www/irongate;
    index index.html;
    
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
    client_max_body_size 10M;
    
    location / { try_files \$uri \$uri/ =404; }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
        fastcgi_connect_timeout 10s;
        fastcgi_send_timeout 30s;
        fastcgi_read_timeout 30s;
    }
    
    location ~ /\.ht { deny all; }
    
    location /health {
        access_log off;
        return 200 "OK";
        add_header Content-Type text/plain;
    }
}
EOF

ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null

# Test nginx config
if nginx -t 2>&1 | grep -q "successful"; then
    echo -e "${GREEN}  ✓ nginx config valid${NC}"
else
    echo -e "${RED}  nginx config error:${NC}"
    nginx -t
    exit 1
fi

# Fix 3: Fix permissions
echo -e "${YELLOW}[3/5] Fixing permissions...${NC}"

# Web directory
chown -R www-data:www-data /var/www/irongate
chmod -R 755 /var/www/irongate
chmod 666 /var/www/irongate/dhcp.db 2>/dev/null

# Config directories
mkdir -p /etc/irongate
chown root:www-data /etc/irongate
chmod 775 /etc/irongate
touch /etc/irongate/config.yaml
chown root:www-data /etc/irongate/config.yaml
chmod 664 /etc/irongate/config.yaml

# dnsmasq configs
chown www-data:www-data /etc/dnsmasq.conf 2>/dev/null
chmod 664 /etc/dnsmasq.conf 2>/dev/null
chown -R www-data:www-data /etc/dnsmasq.d 2>/dev/null
chmod -R 775 /etc/dnsmasq.d 2>/dev/null

echo -e "${GREEN}  ✓ Permissions fixed${NC}"

# Fix 4: Patch api.php to prevent JSON corruption
echo -e "${YELLOW}[4/5] Patching api.php...${NC}"

if [ -f /var/www/irongate/api.php ]; then
    if ! grep -q "error_reporting(0)" /var/www/irongate/api.php; then
        # Create new header
        cat > /tmp/api_header.php << 'EOFPHP'
<?php
// Suppress warnings/notices from corrupting JSON output
error_reporting(0);
ini_set('display_errors', 0);

set_error_handler(function($severity, $message, $file, $line) {
    error_log("Irongate API: $message in $file:$line");
    return true;
});

EOFPHP
        # Remove old <?php and prepend new header
        tail -n +2 /var/www/irongate/api.php > /tmp/api_body.php
        cat /tmp/api_header.php /tmp/api_body.php > /var/www/irongate/api.php
        rm -f /tmp/api_header.php /tmp/api_body.php
        chown www-data:www-data /var/www/irongate/api.php
        echo -e "${GREEN}  ✓ api.php patched${NC}"
    else
        echo -e "${GREEN}  ✓ api.php already patched${NC}"
    fi
else
    echo -e "${RED}  api.php not found!${NC}"
fi

# Fix 5: Restart services
echo -e "${YELLOW}[5/5] Restarting services...${NC}"
systemctl restart $PHP_FPM_SERVICE
systemctl restart nginx
systemctl restart dnsmasq 2>/dev/null || true

# Verify
sleep 2
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Status:${NC}"
echo -e "  nginx:      $(systemctl is-active nginx)"
echo -e "  php-fpm:    $(systemctl is-active $PHP_FPM_SERVICE)"
echo -e "  dnsmasq:    $(systemctl is-active dnsmasq)"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Test web server
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/health" | grep -q "200"; then
    echo -e "${GREEN}  ✓ Web server responding${NC}"
    echo ""
    echo -e "  Access Irongate at: ${GREEN}http://${SERVER_IP}/${NC}"
else
    echo -e "${RED}  ✗ Web server not responding${NC}"
    echo ""
    echo -e "  Check logs:"
    echo -e "    journalctl -u nginx -n 20"
    echo -e "    journalctl -u $PHP_FPM_SERVICE -n 20"
fi
echo ""
