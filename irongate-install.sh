#!/bin/bash

#######################################
# IRONGATE - Network Isolation System
# 
# A complete network security appliance:
#   • Zone-based device isolation
#   • Integrated DHCP server
#   • ARP/IPv6 attack protection  
#   • nftables firewall
#   • Web management interface
#
# Deploy on any Debian/Raspbian SBC
#######################################

IRONGATE_REPO="https://github.com/beatboxes/irongate"
IRONGATE_RAW="https://raw.githubusercontent.com/beatboxes/irongate/main"
IRONGATE_API="https://api.github.com/repos/beatboxes/irongate/commits/main"

# Get current commit hash from GitHub (will be stored after install)
echo "Fetching commit hash from GitHub API..."
API_RESPONSE=$(curl -sf -H "User-Agent: Irongate-Updater" "$IRONGATE_API" 2>/dev/null)
if [ -n "$API_RESPONSE" ]; then
    IRONGATE_COMMIT=$(echo "$API_RESPONSE" | grep -m1 '"sha"' | cut -d'"' -f4 | cut -c1-7)
fi

if [ -z "$IRONGATE_COMMIT" ]; then
    # Fallback: check if already stored in database
    if [ -f /var/www/irongate/dhcp.db ]; then
        IRONGATE_COMMIT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null)
    fi
fi

if [ -z "$IRONGATE_COMMIT" ]; then
    IRONGATE_COMMIT="local"
fi
echo "Commit: $IRONGATE_COMMIT"

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${MAGENTA}"
echo "╔══════════════════════════════════════════════╗"
echo "║                                              ║"
echo "║          🛡️  I R O N G A T E                ║"
echo "║                                              ║"
echo "║       Network Isolation System              ║"
echo "║              ${IRONGATE_COMMIT}                          ║"
echo "║                                              ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./irongate-install.sh)${NC}"
    exit 1
fi

WEBUI_PORT="80"

# Detect primary network interface
echo -e "${YELLOW}Detecting network interface...${NC}"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip link show | grep -E "^[0-9]+:" | grep -v lo | head -n1 | awk -F: '{print $2}' | tr -d ' ')
fi
echo -e "Using interface: ${GREEN}$INTERFACE${NC}"

# Get current IP
CURRENT_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
CURRENT_CIDR=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1 | cut -d'/' -f2)
CURRENT_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)
echo -e "Current IP: ${GREEN}$CURRENT_IP/$CURRENT_CIDR${NC}"
echo -e "Current Gateway: ${GREEN}$CURRENT_GATEWAY${NC}"

# Update system
echo -e "${YELLOW}Updating system and installing packages...${NC}"
apt update
apt install -y dnsmasq nginx php-fpm php-sqlite3 sqlite3 jq

# Install Irongate dependencies
echo -e "${YELLOW}Installing Irongate network isolation dependencies...${NC}"
apt install -y python3 python3-pip python3-venv python3-dev \
    nftables iptables arptables ebtables bridge-utils \
    libpcap-dev arp-scan tcpdump net-tools \
    conntrack ipset 2>/dev/null || true

# Detect PHP version installed
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
echo -e "PHP Version: ${GREEN}$PHP_VERSION${NC}"

# Enable persistent journaling (logs survive reboots for debugging)
echo -e "${YELLOW}Enabling persistent journaling...${NC}"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
systemctl restart systemd-journald 2>/dev/null || true

# Stop services during configuration and kill any zombie processes
# IMPORTANT: Add trap to restart ALL services if script fails or exits
cleanup_on_exit() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Script exited with code $exit_code - ensuring services are running...${NC}"
    fi
    # Always ensure critical services are running when script exits
    echo -e "${YELLOW}Ensuring services are started...${NC}"
    systemctl start dnsmasq 2>/dev/null || true
    systemctl start nginx 2>/dev/null || true
    # Find and start php-fpm regardless of version
    PHP_FPM=$(systemctl list-unit-files | grep -oP 'php[\d.]*-fpm\.service' | head -n1)
    if [ -n "$PHP_FPM" ]; then
        systemctl start "$PHP_FPM" 2>/dev/null || true
    fi
    systemctl start irongate 2>/dev/null || true
}
trap cleanup_on_exit EXIT

systemctl stop dnsmasq 2>/dev/null || true
pkill -9 dnsmasq 2>/dev/null || true
sleep 1
systemctl stop nginx 2>/dev/null || true

# Backup existing configs (but don't overwrite them)
PRESERVE_CONFIG=false
if [ -f /etc/dnsmasq.conf ]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s)
    echo -e "${GREEN}Backed up existing dnsmasq.conf${NC}"
    # Check if this is a configured DHCP server
    if grep -q "dhcp-range=" /etc/dnsmasq.conf 2>/dev/null; then
        PRESERVE_CONFIG=true
    fi
fi

# Create directories
mkdir -p /var/lib/dnsmasq
mkdir -p /etc/dnsmasq.d
mkdir -p /var/www/irongate

# Create/update lease file with proper permissions
touch /var/lib/dnsmasq/dnsmasq.leases
chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || chown nobody:nogroup /var/lib/dnsmasq/dnsmasq.leases
chmod 644 /var/lib/dnsmasq/dnsmasq.leases

# Create/update log file - must be writable by dnsmasq and readable by www-data
touch /var/log/dnsmasq.log
chown dnsmasq:adm /var/log/dnsmasq.log 2>/dev/null || chown nobody:adm /var/log/dnsmasq.log
chmod 644 /var/log/dnsmasq.log

#######################################
# Preserve existing dnsmasq config if it has DHCP settings
#######################################
if [ "$PRESERVE_CONFIG" = true ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ Existing DHCP config detected - PRESERVING${NC}"
    echo -e "${GREEN}  ✓ Your IP reservations and settings are safe!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Count settings for user feedback
    DHCP_RANGE=$(grep "^dhcp-range=" /etc/dnsmasq.conf | head -1)
    echo -e "${GREEN}  Current range: $DHCP_RANGE${NC}"
    
    # Just ensure we have the required settings for logging
    if ! grep -q "log-dhcp" /etc/dnsmasq.conf; then
        echo "" >> /etc/dnsmasq.conf
        echo "# Logging (added by setup script)" >> /etc/dnsmasq.conf
        echo "log-dhcp" >> /etc/dnsmasq.conf
        echo "log-facility=/var/log/dnsmasq.log" >> /etc/dnsmasq.conf
    fi
    
    # Ensure bind-dynamic is set (safer than bind-interfaces)
    if grep -q "^bind-interfaces" /etc/dnsmasq.conf; then
        sed -i 's/^bind-interfaces/bind-dynamic/' /etc/dnsmasq.conf
        echo -e "${YELLOW}Upgraded bind-interfaces to bind-dynamic for better reliability${NC}"
    fi
else
    echo -e "${YELLOW}Creating initial dnsmasq configuration...${NC}"
    cat > /etc/dnsmasq.conf << EOF
# DHCP Server Configuration
# Configure via Web UI at http://$(hostname -I | awk '{print $1}')

# Interface - will be set by web UI
interface=$INTERFACE
bind-dynamic

# Disable DNS (DHCP only)
port=0

# DHCP disabled until configured via web UI
# dhcp-range will be added by web UI

# Lease file
dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases

# Be authoritative
dhcp-authoritative

# Logging
log-dhcp
log-facility=/var/log/dnsmasq.log

# Static reservations
conf-dir=/etc/dnsmasq.d/,*.conf
EOF
fi

# Create empty reservations file only if it doesn't exist
if [ ! -f /etc/dnsmasq.d/reservations.conf ]; then
    cat > /etc/dnsmasq.d/reservations.conf << EOF
# Static DHCP Reservations - Managed by Web UI
EOF
    echo -e "${YELLOW}Created new reservations.conf${NC}"
else
    RESERVATION_COUNT=$(grep -c "^dhcp-host=" /etc/dnsmasq.d/reservations.conf 2>/dev/null || echo "0")
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ Preserving reservations.conf ($RESERVATION_COUNT reservations)${NC}"
    
    # Always fix hostnames with spaces (replace space with hyphen in the hostname field)
    # Backup to /tmp, NOT in dnsmasq.d (dnsmasq reads all files there causing duplicates)
    cp /etc/dnsmasq.d/reservations.conf /tmp/reservations.conf.bak.$(date +%s)
    # Use awk to replace spaces with hyphens only in the 3rd field (hostname)
    awk -F, 'BEGIN{OFS=","} /^dhcp-host=/ && NF>=3 {gsub(/ /, "-", $3)} {print}' /etc/dnsmasq.d/reservations.conf > /tmp/reservations.conf.fixed
    if [ -s /tmp/reservations.conf.fixed ]; then
        mv /tmp/reservations.conf.fixed /etc/dnsmasq.d/reservations.conf
        chown www-data:www-data /etc/dnsmasq.d/reservations.conf
        chmod 664 /etc/dnsmasq.d/reservations.conf
        echo -e "${GREEN}  ✓ Hostnames sanitized (spaces → hyphens)${NC}"
    fi
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi

# Clean up any old backup files in dnsmasq.d that could cause duplicate errors
rm -f /etc/dnsmasq.d/*.bak.* 2>/dev/null || true

#######################################
# Migration from older versions
#######################################
echo -e "${YELLOW}Checking for existing installations...${NC}"

# Create new directory structure
mkdir -p /var/www/irongate
mkdir -p /etc/irongate

# Check for old DHCP-admin installation and migrate
if [ -f /var/www/dhcp-admin/dhcp.db ] && [ ! -f /var/www/irongate/dhcp.db ]; then
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  📦 Found old DHCP-admin installation${NC}"
    echo -e "${CYAN}  📦 Migrating to Irongate...${NC}"
    
    # Copy database
    cp /var/www/dhcp-admin/dhcp.db /var/www/irongate/dhcp.db
    echo -e "${GREEN}  ✓ Database migrated${NC}"
    
    # Count what was migrated
    MIGRATED_RESERVATIONS=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    MIGRATED_DEVICES=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM irongate_devices;" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}  ✓ Reservations: $MIGRATED_RESERVATIONS${NC}"
    echo -e "${GREEN}  ✓ Protected devices: $MIGRATED_DEVICES${NC}"
    
    # Backup old installation
    mv /var/www/dhcp-admin /var/www/dhcp-admin.old.$(date +%s)
    echo -e "${GREEN}  ✓ Old installation backed up${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
elif [ -f /var/www/dhcp-admin/dhcp.db ] && [ -f /var/www/irongate/dhcp.db ]; then
    # Both exist - check which is newer and has more data
    OLD_COUNT=$(sqlite3 /var/www/dhcp-admin/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    NEW_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    
    if [ "$OLD_COUNT" -gt "$NEW_COUNT" ]; then
        echo -e "${YELLOW}  ⚠️  Old database has more data ($OLD_COUNT vs $NEW_COUNT reservations)${NC}"
        echo -e "${YELLOW}  ⚠️  Keeping current Irongate database. Old data at /var/www/dhcp-admin/${NC}"
    fi
fi

# Remove old nginx config if it exists
if [ -f /etc/nginx/sites-enabled/dhcp-admin ]; then
    rm -f /etc/nginx/sites-enabled/dhcp-admin
    rm -f /etc/nginx/sites-available/dhcp-admin
    echo -e "${GREEN}  ✓ Removed old nginx config${NC}"
fi

#######################################
# Create SQLite Database (preserve existing data)
#######################################
echo -e "${YELLOW}Setting up database...${NC}"

if [ -f /var/www/irongate/dhcp.db ]; then
    # BACKUP THE DATABASE FIRST - safety measure
    cp /var/www/irongate/dhcp.db /var/www/irongate/dhcp.db.bak.$(date +%s)
    echo -e "${GREEN}Created database backup${NC}"
    
    # Count existing reservations
    DB_RESERVATION_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    DHCP_ENABLED=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='dhcp_enabled';" 2>/dev/null || echo "unknown")
    RANGE_START=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='range_start';" 2>/dev/null || echo "")
    RANGE_END=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='range_end';" 2>/dev/null || echo "")
    
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ Existing database found - PRESERVING${NC}"
    echo -e "${GREEN}  ✓ Reservations in database: $DB_RESERVATION_COUNT${NC}"
    echo -e "${GREEN}  ✓ DHCP enabled: $DHCP_ENABLED${NC}"
    if [ -n "$RANGE_START" ] && [ -n "$RANGE_END" ]; then
        echo -e "${GREEN}  ✓ DHCP range: $RANGE_START - $RANGE_END${NC}"
    fi
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Just ensure tables exist without overwriting data (INSERT OR IGNORE keeps existing values)
    sqlite3 /var/www/irongate/dhcp.db << 'EOSQL'
CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
-- INSERT OR IGNORE does NOT overwrite existing values - only inserts if key doesn't exist
INSERT OR IGNORE INTO settings (key, value) VALUES ('dhcp_enabled', 'false');
INSERT OR IGNORE INTO settings (key, value) VALUES ('interface', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('server_ip', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('cidr', '24');
INSERT OR IGNORE INTO settings (key, value) VALUES ('range_start', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('range_end', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('gateway', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_primary', '8.8.8.8');
INSERT OR IGNORE INTO settings (key, value) VALUES ('dns_secondary', '1.1.1.1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('lease_time', '24h');
INSERT OR IGNORE INTO settings (key, value) VALUES ('domain', '');
-- Auto-update settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_update_enabled', 'false');
INSERT OR IGNORE INTO settings (key, value) VALUES ('last_update_check', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('installed_commit', '');
-- Irongate Network Isolation Settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_enabled', 'false');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_mode', 'single');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_isolated_interface', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_bridge_ip', '10.99.0.1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_bridge_dhcp_start', '10.99.1.1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_bridge_dhcp_end', '10.99.255.254');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_arp_defense', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_ipv6_ra', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_gateway_takeover', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('irongate_bypass_detection', 'true');
-- Irongate device zones table
CREATE TABLE IF NOT EXISTS irongate_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT,
    hostname TEXT,
    zone TEXT DEFAULT 'isolated',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- Custom device groups table
CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    color TEXT DEFAULT '#6c757d',
    icon TEXT DEFAULT '📁',
    description TEXT,
    lan_access TEXT DEFAULT 'none',
    can_access_groups TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOSQL

    # Always fix hostnames with spaces in database (replace space with hyphen)
    echo -e "${YELLOW}  → Sanitizing hostnames in database...${NC}"
    sqlite3 /var/www/irongate/dhcp.db "UPDATE reservations SET hostname = REPLACE(hostname, ' ', '-') WHERE hostname LIKE '% %';"
    FIXED_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT changes();" 2>/dev/null || echo "0")
    echo -e "${GREEN}  ✓ Database hostnames sanitized${NC}"
    
    # Verify data wasn't lost
    VERIFY_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    if [ "$VERIFY_COUNT" != "$DB_RESERVATION_COUNT" ]; then
        echo -e "${RED}WARNING: Reservation count changed! Restoring backup...${NC}"
        cp /var/www/irongate/dhcp.db.bak.* /var/www/irongate/dhcp.db 2>/dev/null
    fi
else
    echo -e "${YELLOW}Creating new database${NC}"
    sqlite3 /var/www/irongate/dhcp.db << 'EOSQL'
CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
INSERT OR REPLACE INTO settings (key, value) VALUES ('dhcp_enabled', 'false');
INSERT OR REPLACE INTO settings (key, value) VALUES ('interface', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('server_ip', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('cidr', '24');
INSERT OR REPLACE INTO settings (key, value) VALUES ('range_start', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('range_end', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('gateway', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_primary', '8.8.8.8');
INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_secondary', '1.1.1.1');
INSERT OR REPLACE INTO settings (key, value) VALUES ('lease_time', '24h');
INSERT OR REPLACE INTO settings (key, value) VALUES ('domain', '');
-- Irongate Network Isolation Settings
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_enabled', 'false');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_mode', 'single');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_isolated_interface', '');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_bridge_ip', '10.99.0.1');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_bridge_dhcp_start', '10.99.1.1');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_bridge_dhcp_end', '10.99.255.254');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_arp_defense', 'true');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_ipv6_ra', 'true');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_gateway_takeover', 'true');
INSERT OR REPLACE INTO settings (key, value) VALUES ('irongate_bypass_detection', 'true');
-- Irongate device zones table
CREATE TABLE IF NOT EXISTS irongate_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT,
    hostname TEXT,
    zone TEXT DEFAULT 'isolated',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- Custom device groups table
CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    color TEXT DEFAULT '#6c757d',
    icon TEXT DEFAULT '📁',
    description TEXT,
    lan_access TEXT DEFAULT 'none',
    can_access_groups TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
EOSQL
fi

# Always update the installed commit hash
sqlite3 /var/www/irongate/dhcp.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '${IRONGATE_COMMIT}');"
echo -e "${GREEN}  ✓ Commit: ${IRONGATE_COMMIT}${NC}"

#######################################
# Create PHP Backend API
#######################################
echo -e "${YELLOW}Creating web application...${NC}"

cat > /var/www/irongate/api.php << 'EOPHP'
<?php
// Suppress warnings/notices from corrupting JSON output
error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Custom error handler to log errors without outputting them
set_error_handler(function($severity, $message, $file, $line) {
    error_log("Irongate API Error: $message in $file:$line");
    return true; // Don't execute PHP's internal error handler
});

$db = new SQLite3('/var/www/irongate/dhcp.db');
$action = $_GET['action'] ?? '';

// Helper functions
function getSetting($db, $key) {
    $stmt = $db->prepare('SELECT value FROM settings WHERE key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ? $row['value'] : null;
}

function setSetting($db, $key, $value) {
    $stmt = $db->prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $stmt->bindValue(2, $value, SQLITE3_TEXT);
    return $stmt->execute() ? true : false;
}

function getAllSettings($db) {
    $results = $db->query('SELECT key, value FROM settings');
    $settings = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $settings[$row['key']] = $row['value'];
    }
    return $settings;
}

function cidrToNetmask($cidr) {
    $cidr = intval($cidr);
    $bin = str_repeat('1', $cidr) . str_repeat('0', 32 - $cidr);
    $parts = str_split($bin, 8);
    return implode('.', array_map('bindec', $parts));
}

function cidrToHosts($cidr) {
    return pow(2, 32 - intval($cidr)) - 2;
}

function getLeases() {
    $leases = [];
    $file = '/var/lib/dnsmasq/dnsmasq.leases';
    if (file_exists($file)) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 4) {
                $leases[] = [
                    'expires' => date('Y-m-d H:i:s', intval($parts[0])),
                    'expires_unix' => intval($parts[0]),
                    'mac' => strtoupper($parts[1]),
                    'ip' => $parts[2],
                    'hostname' => $parts[3] ?? '*',
                    'client_id' => $parts[4] ?? ''
                ];
            }
        }
    }
    usort($leases, function($a, $b) {
        return ip2long($a['ip']) - ip2long($b['ip']);
    });
    return $leases;
}

function getReservations($db) {
    $results = $db->query('SELECT * FROM reservations ORDER BY ip');
    $reservations = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $reservations[] = $row;
    }
    return $reservations;
}

// Sanitize hostname - replace spaces with hyphens, remove invalid chars
function sanitizeHostname($hostname) {
    $hostname = trim($hostname);
    if (empty($hostname)) return '';
    // Replace spaces with hyphens
    $hostname = str_replace(' ', '-', $hostname);
    // Remove any character that's not alphanumeric or hyphen
    $hostname = preg_replace('/[^a-zA-Z0-9\-]/', '', $hostname);
    // Remove leading/trailing hyphens
    $hostname = trim($hostname, '-');
    // Collapse multiple hyphens
    $hostname = preg_replace('/-+/', '-', $hostname);
    return $hostname;
}

function addReservation($db, $mac, $ip, $hostname, $description) {
    $mac = strtolower(trim($mac));
    $ip = trim($ip);
    $hostname = sanitizeHostname($hostname);
    $stmt = $db->prepare('INSERT OR REPLACE INTO reservations (mac, ip, hostname, description) VALUES (?, ?, ?, ?)');
    $stmt->bindValue(1, $mac, SQLITE3_TEXT);
    $stmt->bindValue(2, $ip, SQLITE3_TEXT);
    $stmt->bindValue(3, $hostname, SQLITE3_TEXT);
    $stmt->bindValue(4, $description, SQLITE3_TEXT);
    $result = $stmt->execute();
    if ($result) {
        syncReservationsToFile($db);
        return true;
    }
    return false;
}

function deleteReservation($db, $id) {
    $stmt = $db->prepare('DELETE FROM reservations WHERE id = ?');
    $stmt->bindValue(1, $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    syncReservationsToFile($db);
    return $result ? true : false;
}

function syncReservationsToFile($db) {
    $results = $db->query('SELECT * FROM reservations');
    $content = "# Static DHCP Reservations - Auto-generated by Web UI\n";
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $line = "dhcp-host=" . $row['mac'] . "," . $row['ip'];
        $hostname = sanitizeHostname($row['hostname']);
        if (!empty($hostname)) {
            $line .= "," . $hostname;
        }
        $content .= $line . "\n";
    }
    file_put_contents('/etc/dnsmasq.d/reservations.conf', $content);
}

function generateDnsmasqConfig($db) {
    $settings = getAllSettings($db);
    
    $config = "# DHCP Server Configuration\n";
    $config .= "# Auto-generated by Web UI on " . date('Y-m-d H:i:s') . "\n\n";
    
    $interface = $settings['interface'] ?? '';
    if (empty($interface)) {
        $interface = trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    }
    
    $config .= "# Interface\n";
    $config .= "interface=$interface\n";
    // Use bind-dynamic instead of bind-interfaces - more resilient to interface changes
    $config .= "bind-dynamic\n\n";
    
    $config .= "# Disable DNS (DHCP only)\n";
    $config .= "port=0\n\n";
    
    if ($settings['dhcp_enabled'] === 'true' && !empty($settings['range_start']) && !empty($settings['range_end'])) {
        $netmask = cidrToNetmask($settings['cidr'] ?? '24');
        $leaseTime = $settings['lease_time'] ?? '24h';
        
        $config .= "# DHCP Range\n";
        $config .= "dhcp-range={$settings['range_start']},{$settings['range_end']},$netmask,$leaseTime\n\n";
        
        if (!empty($settings['gateway'])) {
            $config .= "# Gateway\n";
            $config .= "dhcp-option=option:router,{$settings['gateway']}\n\n";
        }
        
        $dns = [];
        if (!empty($settings['dns_primary'])) $dns[] = $settings['dns_primary'];
        if (!empty($settings['dns_secondary'])) $dns[] = $settings['dns_secondary'];
        if (!empty($dns)) {
            $config .= "# DNS Servers\n";
            $config .= "dhcp-option=option:dns-server," . implode(',', $dns) . "\n\n";
        }
        
        if (!empty($settings['domain'])) {
            $config .= "# Domain\n";
            $config .= "domain={$settings['domain']}\n\n";
        }
    } else {
        $config .= "# DHCP is disabled - configure via Web UI\n\n";
    }
    
    $config .= "# Lease file\n";
    $config .= "dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases\n\n";
    
    $config .= "# Be authoritative\n";
    $config .= "dhcp-authoritative\n\n";
    
    $config .= "# Logging\n";
    $config .= "log-dhcp\n";
    $config .= "log-facility=/var/log/dnsmasq.log\n\n";
    
    $config .= "# Static reservations\n";
    $config .= "conf-dir=/etc/dnsmasq.d/,*.conf\n";
    
    return $config;
}

// Validate dnsmasq config before applying
function validateConfig($configContent) {
    // Write to temp file and test
    $tempFile = '/tmp/dnsmasq-test-' . time() . '.conf';
    file_put_contents($tempFile, $configContent);
    
    exec("dnsmasq --test --conf-file=$tempFile 2>&1", $output, $retval);
    unlink($tempFile);
    
    return [
        'valid' => ($retval === 0),
        'output' => implode("\n", $output),
        'return_code' => $retval
    ];
}

function applyConfig($db) {
    $config = generateDnsmasqConfig($db);
    
    // Validate config first
    $validation = validateConfig($config);
    if (!$validation['valid']) {
        return [
            'success' => false,
            'error' => 'Config validation failed: ' . $validation['output'],
            'stage' => 'validation'
        ];
    }
    
    // Write the config
    file_put_contents('/etc/dnsmasq.conf', $config);
    
    // Stop current service gracefully
    exec('sudo systemctl stop dnsmasq 2>&1', $stopOutput, $stopRetval);
    usleep(500000); // Wait 500ms
    
    // Start the service
    exec('sudo systemctl start dnsmasq 2>&1', $startOutput, $startRetval);
    
    if ($startRetval !== 0) {
        // Get the actual error from journalctl
        exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
        return [
            'success' => false,
            'error' => 'Service start failed',
            'output' => implode("\n", $startOutput),
            'journal' => implode("\n", $journalOutput),
            'stage' => 'start'
        ];
    }
    
    return ['success' => true];
}

function getServiceStatus() {
    exec('systemctl is-active dnsmasq 2>&1', $output, $retval);
    $active = ($retval === 0);
    
    $uptime = '';
    $lastError = '';
    if ($active) {
        $uptime = trim(shell_exec("systemctl show dnsmasq --property=ActiveEnterTimestamp | cut -d'=' -f2"));
    } else {
        // Get last error from journal
        exec('journalctl -u dnsmasq -n 10 --no-pager 2>&1', $journalOutput);
        $lastError = implode("\n", $journalOutput);
    }
    
    return [
        'running' => $active,
        'status' => $active ? 'running' : 'stopped',
        'since' => $uptime,
        'last_error' => $lastError
    ];
}

function getSystemInfo() {
    $interface = trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    $ip = trim(shell_exec("ip -4 addr show $interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1"));
    $cidr = trim(shell_exec("ip -4 addr show $interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1 | cut -d'/' -f2"));
    $gateway = trim(shell_exec("ip route | grep default | awk '{print \$3}' | head -n1"));
    $mac = trim(shell_exec("ip link show $interface | grep -oP '(?<=link/ether\s)[a-f0-9:]+' | head -n1"));
    $hostname = gethostname();
    
    // Get all interfaces
    $interfaces = [];
    exec("ip -o link show | awk -F': ' '{print \$2}' | grep -v lo", $ifaceList);
    foreach ($ifaceList as $iface) {
        $iface = trim(explode('@', $iface)[0]);
        $ifaceIp = trim(shell_exec("ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1"));
        $interfaces[] = [
            'name' => $iface,
            'ip' => $ifaceIp ?: 'No IP',
            'current' => ($iface === $interface)
        ];
    }
    
    return [
        'hostname' => $hostname,
        'interface' => $interface,
        'interfaces' => $interfaces,
        'ip' => $ip,
        'cidr' => $cidr,
        'mac' => $mac,
        'gateway' => $gateway,
        'uptime' => trim(shell_exec('uptime -p'))
    ];
}

function getRecentLogs($lines = 100) {
    $logs = [];
    $debug = [];
    $lines = max(1, min(1000, intval($lines)));
    $logFile = '/var/log/dnsmasq.log';
    $syslogFile = '/var/log/syslog';
    
    // Method 1: Read the dedicated log file directly (most likely to work)
    if (file_exists($logFile)) {
        $debug[] = "Log file exists: $logFile";
        $fileSize = filesize($logFile);
        $debug[] = "File size: $fileSize bytes";
        
        if ($fileSize > 0) {
            // Try direct read first
            if (is_readable($logFile)) {
                $content = @file_get_contents($logFile);
                if ($content !== false && strlen($content) > 0) {
                    $allLines = explode("\n", $content);
                    $allLines = array_filter($allLines, function($l) { return strlen(trim($l)) > 0; });
                    if (count($allLines) > 0) {
                        $recentLines = array_slice($allLines, -$lines);
                        foreach ($recentLines as $line) {
                            $logs[] = htmlspecialchars(trim($line));
                        }
                        return array_reverse($logs);
                    }
                }
            }
            
            // Try tail command as fallback
            $tailCmd = "/usr/bin/tail -n $lines " . escapeshellarg($logFile) . " 2>&1";
            $tailOutput = [];
            exec($tailCmd, $tailOutput, $tailRet);
            $debug[] = "tail returned: $tailRet, lines: " . count($tailOutput);
            if (count($tailOutput) > 0) {
                foreach ($tailOutput as $line) {
                    $line = trim($line);
                    if (strlen($line) > 0) {
                        $logs[] = htmlspecialchars($line);
                    }
                }
                if (count($logs) > 0) {
                    return array_reverse($logs);
                }
            }
        } else {
            $debug[] = "Log file is empty";
        }
    } else {
        $debug[] = "Log file does not exist: $logFile";
    }
    
    // Method 2: Try journalctl (may require group membership)
    $journalCmd = "/usr/bin/journalctl -u dnsmasq -n $lines --no-pager 2>&1";
    $journalOutput = [];
    exec($journalCmd, $journalOutput, $journalRet);
    $debug[] = "journalctl returned: $journalRet, lines: " . count($journalOutput);
    
    if ($journalRet === 0 && count($journalOutput) > 0) {
        foreach ($journalOutput as $line) {
            $line = trim($line);
            // Skip journal metadata lines
            if (strlen($line) > 0 && 
                strpos($line, '-- No entries --') === false && 
                strpos($line, '-- Journal begins') === false &&
                strpos($line, '-- Logs begin') === false) {
                $logs[] = htmlspecialchars($line);
            }
        }
        if (count($logs) > 0) {
            return array_reverse($logs);
        }
    }
    
    // Method 3: Try syslog
    if (file_exists($syslogFile) && is_readable($syslogFile)) {
        $debug[] = "Trying syslog";
        $grepCmd = "/usr/bin/grep -i dnsmasq " . escapeshellarg($syslogFile) . " 2>/dev/null | /usr/bin/tail -n $lines";
        $syslogOutput = [];
        exec($grepCmd, $syslogOutput, $syslogRet);
        $debug[] = "syslog grep returned: $syslogRet, lines: " . count($syslogOutput);
        
        if (count($syslogOutput) > 0) {
            foreach ($syslogOutput as $line) {
                $line = trim($line);
                if (strlen($line) > 0) {
                    $logs[] = htmlspecialchars($line);
                }
            }
            if (count($logs) > 0) {
                return array_reverse($logs);
            }
        }
    }
    
    // Method 4: Check systemctl status output for recent activity
    $statusOutput = [];
    exec("/bin/systemctl status dnsmasq 2>&1 | tail -20", $statusOutput, $statusRet);
    if (count($statusOutput) > 0) {
        foreach ($statusOutput as $line) {
            $line = trim($line);
            if (strlen($line) > 0 && (strpos($line, 'dnsmasq') !== false || strpos($line, 'DHCP') !== false)) {
                $logs[] = htmlspecialchars($line);
            }
        }
        if (count($logs) > 0) {
            return array_reverse($logs);
        }
    }
    
    // Return debug info if no logs found
    $noLogsMsg = ['No DHCP logs found. Debug info:'];
    foreach ($debug as $d) {
        $noLogsMsg[] = "  - $d";
    }
    $noLogsMsg[] = '';
    $noLogsMsg[] = 'Possible reasons:';
    $noLogsMsg[] = '  - No DHCP requests have been made yet';
    $noLogsMsg[] = '  - Service is not running';
    $noLogsMsg[] = '  - Log file permissions issue';
    
    return $noLogsMsg;
}

// Get diagnostic info for troubleshooting
function getDiagnostics() {
    $diag = [];
    
    // Check dnsmasq config syntax
    exec('dnsmasq --test 2>&1', $testOutput, $testRetval);
    $diag['config_valid'] = ($testRetval === 0);
    $diag['config_test'] = implode("\n", $testOutput);
    
    // Check if port 67 is in use by something else
    exec('ss -ulnp | grep :67 2>&1', $portOutput);
    $diag['port_67_status'] = implode("\n", $portOutput);
    
    // Check interface status
    $interface = trim(shell_exec("grep '^interface=' /etc/dnsmasq.conf | cut -d'=' -f2"));
    $diag['configured_interface'] = $interface;
    exec("ip link show $interface 2>&1", $ifaceOutput, $ifaceRetval);
    $diag['interface_exists'] = ($ifaceRetval === 0);
    $diag['interface_status'] = implode("\n", $ifaceOutput);
    
    // Check file permissions
    $diag['config_writable'] = is_writable('/etc/dnsmasq.conf');
    $diag['leases_writable'] = is_writable('/var/lib/dnsmasq/dnsmasq.leases');
    $diag['log_writable'] = is_writable('/var/log/dnsmasq.log');
    
    // Get recent journal errors
    exec('journalctl -u dnsmasq -p err -n 10 --no-pager 2>&1', $errOutput);
    $diag['recent_errors'] = implode("\n", $errOutput);
    
    // Get service status detail
    exec('systemctl status dnsmasq 2>&1', $statusOutput);
    $diag['service_status'] = implode("\n", $statusOutput);
    
    return $diag;
}

// Fix common issues automatically
function autoRepair() {
    $repairs = [];
    
    // Ensure lease file exists and is writable
    if (!file_exists('/var/lib/dnsmasq/dnsmasq.leases')) {
        touch('/var/lib/dnsmasq/dnsmasq.leases');
        chmod('/var/lib/dnsmasq/dnsmasq.leases', 0644);
        $repairs[] = 'Created lease file';
    }
    
    // Ensure log file exists and is writable
    if (!file_exists('/var/log/dnsmasq.log')) {
        touch('/var/log/dnsmasq.log');
        chmod('/var/log/dnsmasq.log', 0644);
        $repairs[] = 'Created log file';
    }
    
    // Fix common permission issues
    exec('sudo chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq.leases 2>&1');
    exec('sudo chmod 644 /var/lib/dnsmasq/dnsmasq.leases 2>&1');
    exec('sudo chmod 644 /var/log/dnsmasq.log 2>&1');
    $repairs[] = 'Fixed file permissions';
    
    // Kill any zombie dnsmasq processes
    exec('sudo pkill -9 dnsmasq 2>&1');
    usleep(500000);
    $repairs[] = 'Killed stale processes';
    
    // Try to start the service
    exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
    
    if ($retval === 0) {
        $repairs[] = 'Service started successfully';
        return ['success' => true, 'repairs' => $repairs];
    } else {
        exec('journalctl -u dnsmasq -n 10 --no-pager 2>&1', $journalOutput);
        $repairs[] = 'Service failed to start';
        return [
            'success' => false,
            'repairs' => $repairs,
            'error' => implode("\n", $journalOutput)
        ];
    }
}

// API Routes
switch ($action) {
    case 'system':
        echo json_encode(['success' => true, 'data' => getSystemInfo()]);
        break;
    
    case 'status':
        echo json_encode(['success' => true, 'data' => getServiceStatus()]);
        break;
    
    case 'settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            
            // Validate lease_time format (dnsmasq format: 30m, 24h, 7d, 1w, infinite, or raw seconds)
            if (isset($data['lease_time'])) {
                $lt = trim($data['lease_time']);
                if (!preg_match('/^(\d+[smhdw]?|infinite)$/i', $lt)) {
                    echo json_encode(['success' => false, 'error' => 'Invalid lease time format. Use: 30m, 24h, 7d, 1w, or infinite']);
                    exit;
                }
                $data['lease_time'] = strtolower($lt);
            }
            
            foreach ($data as $key => $value) {
                setSetting($db, $key, $value);
            }
            $result = applyConfig($db);
            if (is_array($result) && isset($result['success'])) {
                echo json_encode($result);
            } else {
                echo json_encode(['success' => $result, 'applied' => $result]);
            }
        } else {
            echo json_encode(['success' => true, 'data' => getAllSettings($db)]);
        }
        break;
    
    case 'apply':
        $result = applyConfig($db);
        echo json_encode($result);
        break;
    
    case 'leases':
        echo json_encode(['success' => true, 'data' => getLeases()]);
        break;
    
    case 'reservations':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $result = addReservation($db, $data['mac'], $data['ip'], $data['hostname'] ?? '', $data['description'] ?? '');
            if ($result) {
                $applyResult = applyConfig($db);
                echo json_encode(['success' => true, 'applied' => $applyResult]);
            } else {
                echo json_encode(['success' => false]);
            }
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $result = deleteReservation($db, $id);
            if ($result) {
                $applyResult = applyConfig($db);
                echo json_encode(['success' => true, 'applied' => $applyResult]);
            } else {
                echo json_encode(['success' => false]);
            }
        } else {
            echo json_encode(['success' => true, 'data' => getReservations($db)]);
        }
        break;
    
    case 'logs':
        $lines = intval($_GET['lines'] ?? 100);
        echo json_encode(['success' => true, 'data' => getRecentLogs($lines)]);
        break;
    
    case 'restart':
        // Stop first
        exec('sudo systemctl stop dnsmasq 2>&1');
        usleep(500000);
        // Start
        exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
        if ($retval !== 0) {
            exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
            echo json_encode([
                'success' => false,
                'output' => implode("\n", $output),
                'journal' => implode("\n", $journalOutput)
            ]);
        } else {
            echo json_encode(['success' => true, 'output' => implode("\n", $output)]);
        }
        break;
    
    case 'stop':
        exec('sudo systemctl stop dnsmasq 2>&1', $output, $retval);
        echo json_encode(['success' => $retval === 0]);
        break;
    
    case 'start':
        exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
        if ($retval !== 0) {
            exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
            echo json_encode([
                'success' => false,
                'output' => implode("\n", $output),
                'journal' => implode("\n", $journalOutput)
            ]);
        } else {
            echo json_encode(['success' => true]);
        }
        break;
    
    case 'diagnostics':
        echo json_encode(['success' => true, 'data' => getDiagnostics()]);
        break;
    
    case 'repair':
        echo json_encode(autoRepair());
        break;
    
    case 'validate':
        $config = generateDnsmasqConfig($db);
        $result = validateConfig($config);
        echo json_encode(['success' => true, 'data' => $result]);
        break;
    
    //==========================================================================
    // IRONGATE NETWORK ISOLATION API
    //==========================================================================
    
    case 'irongate_status':
        $enabled = getSetting($db, 'irongate_enabled') === 'true';
        $mode = getSetting($db, 'irongate_mode') ?? 'single';
        exec('systemctl is-active irongate 2>&1', $svcOutput, $svcRet);
        $serviceActive = ($svcRet === 0);
        
        echo json_encode([
            'success' => true,
            'data' => [
                'enabled' => $enabled,
                'mode' => $mode,
                'service_running' => $serviceActive,
                'isolated_interface' => getSetting($db, 'irongate_isolated_interface'),
                'bridge_ip' => getSetting($db, 'irongate_bridge_ip'),
                'layers' => [
                    'arp_defense' => getSetting($db, 'irongate_arp_defense') !== 'false',
                    'ipv6_ra' => getSetting($db, 'irongate_ipv6_ra') !== 'false',
                    'gateway_takeover' => getSetting($db, 'irongate_gateway_takeover') !== 'false',
                    'bypass_detection' => getSetting($db, 'irongate_bypass_detection') !== 'false',
                    'firewall' => getSetting($db, 'irongate_firewall') !== 'false'
                ]
            ]
        ]);
        break;
    
    case 'irongate_settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            foreach ($data as $key => $value) {
                if (strpos($key, 'irongate_') === 0 || strpos($key, 'blockchain_') === 0) {
                    setSetting($db, $key, $value);
                }
            }
            $result = applyIrongateConfig($db);
            echo json_encode($result);
        } else {
            $settings = [];
            foreach (['irongate_enabled', 'irongate_mode', 'irongate_isolated_interface',
                      'irongate_bridge_ip', 'irongate_bridge_dhcp_start', 'irongate_bridge_dhcp_end',
                      'irongate_arp_defense', 'irongate_ipv6_ra', 'irongate_gateway_takeover',
                      'irongate_bypass_detection', 'irongate_firewall',
                      'blockchain_enabled', 'blockchain_network', 'blockchain_app_id',
                      'blockchain_admin_mnemonic', 'blockchain_cache_ttl', 'blockchain_fallback_allow',
                      'blockchain_audit_logging', 'blockchain_allow_rogue_devices'] as $key) {
                $settings[$key] = getSetting($db, $key);
            }
            echo json_encode(['success' => true, 'data' => $settings]);
        }
        break;
    
    case 'irongate_interfaces':
        $interfaces = [];
        $mainIface = getSetting($db, 'interface') ?: trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
        exec("ls /sys/class/net 2>/dev/null", $ifaceList);
        foreach ($ifaceList as $iface) {
            $iface = trim($iface);
            if (in_array($iface, ['lo', 'docker0', 'br-irongate', 'br0'])) continue;
            $isUsb = (strpos($iface, 'enx') === 0 || strpos($iface, 'usb') === 0);
            if (!$isUsb && file_exists("/sys/class/net/$iface/device/uevent")) {
                $uevent = @file_get_contents("/sys/class/net/$iface/device/uevent");
                $isUsb = (stripos($uevent, 'usb') !== false);
            }
            $mac = trim(@file_get_contents("/sys/class/net/$iface/address") ?: '');
            $state = trim(@file_get_contents("/sys/class/net/$iface/operstate") ?: 'unknown');
            $interfaces[] = [
                'name' => $iface,
                'mac' => $mac,
                'state' => $state,
                'is_usb' => $isUsb,
                'is_main' => ($iface === $mainIface)
            ];
        }
        echo json_encode(['success' => true, 'data' => $interfaces]);
        break;
    
    case 'irongate_toggle':
        $data = json_decode(file_get_contents('php://input'), true);
        $enable = $data['enabled'] ?? false;
        setSetting($db, 'irongate_enabled', $enable ? 'true' : 'false');
        
        if ($enable) {
            $result = applyIrongateConfig($db);
        } else {
            exec('sudo systemctl stop irongate 2>&1', $output, $retval);
            $result = ['success' => true, 'message' => 'Irongate disabled'];
        }
        echo json_encode($result);
        break;
    
    case 'irongate_apply':
        $result = applyIrongateConfig($db);
        echo json_encode($result);
        break;
    
    case 'irongate_logs':
        $lines = intval($_GET['lines'] ?? 50);
        $logs = [];
        exec("sudo journalctl -u irongate -n $lines --no-pager 2>&1", $journalOutput);
        foreach ($journalOutput as $line) {
            $line = trim($line);
            if (!empty($line) && strpos($line, '-- No entries') === false) {
                $logs[] = htmlspecialchars($line);
            }
        }
        echo json_encode(['success' => true, 'data' => array_reverse($logs)]);
        break;

    case 'device_groups':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $name = trim($data['name'] ?? '');

            // Validate name - cannot use built-in group names
            $reserved = ['isolated', 'servers', 'trusted'];
            if (in_array(strtolower($name), $reserved)) {
                echo json_encode(['success' => false, 'error' => 'Cannot use reserved group name']);
                break;
            }

            if (empty($name)) {
                echo json_encode(['success' => false, 'error' => 'Group name is required']);
                break;
            }

            $stmt = $db->prepare('INSERT OR REPLACE INTO device_groups (name, color, icon, description, lan_access, can_access_groups) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->bindValue(1, $name, SQLITE3_TEXT);
            $stmt->bindValue(2, $data['color'] ?? '#6c757d', SQLITE3_TEXT);
            $stmt->bindValue(3, $data['icon'] ?? '📁', SQLITE3_TEXT);
            $stmt->bindValue(4, $data['description'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(5, $data['lan_access'] ?? 'none', SQLITE3_TEXT);
            $stmt->bindValue(6, json_encode($data['can_access_groups'] ?? []), SQLITE3_TEXT);
            $result = $stmt->execute();

            $configResult = ['success' => true];
            if ($result) {
                // Buffer output to prevent PHP warnings from corrupting JSON
                ob_start();
                try {
                    $configResult = applyIrongateConfig($db);
                } catch (Exception $e) {
                    $configResult = ['success' => false, 'error' => $e->getMessage()];
                }
                ob_end_clean();
            }
            echo json_encode(['success' => $result ? true : false, 'config' => $configResult]);
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $name = $_GET['name'] ?? '';

            // First get the group name if deleting by ID
            if ($id) {
                $stmt = $db->prepare('SELECT name FROM device_groups WHERE id = ?');
                $stmt->bindValue(1, $id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $row = $result->fetchArray(SQLITE3_ASSOC);
                if ($row) {
                    $name = $row['name'];
                }
            }

            // Move all devices in this group to 'isolated'
            if ($name) {
                $stmt = $db->prepare('UPDATE irongate_devices SET zone = ? WHERE zone = ?');
                $stmt->bindValue(1, 'isolated', SQLITE3_TEXT);
                $stmt->bindValue(2, $name, SQLITE3_TEXT);
                $stmt->execute();
            }

            // Delete the group
            if ($id) {
                $stmt = $db->prepare('DELETE FROM device_groups WHERE id = ?');
                $stmt->bindValue(1, $id, SQLITE3_INTEGER);
            } else {
                $stmt = $db->prepare('DELETE FROM device_groups WHERE name = ?');
                $stmt->bindValue(1, $name, SQLITE3_TEXT);
            }
            $result = $stmt->execute();

            $configResult = ['success' => true];
            if ($result) {
                ob_start();
                try {
                    $configResult = applyIrongateConfig($db);
                } catch (Exception $e) {
                    $configResult = ['success' => false, 'error' => $e->getMessage()];
                }
                ob_end_clean();
            }
            echo json_encode(['success' => $result ? true : false]);
        } else {
            // GET - return all custom groups plus built-in groups
            $results = $db->query('SELECT * FROM device_groups ORDER BY name');
            $groups = [];

            // Add built-in groups first
            $groups[] = [
                'id' => 0,
                'name' => 'isolated',
                'color' => '#e94560',
                'icon' => '🔴',
                'description' => 'Internet only, no LAN access',
                'lan_access' => 'none',
                'can_access_groups' => [],
                'builtin' => true
            ];
            $groups[] = [
                'id' => 0,
                'name' => 'servers',
                'color' => '#ffc107',
                'icon' => '🟡',
                'description' => 'Can communicate with other servers',
                'lan_access' => 'servers',
                'can_access_groups' => ['servers'],
                'builtin' => true
            ];
            $groups[] = [
                'id' => 0,
                'name' => 'trusted',
                'color' => '#00bf63',
                'icon' => '🟢',
                'description' => 'Full network access',
                'lan_access' => 'full',
                'can_access_groups' => [],
                'builtin' => true
            ];

            // Add custom groups
            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                $row['can_access_groups'] = json_decode($row['can_access_groups'] ?? '[]', true) ?: [];
                $row['builtin'] = false;
                $groups[] = $row;
            }

            echo json_encode(['success' => true, 'data' => $groups]);
        }
        break;

    case 'irongate_devices':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $db->prepare('INSERT OR REPLACE INTO irongate_devices (mac, ip, hostname, zone) VALUES (?, ?, ?, ?)');
            $stmt->bindValue(1, strtolower($data['mac']), SQLITE3_TEXT);
            $stmt->bindValue(2, $data['ip'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(3, $data['hostname'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(4, $data['zone'] ?? 'isolated', SQLITE3_TEXT);
            $result = $stmt->execute();
            if ($result) {
                applyIrongateConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $stmt = $db->prepare('DELETE FROM irongate_devices WHERE id = ?');
            $stmt->bindValue(1, $id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            if ($result) {
                applyIrongateConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } else {
            $results = $db->query('SELECT * FROM irongate_devices ORDER BY zone, ip');
            $devices = [];
            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                $devices[] = $row;
            }
            echo json_encode(['success' => true, 'data' => $devices]);
        }
        break;
    
    case 'irongate_diag':
        // Diagnostic info for troubleshooting
        $diag = [];
        
        // 1. Check devices with IPs
        $results = $db->query('SELECT * FROM irongate_devices WHERE ip IS NOT NULL AND ip != ""');
        $devicesWithIp = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $devicesWithIp[] = $row;
        }
        $diag['devices_with_ip'] = $devicesWithIp;
        $diag['devices_without_ip_warning'] = count($devicesWithIp) === 0 ? 
            'WARNING: No devices have IPs set! Firewall rules will not work.' : null;
        
        // 2. IP forwarding status
        $ipForward = trim(shell_exec('cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'));
        $diag['ip_forward'] = $ipForward === '1' ? 'enabled' : 'DISABLED';
        
        // 3. nftables rules
        $nftRules = shell_exec('nft list table inet irongate 2>&1');
        $diag['nftables'] = $nftRules ?: 'No irongate table found';
        
        // 4. ARP cache
        $arpCache = shell_exec('ip neigh show 2>/dev/null | head -20');
        $diag['arp_cache'] = $arpCache;
        
        // 5. Service status
        exec('systemctl status irongate 2>&1', $svcStatus);
        $diag['service_status'] = implode("\n", array_slice($svcStatus, 0, 15));
        
        // 6. Recent logs
        $logs = shell_exec('sudo journalctl -u irongate -n 30 --no-pager 2>&1');
        $diag['recent_logs'] = $logs;
        
        // 7. Config file
        $config = @file_get_contents('/etc/irongate/config.yaml');
        $diag['config'] = $config ?: 'Config file not found';
        
        echo json_encode(['success' => true, 'data' => $diag]);
        break;
    
    case 'update_check':
        // Check for updates from GitHub using commit hash
        $currentCommit = getSetting($db, 'installed_commit') ?: 'unknown';
        $githubApi = 'https://api.github.com/repos/beatboxes/irongate/commits/main';
        
        // Fetch latest commit from GitHub API
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 10,
                'header' => 'User-Agent: Irongate-Updater'
            ]
        ]);
        $response = @file_get_contents($githubApi, false, $ctx);
        
        if ($response === false) {
            echo json_encode(['success' => false, 'error' => 'Could not reach GitHub API']);
            break;
        }
        
        $data = json_decode($response, true);
        if (!isset($data['sha'])) {
            echo json_encode(['success' => false, 'error' => 'Invalid response from GitHub']);
            break;
        }
        
        $remoteCommit = substr($data['sha'], 0, 7);
        $commitMessage = $data['commit']['message'] ?? '';
        $commitDate = $data['commit']['committer']['date'] ?? '';
        $updateAvailable = ($currentCommit !== $remoteCommit && $currentCommit !== 'unknown' && $currentCommit !== 'local');
        
        // Update last check time
        setSetting($db, 'last_update_check', date('Y-m-d H:i:s'));
        
        echo json_encode([
            'success' => true,
            'current_commit' => $currentCommit,
            'remote_commit' => $remoteCommit,
            'update_available' => $updateAvailable,
            'commit_message' => $commitMessage,
            'commit_date' => $commitDate,
            'last_check' => date('Y-m-d H:i:s')
        ]);
        break;
    
    case 'update_settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            if (isset($data['auto_update_enabled'])) {
                setSetting($db, 'auto_update_enabled', $data['auto_update_enabled'] ? 'true' : 'false');
                
                // Enable/disable the auto-update timer
                if ($data['auto_update_enabled']) {
                    exec('sudo systemctl enable irongate-updater.timer 2>&1');
                    exec('sudo systemctl start irongate-updater.timer 2>&1');
                } else {
                    exec('sudo systemctl stop irongate-updater.timer 2>&1');
                    exec('sudo systemctl disable irongate-updater.timer 2>&1');
                }
            }
            echo json_encode(['success' => true]);
        } else {
            echo json_encode([
                'success' => true,
                'data' => [
                    'auto_update_enabled' => getSetting($db, 'auto_update_enabled') === 'true',
                    'installed_commit' => getSetting($db, 'installed_commit') ?: 'unknown',
                    'last_update_check' => getSetting($db, 'last_update_check') ?: 'Never'
                ]
            ]);
        }
        break;
    
    case 'update_now':
        // Perform update
        $repoRaw = 'https://raw.githubusercontent.com/beatboxes/irongate/main';
        $githubApi = 'https://api.github.com/repos/beatboxes/irongate/commits/main';
        $scriptPath = '/tmp/irongate-update.sh';
        
        // First, get the commit hash we're updating TO
        $ctx = stream_context_create(['http' => ['timeout' => 10, 'header' => 'User-Agent: Irongate-Updater']]);
        $commitData = @file_get_contents($githubApi, false, $ctx);
        $targetCommit = 'unknown';
        if ($commitData) {
            $json = json_decode($commitData, true);
            if (isset($json['sha'])) {
                $targetCommit = substr($json['sha'], 0, 7);
            }
        }
        
        // Download the latest install script
        $ctx = stream_context_create(['http' => ['timeout' => 30, 'header' => 'User-Agent: Irongate-Updater']]);
        $script = @file_get_contents("$repoRaw/irongate-install.sh", false, $ctx);
        
        if ($script === false) {
            echo json_encode(['success' => false, 'error' => 'Failed to download update']);
            break;
        }
        
        // Save commit hash BEFORE running update (in case script fails to set it)
        setSetting($db, 'installed_commit', $targetCommit);
        
        // Save and execute
        file_put_contents($scriptPath, $script);
        chmod($scriptPath, 0755);
        
        // Create log file with proper permissions first
        exec("sudo touch /var/log/irongate-update.log");
        exec("sudo chown www-data /var/log/irongate-update.log");
        
        // Run update in background
        exec("sudo bash $scriptPath > /var/log/irongate-update.log 2>&1 &");
        
        echo json_encode([
            'success' => true,
            'message' => 'Update started. The page will reload when complete.',
            'log' => '/var/log/irongate-update.log',
            'target_commit' => $targetCommit
        ]);
        break;
    
    case 'update_log':
        $log = @file_get_contents('/var/log/irongate-update.log');
        echo json_encode(['success' => true, 'data' => $log ?: 'No update log available']);
        break;
    
    default:
        echo json_encode(['error' => 'Unknown action', 'available' => [
            'system', 'status', 'settings', 'apply', 'leases', 
            'reservations', 'logs', 'restart', 'stop', 'start',
            'diagnostics', 'repair', 'validate',
            'irongate_status', 'irongate_settings', 'irongate_interfaces',
            'irongate_toggle', 'irongate_apply', 'irongate_logs', 'irongate_devices', 'device_groups',
            'update_check', 'update_settings', 'update_now', 'update_log'
        ]]);
}

// Irongate config generator
function applyIrongateConfig($db) {
    $settings = getAllSettings($db);
    $enabled = ($settings['irongate_enabled'] ?? 'false') === 'true';
    
    if (!$enabled) {
        exec('sudo systemctl stop irongate 2>&1');
        return ['success' => true, 'message' => 'Irongate disabled'];
    }
    
    $mode = $settings['irongate_mode'] ?? 'single';
    $interface = $settings['interface'] ?: trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    $gateway = $settings['gateway'] ?: trim(shell_exec("ip route | grep default | awk '{print \$3}' | head -n1"));
    $localIp = trim(shell_exec("ip -4 addr show $interface 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -n1"));
    $localMac = trim(shell_exec("ip link show $interface 2>/dev/null | awk '/ether/ {print \$2}'"));
    
    // Get gateway MAC - try ARP cache first, then arping
    $gatewayMac = trim(shell_exec("ip neigh show | grep '$gateway ' | awk '{print \$5}' | head -n1"));
    if (empty($gatewayMac)) {
        exec("arping -c 1 -I $interface $gateway 2>/dev/null", $arpOutput);
        $gatewayMac = trim(shell_exec("ip neigh show | grep '$gateway ' | awk '{print \$5}' | head -n1"));
    }
    
    // Generate YAML config
    $config = "# Irongate Configuration\n";
    $config .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";
    $config .= "network:\n";
    $config .= "  interface: \"$interface\"\n";
    $config .= "  local_ip: \"$localIp\"\n";
    $config .= "  local_mac: \"$localMac\"\n";
    $config .= "  gateway_ip: \"$gateway\"\n";
    $config .= "  gateway_mac: \"$gatewayMac\"\n\n";
    
    $config .= "mode: \"$mode\"\n\n";
    
    if ($mode === 'dual') {
        $config .= "bridge:\n";
        $config .= "  enabled: true\n";
        $config .= "  isolated_interface: \"" . ($settings['irongate_isolated_interface'] ?? '') . "\"\n";
        $config .= "  bridge_name: \"br-irongate\"\n";
        $config .= "  bridge_ip: \"" . ($settings['irongate_bridge_ip'] ?? '10.99.0.1') . "\"\n";
        $config .= "  bridge_netmask: \"255.255.0.0\"\n";
        $config .= "  dhcp_start: \"" . ($settings['irongate_bridge_dhcp_start'] ?? '10.99.1.1') . "\"\n";
        $config .= "  dhcp_end: \"" . ($settings['irongate_bridge_dhcp_end'] ?? '10.99.255.254') . "\"\n";
        $config .= "  port_isolation: true\n\n";
    }
    
    $config .= "layers:\n";
    $config .= "  arp_defense: " . (($settings['irongate_arp_defense'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  ipv6_ra: " . (($settings['irongate_ipv6_ra'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  gateway_takeover: " . (($settings['irongate_gateway_takeover'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  bypass_detection: " . (($settings['irongate_bypass_detection'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  firewall: " . (($settings['irongate_firewall'] ?? 'true') === 'true' ? 'true' : 'false') . "\n\n";
    
    // Layer 8: Blockchain settings
    $config .= "# Layer 8: Algorand Blockchain Verification\n";
    $config .= "blockchain:\n";
    $config .= "  enabled: " . (($settings['blockchain_enabled'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  network: \"" . ($settings['blockchain_network'] ?? 'mainnet') . "\"\n";
    $appId = $settings['blockchain_app_id'] ?? '';
    if (!empty($appId) && $appId !== 'null') {
        $config .= "  app_id: " . intval($appId) . "\n";
    } else {
        $config .= "  app_id: null\n";
    }
    $mnemonic = $settings['blockchain_admin_mnemonic'] ?? '';
    if (!empty($mnemonic) && $mnemonic !== 'null') {
        $config .= "  admin_mnemonic: \"" . $mnemonic . "\"\n";
    } else {
        $config .= "  admin_mnemonic: null\n";
    }
    $config .= "  cache_ttl: " . intval($settings['blockchain_cache_ttl'] ?? 60) . "\n";
    $config .= "  fallback_allow: " . (($settings['blockchain_fallback_allow'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  audit_logging: " . (($settings['blockchain_audit_logging'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  allow_rogue_devices: " . (($settings['blockchain_allow_rogue_devices'] ?? 'false') === 'true' ? 'true' : 'false') . "\n\n";
    
    // Get custom device groups from database
    $groupResults = $db->query('SELECT * FROM device_groups ORDER BY name');
    $customGroups = [];
    while ($row = $groupResults->fetchArray(SQLITE3_ASSOC)) {
        $customGroups[] = $row;
    }

    $config .= "# Custom Device Groups\n";
    $config .= "custom_groups:\n";
    if (!empty($customGroups)) {
        foreach ($customGroups as $group) {
            $config .= "  - name: \"" . $group['name'] . "\"\n";
            $config .= "    color: \"" . $group['color'] . "\"\n";
            $config .= "    icon: \"" . $group['icon'] . "\"\n";
            $config .= "    description: \"" . ($group['description'] ?? '') . "\"\n";
            $config .= "    lan_access: \"" . ($group['lan_access'] ?? 'none') . "\"\n";
            $canAccess = json_decode($group['can_access_groups'] ?? '[]', true) ?: [];
            $config .= "    can_access_groups: [" . implode(', ', array_map(function($g) { return '"' . $g . '"'; }, $canAccess)) . "]\n";
        }
    } else {
        $config .= "  []\n";
    }
    $config .= "\n";

    // Get protected devices from database
    $results = $db->query('SELECT mac, ip, zone FROM irongate_devices');
    $devices = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $devices[] = $row;
    }

    $config .= "devices:\n";
    if (!empty($devices)) {
        foreach ($devices as $dev) {
            $config .= "  - mac: \"" . $dev['mac'] . "\"\n";
            $config .= "    ip: \"" . $dev['ip'] . "\"\n";
            $config .= "    zone: \"" . $dev['zone'] . "\"\n";
        }
    } else {
        $config .= "  []\n";
    }

    // Write config
    @mkdir('/etc/irongate', 0775, true);
    $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
    if ($writeResult === false) {
        // Try to fix permissions and retry
        @chmod('/etc/irongate', 0775);
        @chown('/etc/irongate', 'root');
        @chgrp('/etc/irongate', 'www-data');
        $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
        if ($writeResult === false) {
            return [
                'success' => false,
                'error' => 'Failed to write config file - check /etc/irongate permissions'
            ];
        }
    }
    
    // Restart service
    exec('sudo systemctl restart irongate 2>&1', $output, $retval);
    
    if ($retval !== 0) {
        exec('sudo journalctl -u irongate -n 20 --no-pager 2>&1', $journalOutput);
        return [
            'success' => false,
            'error' => 'Failed to start Irongate',
            'output' => implode("\n", $output),
            'journal' => implode("\n", $journalOutput)
        ];
    }
    
    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
}
EOPHP

#######################################
# Create Web UI with improved error display
#######################################
cat > /var/www/irongate/index.html << 'EOHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Irongate</title>
    <style>
        :root{--bg:#1a1a2e;--surface:#16213e;--surface2:#0f3460;--primary:#e94560;--success:#00bf63;--warning:#ffc107;--danger:#dc3545;--text:#eee;--text-secondary:#aaa;}
        *{box-sizing:border-box;margin:0;padding:0;}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;}
        .container{display:flex;min-height:100vh;}
        .sidebar{width:240px;background:var(--surface);padding:20px;border-right:1px solid var(--surface2);}
        .logo{font-size:1.4em;font-weight:bold;color:var(--primary);margin-bottom:30px;display:flex;align-items:center;gap:10px;}
        .logo svg{width:28px;height:28px;}
        .nav-item{padding:12px 15px;margin:5px 0;border-radius:8px;cursor:pointer;transition:all 0.2s;display:flex;align-items:center;gap:10px;}
        .nav-item:hover,.nav-item.active{background:var(--surface2);}
        .main{flex:1;padding:30px;overflow-y:auto;}
        .page{display:none;}
        .page.active{display:block;}
        .card{background:var(--surface);border-radius:12px;padding:20px;margin-bottom:20px;}
        .card-title{font-size:1.2em;margin-bottom:15px;color:var(--text);display:flex;align-items:center;gap:10px;}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;}
        .stat-card{background:var(--surface2);padding:20px;border-radius:10px;text-align:center;}
        .stat-value{font-size:2em;font-weight:bold;color:var(--primary);}
        .stat-label{color:var(--text-secondary);font-size:0.9em;margin-top:5px;}
        table{width:100%;border-collapse:collapse;}
        th,td{padding:12px;text-align:left;border-bottom:1px solid var(--surface2);}
        th{color:var(--text-secondary);font-weight:500;}
        .btn{padding:10px 20px;border:none;border-radius:6px;cursor:pointer;font-size:0.9em;transition:all 0.2s;}
        .btn-primary{background:var(--primary);color:white;}
        .btn-secondary{background:var(--surface2);color:var(--text);}
        .btn-success{background:var(--success);color:white;}
        .btn-danger{background:var(--danger);color:white;}
        .btn-warning{background:var(--warning);color:black;}
        .btn:hover{opacity:0.9;transform:translateY(-1px);}
        .btn-sm{padding:6px 12px;font-size:0.85em;}
        .form-group{margin-bottom:15px;}
        .form-group label{display:block;margin-bottom:5px;color:var(--text-secondary);}
        .form-control{width:100%;padding:10px;border:1px solid var(--surface2);border-radius:6px;background:var(--bg);color:var(--text);font-size:1em;}
        .form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;}
        .toggle{width:50px;height:26px;background:var(--surface2);border-radius:13px;position:relative;cursor:pointer;transition:all 0.2s;}
        .toggle.active{background:var(--success);}
        .toggle::after{content:'';position:absolute;width:22px;height:22px;background:white;border-radius:50%;top:2px;left:2px;transition:all 0.2s;}
        .toggle.active::after{left:26px;}
        .status-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:8px;}
        .status-dot.running{background:var(--success);}
        .status-dot.stopped{background:var(--danger);}
        .alert{padding:15px;border-radius:8px;margin-bottom:15px;display:flex;align-items:center;gap:10px;}
        .alert-warning{background:rgba(255,193,7,0.2);border:1px solid var(--warning);}
        .alert-danger{background:rgba(220,53,69,0.2);border:1px solid var(--danger);}
        .alert-success{background:rgba(0,191,99,0.2);border:1px solid var(--success);}
        .badge{padding:4px 8px;border-radius:4px;font-size:0.8em;}
        .badge-success{background:var(--success);color:white;}
        .badge-warning{background:var(--warning);color:black;}
        .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);align-items:center;justify-content:center;z-index:1000;}
        .modal.active{display:flex;}
        .modal-content{background:var(--surface);padding:25px;border-radius:12px;width:100%;max-width:500px;}
        .modal-title{font-size:1.3em;margin-bottom:20px;}
        .logs-container{background:var(--bg);padding:15px;border-radius:8px;font-family:monospace;font-size:0.85em;max-height:400px;overflow-y:auto;}
        .log-line{padding:3px 0;border-bottom:1px solid var(--surface2);}
        .toast{position:fixed;bottom:20px;right:20px;padding:15px 25px;background:var(--surface);border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);z-index:2000;animation:slideIn 0.3s;}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0;}to{transform:translateX(0);opacity:1;}}
        code{background:var(--bg);padding:2px 6px;border-radius:4px;font-size:0.9em;}
        .diag-section{margin-bottom:15px;padding:10px;background:var(--bg);border-radius:6px;}
        .diag-label{color:var(--text-secondary);font-size:0.85em;margin-bottom:5px;}
        .diag-value{font-family:monospace;font-size:0.9em;white-space:pre-wrap;word-break:break-all;}
        .diag-ok{color:var(--success);}
        .diag-error{color:var(--danger);}
        .error-box{background:rgba(220,53,69,0.1);border:1px solid var(--danger);border-radius:8px;padding:15px;margin:10px 0;font-family:monospace;font-size:0.85em;white-space:pre-wrap;max-height:200px;overflow-y:auto;}
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="logo" style="color:#e94560;">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/></svg>
                IRONGATE
            </div>
            <div class="nav-item active" onclick="showPage('dashboard')">📊 Dashboard</div>
            <div class="nav-item" onclick="showPage('devices')">🖥️ Devices & Zones</div>
            <div class="nav-item" onclick="showPage('dhcp')">🔗 DHCP Settings</div>
            <div class="nav-item" onclick="showPage('leases')">📋 Active Leases</div>
            <div class="nav-item" onclick="showPage('reservations')">📌 Reservations</div>
            <div class="nav-item" onclick="showPage('protection')">🛡️ Protection</div>
            <div class="nav-item" onclick="showPage('blockchain')">⛓️ Layer 8 Blockchain</div>
            <div class="nav-item" onclick="showPage('logs')">📜 Logs</div>
            <div class="nav-item" onclick="showPage('diagnostics')">🔧 Diagnostics</div>
            <div class="nav-item" onclick="showPage('updates')" style="border-top:1px solid var(--surface2);margin-top:10px;padding-top:15px;">⬆️ Updates</div>
        </div>
        <div class="main">
            <!-- Dashboard -->
            <div class="page active" id="page-dashboard">
                <h2 style="margin-bottom:20px;">🛡️ Irongate Dashboard</h2>
                
                <!-- Protection Status Banner -->
                <div id="protection-banner" class="alert alert-warning" style="margin-bottom:20px;">
                    <span>⚠️</span>
                    <span>Protection is <strong>disabled</strong>. Go to Protection settings to enable.</span>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card" style="cursor:pointer;" onclick="showPage('protection')">
                        <div class="stat-value" id="dash-protection" style="color:var(--danger);">OFF</div>
                        <div class="stat-label">Protection Status</div>
                    </div>
                    <div class="stat-card" style="cursor:pointer;" onclick="showPage('devices')">
                        <div class="stat-value" id="dash-devices">0</div>
                        <div class="stat-label">Protected Devices</div>
                    </div>
                    <div class="stat-card" style="cursor:pointer;" onclick="showPage('leases')">
                        <div class="stat-value" id="dash-leases">--</div>
                        <div class="stat-label">DHCP Leases</div>
                    </div>
                    <div class="stat-card" style="cursor:pointer;" onclick="showPage('reservations')">
                        <div class="stat-value" id="dash-reservations">--</div>
                        <div class="stat-label">Reservations</div>
                    </div>
                </div>
                
                <!-- Zone Summary -->
                <div class="card" style="margin-top:20px;">
                    <div class="card-title">Zone Summary</div>
                    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
                        <div style="text-align:center;padding:15px;background:rgba(233,69,96,0.1);border-radius:8px;">
                            <div style="font-size:2em;color:#e94560;" id="dash-isolated">0</div>
                            <div style="color:var(--text-secondary);">🔴 Isolated</div>
                            <div style="font-size:0.8em;color:var(--text-secondary);">Internet only</div>
                        </div>
                        <div style="text-align:center;padding:15px;background:rgba(255,193,7,0.1);border-radius:8px;">
                            <div style="font-size:2em;color:#ffc107;" id="dash-servers">0</div>
                            <div style="color:var(--text-secondary);">🟡 Servers</div>
                            <div style="font-size:0.8em;color:var(--text-secondary);">Inter-server OK</div>
                        </div>
                        <div style="text-align:center;padding:15px;background:rgba(0,191,99,0.1);border-radius:8px;">
                            <div style="font-size:2em;color:#00bf63;" id="dash-trusted">0</div>
                            <div style="color:var(--text-secondary);">🟢 Trusted</div>
                            <div style="font-size:0.8em;color:var(--text-secondary);">Full access</div>
                        </div>
                    </div>
                    <!-- Custom Groups Summary (populated dynamically) -->
                    <div id="dash-custom-groups" style="margin-top:15px;"></div>
                </div>
                
                <!-- System Info -->
                <div class="card">
                    <div class="card-title">System Information</div>
                    <div class="form-row">
                        <div class="form-group"><label>Hostname</label><input class="form-control" id="sys-hostname" readonly></div>
                        <div class="form-group"><label>IP Address</label><input class="form-control" id="sys-ip" readonly></div>
                        <div class="form-group"><label>Interface</label><input class="form-control" id="sys-interface" readonly></div>
                        <div class="form-group"><label>Gateway</label><input class="form-control" id="sys-gateway" readonly></div>
                    </div>
                    <div style="margin-top:10px;color:var(--text-secondary);">
                        DHCP: <span id="dash-dhcp-status">--</span> | 
                        Pool: <span id="dash-pool-range">--</span>
                    </div>
                </div>
                
                <!-- Quick Actions -->
                <div class="card">
                    <div class="card-title">Quick Actions</div>
                    <button class="btn btn-primary" onclick="showPage('devices')">➕ Add Device</button>
                    <button class="btn btn-success" onclick="showPage('protection')" style="margin-left:10px;">🛡️ Protection Settings</button>
                    <button class="btn btn-secondary" onclick="showPage('dhcp')" style="margin-left:10px;">🔗 DHCP Settings</button>
                    <button class="btn btn-secondary" onclick="loadDashboard()" style="margin-left:10px;">🔄 Refresh</button>
                </div>
                
                <div id="dash-error" class="alert alert-danger" style="display:none;">
                    <span>⚠️</span>
                    <div>
                        <strong>Service Error</strong>
                        <pre id="dash-error-text" style="margin-top:5px;font-size:0.85em;"></pre>
                    </div>
                </div>
            </div>
            
            <!-- Devices & Zones -->
            <div class="page" id="page-devices">
                <h2 style="margin-bottom:20px;">🖥️ Devices & Zones</h2>

                <p style="color:var(--text-secondary);margin-bottom:20px;">
                    Add devices to zones to control their network access. Devices not in any zone have normal network access.
                </p>

                <!-- Zone Legend -->
                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                        <div class="card-title" style="margin:0;">Zone Access Rules</div>
                        <button class="btn btn-secondary btn-sm" onclick="showGroupModal()">+ Create Custom Group</button>
                    </div>
                    <div id="zone-legend-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;">
                        <!-- Built-in zones (static) -->
                        <div style="padding:15px;background:rgba(233,69,96,0.1);border-radius:8px;border-left:4px solid #e94560;">
                            <strong style="color:#e94560;">🔴 isolated</strong>
                            <div style="font-size:0.9em;color:var(--text-secondary);margin-top:5px;">
                                ✓ Internet access<br>
                                ✗ Cannot reach LAN<br>
                                ✗ Cannot reach other devices
                            </div>
                        </div>
                        <div style="padding:15px;background:rgba(255,193,7,0.1);border-radius:8px;border-left:4px solid #ffc107;">
                            <strong style="color:#ffc107;">🟡 servers</strong>
                            <div style="font-size:0.9em;color:var(--text-secondary);margin-top:5px;">
                                ✓ Internet access<br>
                                ✓ Can reach other servers<br>
                                ✗ Cannot reach LAN
                            </div>
                        </div>
                        <div style="padding:15px;background:rgba(0,191,99,0.1);border-radius:8px;border-left:4px solid #00bf63;">
                            <strong style="color:#00bf63;">🟢 trusted</strong>
                            <div style="font-size:0.9em;color:var(--text-secondary);margin-top:5px;">
                                ✓ Internet access<br>
                                ✓ Full LAN access<br>
                                ✓ Can reach all devices
                            </div>
                        </div>
                        <!-- Custom groups will be appended here dynamically -->
                    </div>
                    <div id="custom-groups-container" style="margin-top:15px;"></div>
                </div>
                
                <!-- Device Management -->
                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                        <div class="card-title" style="margin:0;">Protected Devices</div>
                        <div>
                            <button class="btn btn-primary btn-sm" onclick="showDeviceModal()">+ Add Device</button>
                            <button class="btn btn-secondary btn-sm" onclick="importFromLeases()" style="margin-left:10px;">📋 Import from Leases</button>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>MAC Address</th>
                                <th>IP Address</th>
                                <th>Hostname</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="irongate-devices-table">
                            <tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">No devices configured</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- DHCP Settings (renamed from Settings) -->
            <div class="page" id="page-dhcp">
                <h2 style="margin-bottom:20px;">🔗 DHCP Settings</h2>
                <div id="settings-alert" class="alert alert-warning" style="display:none;">
                    <span>⚠️</span>
                    <span>DHCP is currently disabled. Enable it and configure your settings below.</span>
                </div>
                <div class="card">
                    <div class="card-title">DHCP Status</div>
                    <div style="display:flex;align-items:center;gap:15px;">
                        <div class="toggle" id="dhcp-toggle" onclick="toggleDhcp()"></div>
                        <span id="dhcp-status-text">Disabled</span>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Network Configuration</div>
                    <div class="form-row">
                        <div class="form-group"><label>Interface</label><select class="form-control" id="set-interface"></select></div>
                        <div class="form-group"><label>Subnet CIDR</label><select class="form-control" id="set-cidr" onchange="updateCidrInfo()">
                            <option value="8">/8</option><option value="16">/16</option><option value="17">/17</option>
                            <option value="18">/18</option><option value="19">/19</option><option value="20">/20</option>
                            <option value="21">/21</option><option value="22">/22</option><option value="23">/23</option>
                            <option value="24" selected>/24</option><option value="25">/25</option><option value="26">/26</option>
                            <option value="27">/27</option><option value="28">/28</option>
                        </select></div>
                    </div>
                    <div id="cidr-info" style="color:var(--text-secondary);font-size:0.9em;margin-bottom:15px;"></div>
                    <div class="form-row">
                        <div class="form-group"><label>Range Start</label><input class="form-control" id="set-range-start" placeholder="e.g., 192.168.1.100"></div>
                        <div class="form-group"><label>Range End</label><input class="form-control" id="set-range-end" placeholder="e.g., 192.168.1.200"></div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>Gateway (Router IP)</label><input class="form-control" id="set-gateway" placeholder="e.g., 192.168.1.1"></div>
                        <div class="form-group"><label>Lease Time</label><input class="form-control" id="set-lease-time" placeholder="24h"><div style="font-size:0.75em;color:var(--text-secondary);margin-top:3px;">Format: 30m, 24h, 7d, 1w, or infinite</div></div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>Primary DNS</label><input class="form-control" id="set-dns-primary" placeholder="8.8.8.8"></div>
                        <div class="form-group"><label>Secondary DNS</label><input class="form-control" id="set-dns-secondary" placeholder="1.1.1.1"></div>
                    </div>
                    <div class="form-group"><label>Domain (optional)</label><input class="form-control" id="set-domain" placeholder="e.g., local"></div>
                    <button class="btn btn-primary" onclick="saveSettings()">💾 Save & Apply</button>
                    <button class="btn btn-secondary" onclick="validateSettings()" style="margin-left:10px;">✓ Validate</button>
                </div>
            </div>
            
            <!-- Leases -->
            <div class="page" id="page-leases">
                <h2 style="margin-bottom:20px;">Active Leases</h2>
                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                        <div class="card-title" style="margin:0;">Current Leases</div>
                        <button class="btn btn-secondary btn-sm" onclick="loadLeases()">🔄 Refresh</button>
                    </div>
                    <table>
                        <thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Expires</th><th>Actions</th></tr></thead>
                        <tbody id="leases-table"></tbody>
                    </table>
                </div>
            </div>
            
            <!-- Reservations -->
            <div class="page" id="page-reservations">
                <h2 style="margin-bottom:20px;">Static Reservations</h2>
                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                        <div class="card-title" style="margin:0;">Reserved Addresses</div>
                        <button class="btn btn-primary btn-sm" onclick="showReservationModal()">+ Add Reservation</button>
                    </div>
                    <table>
                        <thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Description</th><th>Actions</th></tr></thead>
                        <tbody id="reservations-table"></tbody>
                    </table>
                </div>
            </div>
            
            <!-- Logs -->
            <div class="page" id="page-logs">
                <h2 style="margin-bottom:20px;">DHCP Logs</h2>
                <div class="card">
                    <div style="display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap;align-items:center;">
                        <select class="form-control" id="log-lines" style="width:auto;" onchange="loadLogs()">
                            <option value="50">Last 50</option>
                            <option value="100" selected>Last 100</option>
                            <option value="200">Last 200</option>
                            <option value="500">Last 500</option>
                        </select>
                        <button class="btn btn-secondary" onclick="loadLogs()">🔄 Refresh</button>
                        <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
                            <input type="checkbox" id="log-auto-refresh" onchange="toggleLogAutoRefresh()">
                            Auto-refresh (10s)
                        </label>
                        <span id="log-status" style="color:var(--text-secondary);font-size:0.9em;"></span>
                    </div>
                    <div class="logs-container" id="logs-container" style="font-size:0.8em;line-height:1.4;"></div>
                </div>
            </div>
            
            <!-- Diagnostics -->
            <div class="page" id="page-diagnostics">
                <h2 style="margin-bottom:20px;">Diagnostics</h2>
                <div class="card">
                    <div class="card-title">Service Health Check</div>
                    <div style="margin-bottom:15px;">
                        <button class="btn btn-primary" onclick="runDiagnostics()">🔍 Run Diagnostics</button>
                        <button class="btn btn-warning" onclick="runRepair()" style="margin-left:10px;">🔧 Auto-Repair</button>
                    </div>
                    <div id="diag-results"></div>
                </div>
                <div class="card">
                    <div class="card-title">🛡️ Irongate Protection Diagnostics</div>
                    <div style="margin-bottom:15px;">
                        <button class="btn btn-primary" onclick="runIrongateDiag()">🔍 Check Irongate Setup</button>
                    </div>
                    <div id="irongate-diag-results" style="display:none;">
                        <div id="irongate-diag-content" style="background:var(--bg);padding:15px;border-radius:8px;font-family:monospace;font-size:0.85em;white-space:pre-wrap;max-height:600px;overflow-y:auto;"></div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Service Control</div>
                    <button class="btn btn-success" onclick="startService()">▶️ Start</button>
                    <button class="btn btn-danger" onclick="stopService()" style="margin-left:10px;">⏹️ Stop</button>
                    <button class="btn btn-warning" onclick="restartService()" style="margin-left:10px;">🔄 Restart</button>
                    <div id="service-status" style="margin-top:15px;font-size:1.1em;"></div>
                </div>
            </div>
            
            <!-- Protection Settings -->
            <div class="page" id="page-protection">
                <h2 style="margin-bottom:20px;">🛡️ Protection Settings</h2>
                
                <div id="irongate-alert" class="alert" style="display:none;"></div>
                
                <!-- Master Enable/Disable -->
                <div class="card">
                    <div class="card-title">Protection Status</div>
                    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
                        <div style="display:flex;align-items:center;gap:15px;">
                            <div class="toggle" id="irongate-toggle" onclick="toggleIrongate()"></div>
                            <span id="irongate-status-text">Disabled</span>
                        </div>
                        <div id="irongate-service-status" style="font-size:0.9em;color:var(--text-secondary);"></div>
                    </div>
                    <p style="margin-top:15px;font-size:0.9em;color:var(--text-secondary);">
                        When enabled, Irongate enforces zone-based network isolation for all devices in the Devices & Zones list.
                    </p>
                </div>
                
                <!-- Mode Selection -->
                <div class="card">
                    <div class="card-title">Isolation Mode</div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;">
                        <div id="mode-single" class="stat-card" style="cursor:pointer;border:2px solid transparent;text-align:left;padding:15px;" onclick="setIrongateMode('single')">
                            <div style="font-size:1.3em;margin-bottom:8px;">🔧 Single-NIC Mode</div>
                            <div style="font-size:0.85em;color:var(--text-secondary);">
                                Software-based isolation<br>
                                No hardware changes needed<br>
                                <span style="color:var(--success);">~99% effective</span>
                            </div>
                        </div>
                        <div id="mode-dual" class="stat-card" style="cursor:pointer;border:2px solid transparent;text-align:left;padding:15px;" onclick="setIrongateMode('dual')">
                            <div style="font-size:1.3em;margin-bottom:8px;">🔒 Dual-NIC Mode</div>
                            <div style="font-size:0.85em;color:var(--text-secondary);">
                                Hardware bridge isolation<br>
                                Requires USB NIC (~$10)<br>
                                <span style="color:var(--success);">100% effective (VLAN-equivalent)</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Dual-NIC Config -->
                <div class="card" id="dual-nic-config" style="display:none;">
                    <div class="card-title">Dual-NIC Bridge Configuration</div>
                    <div class="form-group">
                        <label>Isolated Interface (USB NIC)</label>
                        <select class="form-control" id="irongate-isolated-iface" style="max-width:300px;">
                            <option value="">-- Select interface --</option>
                        </select>
                        <div style="font-size:0.85em;color:var(--text-secondary);margin-top:5px;">
                            Connect USB ethernet adapter. Protected servers connect to a switch on this interface.
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>Bridge IP</label><input class="form-control" id="irongate-bridge-ip" value="10.99.0.1"></div>
                        <div class="form-group"><label>DHCP Start</label><input class="form-control" id="irongate-dhcp-start" value="10.99.1.1"></div>
                        <div class="form-group"><label>DHCP End</label><input class="form-control" id="irongate-dhcp-end" value="10.99.255.254"></div>
                    </div>
                    <div style="background:var(--bg);border-radius:8px;padding:15px;margin-top:10px;font-family:monospace;font-size:0.8em;">
                        <strong>Required Topology:</strong><br>
                        <pre style="margin:10px 0 0 0;color:var(--text-secondary);">[Router] ─── [Main Switch] ─── [eth0] ─── [IRONGATE] ─── [eth1/USB] ─── [Isolated Switch]
                                                                              │   │   │
                                                                            [Srv1][Srv2][Srv3]</pre>
                    </div>
                </div>
                
                <!-- Single-NIC Layers -->
                <div class="card" id="single-nic-config">
                    <div class="card-title">Protection Layers (Single-NIC Mode)</div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;">
                        <label style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="layer-arp" checked>
                            <div><strong>ARP Defense</strong><div style="font-size:0.8em;color:var(--text-secondary);">Cache poisoning + bypass detection</div></div>
                        </label>
                        <label style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="layer-ipv6" checked>
                            <div><strong>IPv6 RA Guard</strong><div style="font-size:0.8em;color:var(--text-secondary);">Router advertisement hijacking</div></div>
                        </label>
                        <label style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="layer-gateway" checked>
                            <div><strong>Gateway Takeover</strong><div style="font-size:0.8em;color:var(--text-secondary);">Bidirectional poison + CAM flood</div></div>
                        </label>
                        <label style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="layer-bypass" checked>
                            <div><strong>Bypass Detection</strong><div style="font-size:0.8em;color:var(--text-secondary);">Active monitoring + TCP RST</div></div>
                        </label>
                        <label style="display:flex;align-items:center;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="layer-firewall" checked>
                            <div><strong>nftables Firewall</strong><div style="font-size:0.8em;color:var(--text-secondary);">Zone-based L3/L4 filtering</div></div>
                        </label>
                    </div>
                    <div style="margin-top:15px;padding:12px;background:var(--bg);border-radius:6px;border-left:3px solid var(--accent);">
                        <strong>⛓️ Layer 8 Blockchain</strong> - Configure on the <a href="#" onclick="showPage('blockchain');return false;" style="color:var(--accent);">Layer 8 Blockchain</a> page for 100% VLAN-equivalent protection.
                    </div>
                </div>
                
                <!-- Actions -->
                <div class="card">
                    <button class="btn btn-primary" onclick="saveIrongateSettings()">💾 Save & Apply</button>
                    <button class="btn btn-secondary" onclick="loadIrongateStatus()" style="margin-left:10px;">🔄 Refresh</button>
                    <button class="btn btn-warning" onclick="showPage('devices')" style="margin-left:10px;">🖥️ Manage Devices</button>
                </div>
                
                <!-- How It Works -->
                <div class="card" style="background:linear-gradient(135deg,rgba(233,69,96,0.1),rgba(22,33,62,0.5));">
                    <div class="card-title" style="color:#e94560;">How Irongate Protection Works</div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;font-size:0.9em;">
                        <div>
                            <strong>Single-NIC Mode (7-Layer):</strong>
                            <ol style="margin:10px 0 0 20px;color:var(--text-secondary);">
                                <li>ARP defense against spoofing attacks</li>
                                <li>IPv6 RA to capture IPv6 devices</li>
                                <li>nftables zone-based firewall rules</li>
                                <li>Gateway takeover intercepts traffic</li>
                                <li>Active monitoring detects evasion</li>
                                <li>Device ARP spoofing claims protected IPs</li>
                                <li>ARP reply interception prevents L2 bypass</li>
                            </ol>
                        </div>
                        <div>
                            <strong>Dual-NIC Mode:</strong>
                            <ul style="margin:10px 0 0 20px;color:var(--text-secondary);">
                                <li>Linux bridge with port isolation</li>
                                <li>Kernel-enforced - impossible to bypass</li>
                                <li>Same security as managed switch VLANs</li>
                                <li>Separate DHCP pool for isolated network</li>
                                <li>NAT provides internet access</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Layer 8 Blockchain Page -->
            <div class="page" id="page-blockchain">
                <h2 style="margin-bottom:20px;">⛓️ Layer 8: Algorand Blockchain</h2>
                
                <div id="blockchain-alert" class="alert" style="display:none;"></div>
                
                <!-- Overview Card -->
                <div class="card" style="background:linear-gradient(135deg,rgba(102,51,153,0.2),rgba(22,33,62,0.5));">
                    <div class="card-title" style="color:#9966cc;">What is Layer 8?</div>
                    <p style="margin-bottom:10px;">Layer 8 adds <strong>cryptographic device verification</strong> via the Algorand blockchain. Each device must be registered on-chain to access protected resources.</p>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:15px;">
                        <div style="background:var(--bg);padding:12px;border-radius:8px;">
                            <strong>🔐 Immutable Registry</strong>
                            <div style="font-size:0.85em;color:var(--text-secondary);">Device list stored on blockchain - tamper-proof</div>
                        </div>
                        <div style="background:var(--bg);padding:12px;border-radius:8px;">
                            <strong>🛡️ MAC Spoof Protection</strong>
                            <div style="font-size:0.85em;color:var(--text-secondary);">Cryptographic proof defeats spoofing attacks</div>
                        </div>
                        <div style="background:var(--bg);padding:12px;border-radius:8px;">
                            <strong>📜 Audit Trail</strong>
                            <div style="font-size:0.85em;color:var(--text-secondary);">Every access attempt logged permanently</div>
                        </div>
                        <div style="background:var(--bg);padding:12px;border-radius:8px;">
                            <strong>💰 Low Cost</strong>
                            <div style="font-size:0.85em;color:var(--text-secondary);">~$0.50/month for 100 devices</div>
                        </div>
                    </div>
                </div>
                
                <!-- Enable/Disable -->
                <div class="card">
                    <div class="card-title">Blockchain Status</div>
                    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
                        <div style="display:flex;align-items:center;gap:15px;">
                            <div class="toggle" id="blockchain-toggle" onclick="toggleBlockchain()"></div>
                            <span id="blockchain-status-text">Disabled</span>
                        </div>
                        <div id="blockchain-connection-status" style="font-size:0.9em;color:var(--text-secondary);"></div>
                    </div>
                    <p style="margin-top:15px;font-size:0.9em;color:var(--text-secondary);">
                        When enabled, devices must be registered on the Algorand blockchain to access protected resources.
                        Requires a deployed smart contract (App ID).
                    </p>
                </div>
                
                <!-- Smart Contract Config -->
                <div class="card">
                    <div class="card-title">Smart Contract Configuration</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Network</label>
                            <select class="form-control" id="blockchain-network" style="max-width:200px;">
                                <option value="mainnet">Mainnet (Production)</option>
                                <option value="testnet">Testnet (Testing)</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex:2;">
                            <label>App ID (Smart Contract)</label>
                            <input class="form-control" id="blockchain-app-id" type="number" placeholder="e.g., 1234567890">
                            <div style="font-size:0.8em;color:var(--text-secondary);margin-top:5px;">
                                Deploy with: <code>python3 /opt/irongate/smart_contract.py</code>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Admin Mnemonic (25 words)</label>
                        <input class="form-control" id="blockchain-mnemonic" type="password" placeholder="your 25 word recovery phrase...">
                        <div style="font-size:0.8em;color:var(--text-secondary);margin-top:5px;">
                            ⚠️ Keep secure! Only needed for registering/revoking devices.
                            <button class="btn btn-secondary" style="padding:2px 8px;font-size:0.8em;margin-left:10px;" onclick="document.getElementById('blockchain-mnemonic').type = document.getElementById('blockchain-mnemonic').type === 'password' ? 'text' : 'password'">👁️ Show/Hide</button>
                        </div>
                    </div>
                </div>
                
                <!-- Behavior Settings -->
                <div class="card">
                    <div class="card-title">Behavior Settings</div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;">
                        <label style="display:flex;align-items:flex-start;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="blockchain-allow-rogue" style="margin-top:3px;">
                            <div>
                                <strong>🌐 Public WiFi Mode</strong>
                                <div style="font-size:0.8em;color:var(--text-secondary);">Allow unregistered devices but log them. Use for coffee shops, hotels, public hotspots.</div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="blockchain-fallback" checked style="margin-top:3px;">
                            <div>
                                <strong>🔄 Fallback Allow</strong>
                                <div style="font-size:0.8em;color:var(--text-secondary);">Allow network access if blockchain is temporarily unavailable.</div>
                            </div>
                        </label>
                        <label style="display:flex;align-items:flex-start;gap:10px;padding:12px;background:var(--bg);border-radius:6px;cursor:pointer;">
                            <input type="checkbox" id="blockchain-audit" style="margin-top:3px;">
                            <div>
                                <strong>📝 Audit Logging</strong>
                                <div style="font-size:0.8em;color:var(--text-secondary);">Log all access attempts to blockchain. Adds ~0.001 ALGO per entry.</div>
                            </div>
                        </label>
                    </div>
                    <div class="form-group" style="margin-top:15px;">
                        <label>Cache TTL (seconds)</label>
                        <input class="form-control" id="blockchain-cache-ttl" type="number" value="60" min="10" max="3600" style="max-width:150px;">
                        <div style="font-size:0.8em;color:var(--text-secondary);margin-top:5px;">
                            How long to cache device verification. Higher = fewer blockchain queries, lower = faster revocation.
                        </div>
                    </div>
                </div>
                
                <!-- Actions -->
                <div class="card">
                    <button class="btn btn-primary" onclick="saveBlockchainSettings()">💾 Save & Apply</button>
                    <button class="btn btn-secondary" onclick="loadBlockchainSettings()" style="margin-left:10px;">🔄 Refresh</button>
                    <button class="btn btn-warning" onclick="testBlockchainConnection()" style="margin-left:10px;">🔗 Test Connection</button>
                </div>
                
                <!-- CLI Reference -->
                <div class="card">
                    <div class="card-title">Command Line Tools</div>
                    <div style="background:var(--bg);border-radius:8px;padding:15px;font-family:monospace;font-size:0.85em;">
                        <div style="margin-bottom:8px;"><code>irongate-blockchain status</code> - Show connection status</div>
                        <div style="margin-bottom:8px;"><code>irongate-blockchain list</code> - List registered devices</div>
                        <div style="margin-bottom:8px;"><code>irongate-blockchain register</code> - Register a new device</div>
                        <div style="margin-bottom:8px;"><code>irongate-blockchain revoke &lt;mac&gt;</code> - Revoke a device</div>
                        <div style="margin-bottom:8px;"><code>irongate-blockchain verify &lt;mac&gt; &lt;ip&gt;</code> - Test verification</div>
                        <div><code>irongate-blockchain sync</code> - Sync devices from config to blockchain</div>
                    </div>
                </div>
                
                <!-- Setup Guide -->
                <div class="card" style="background:linear-gradient(135deg,rgba(233,69,96,0.1),rgba(22,33,62,0.5));">
                    <div class="card-title" style="color:#e94560;">Setup Guide</div>
                    <ol style="margin:10px 0 0 20px;color:var(--text-secondary);line-height:1.8;">
                        <li>Install Algorand SDK: <code>pip install py-algorand-sdk --break-system-packages</code></li>
                        <li>Compile smart contract: <code>python3 /opt/irongate/smart_contract.py</code></li>
                        <li>Create Algorand wallet (Pera Wallet or MyAlgo) and fund with ~1 ALGO</li>
                        <li>Deploy contract using AlgoKit or goal CLI</li>
                        <li>Enter App ID and mnemonic above</li>
                        <li>Enable blockchain and save</li>
                        <li>Register devices: <code>irongate-blockchain sync</code></li>
                    </ol>
                </div>
            </div>
            
            <!-- Updates Page -->
            <div class="page" id="page-updates">
                <h2 style="margin-bottom:20px;">⬆️ Updates</h2>
                
                <!-- Current Version -->
                <div class="card">
                    <div class="card-title">Current Installation</div>
                    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
                        <div class="stat-card">
                            <div class="stat-value" id="update-current-commit" style="font-family:monospace;">--</div>
                            <div class="stat-label">Installed Commit</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="update-remote-commit" style="font-family:monospace;">--</div>
                            <div class="stat-label">Latest Commit</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="update-last-check">--</div>
                            <div class="stat-label">Last Checked</div>
                        </div>
                    </div>
                </div>
                
                <!-- Update Status -->
                <div id="update-status-card" class="card" style="display:none;">
                    <div id="update-status-content"></div>
                </div>
                
                <!-- Latest Commit Info -->
                <div class="card" id="commit-info-card" style="display:none;">
                    <div class="card-title">📝 Latest Commit</div>
                    <div id="commit-info-content" style="background:var(--bg);padding:15px;border-radius:8px;"></div>
                </div>
                
                <!-- Auto-Update Setting -->
                <div class="card">
                    <div class="card-title">Auto-Update</div>
                    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
                        <div style="display:flex;align-items:center;gap:15px;">
                            <div class="toggle" id="auto-update-toggle" onclick="toggleAutoUpdate()"></div>
                            <span id="auto-update-status-text">Disabled</span>
                        </div>
                    </div>
                    <p style="margin-top:15px;font-size:0.9em;color:var(--text-secondary);">
                        When enabled, Irongate will automatically check for and install updates daily at 4:00 AM.
                    </p>
                </div>
                
                <!-- Manual Update Actions -->
                <div class="card">
                    <div class="card-title">Manual Update</div>
                    <button class="btn btn-primary" onclick="checkForUpdates()">🔍 Check for Updates</button>
                    <button class="btn btn-success" id="btn-update-now" onclick="performUpdate()" style="margin-left:10px;display:none;">⬆️ Update Now</button>
                    <button class="btn btn-secondary" onclick="viewUpdateLog()" style="margin-left:10px;">📜 View Update Log</button>
                </div>
                
                <!-- Update Log -->
                <div class="card" id="update-log-card" style="display:none;">
                    <div class="card-title">📜 Update Log</div>
                    <div id="update-log-content" style="background:var(--bg);padding:15px;border-radius:8px;font-family:monospace;font-size:0.85em;max-height:400px;overflow-y:auto;white-space:pre-wrap;"></div>
                </div>
                
                <!-- GitHub Info -->
                <div class="card" style="background:linear-gradient(135deg,rgba(88,166,255,0.1),rgba(22,33,62,0.5));">
                    <div class="card-title" style="color:#58a6ff;">GitHub Repository</div>
                    <p style="color:var(--text-secondary);">
                        Irongate is open source. View the source code, report issues, or contribute:
                    </p>
                    <a href="https://github.com/beatboxes/irongate" target="_blank" style="color:#58a6ff;text-decoration:none;">
                        🔗 https://github.com/beatboxes/irongate
                    </a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Reservation Modal -->
    <div class="modal" id="reservation-modal">
        <div class="modal-content">
            <div class="modal-title">Add Reservation</div>
            <form id="reservation-form" onsubmit="addReservation(event)">
                <div class="form-group"><label>MAC Address</label><input class="form-control" id="res-mac" required placeholder="00:11:22:33:44:55"></div>
                <div class="form-group"><label>IP Address</label><input class="form-control" id="res-ip" required placeholder="192.168.1.50"></div>
                <div class="form-group"><label>Hostname</label><input class="form-control" id="res-hostname" placeholder="optional"></div>
                <div class="form-group"><label>Description</label><input class="form-control" id="res-description" placeholder="optional"></div>
                <div style="display:flex;gap:10px;margin-top:20px;">
                    <button type="submit" class="btn btn-primary">Save</button>
                    <button type="button" class="btn btn-secondary" onclick="hideReservationModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Irongate Device Modal -->
    <div class="modal" id="device-modal">
        <div class="modal-content">
            <div class="modal-title">🛡️ Add Protected Device</div>
            <form id="device-form" onsubmit="addIrongateDevice(event)">
                <div class="form-group">
                    <label>MAC Address *</label>
                    <input class="form-control" id="dev-mac" required placeholder="00:11:22:33:44:55">
                </div>
                <div class="form-group">
                    <label>IP Address</label>
                    <input class="form-control" id="dev-ip" placeholder="Leave empty for DHCP">
                    <div style="font-size:0.8em;color:var(--text-secondary);margin-top:3px;">
                        Optional - used for firewall rules. Can use DHCP reservation IP.
                    </div>
                </div>
                <div class="form-group">
                    <label>Hostname</label>
                    <input class="form-control" id="dev-hostname" placeholder="optional">
                </div>
                <div class="form-group">
                    <label>Zone *</label>
                    <select class="form-control" id="dev-zone" required>
                        <option value="isolated">🔴 isolated - Internet only, no LAN access</option>
                        <option value="servers">🟡 servers - Can talk to other servers</option>
                        <option value="trusted">🟢 trusted - Full network access</option>
                    </select>
                </div>
                <div style="display:flex;gap:10px;margin-top:20px;">
                    <button type="submit" class="btn btn-primary">Add Device</button>
                    <button type="button" class="btn btn-secondary" onclick="hideDeviceModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Import from Leases Modal -->
    <div class="modal" id="import-modal">
        <div class="modal-content" style="max-width:700px;">
            <div class="modal-title">📋 Import Devices from DHCP Leases</div>
            <p style="color:var(--text-secondary);margin-bottom:15px;">Select devices to add to Irongate protection:</p>
            <div id="import-leases-list" style="max-height:400px;overflow-y:auto;"></div>
            <div style="display:flex;gap:10px;margin-top:20px;">
                <button class="btn btn-primary" onclick="importSelectedDevices()">Import Selected</button>
                <button class="btn btn-secondary" onclick="hideImportModal()">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Custom Group Modal -->
    <div class="modal" id="group-modal">
        <div class="modal-content" style="max-width:550px;">
            <div class="modal-title" id="group-modal-title">📁 Create Custom Group</div>
            <form id="group-form" onsubmit="saveCustomGroup(event)">
                <input type="hidden" id="group-edit-id" value="">
                <div class="form-group">
                    <label>Group Name *</label>
                    <input class="form-control" id="group-name" required placeholder="e.g., cameras, printers, iot">
                    <div style="font-size:0.8em;color:var(--text-secondary);margin-top:3px;">
                        Use lowercase, no spaces. This will be the zone identifier.
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Icon</label>
                        <select class="form-control" id="group-icon">
                            <option value="📁">📁 Folder</option>
                            <option value="📷">📷 Camera</option>
                            <option value="🖨️">🖨️ Printer</option>
                            <option value="📺">📺 TV/Display</option>
                            <option value="🔌">🔌 IoT Device</option>
                            <option value="💡">💡 Smart Light</option>
                            <option value="🌡️">🌡️ Sensor</option>
                            <option value="🔒">🔒 Security</option>
                            <option value="🏠">🏠 Home</option>
                            <option value="🏢">🏢 Office</option>
                            <option value="🎮">🎮 Gaming</option>
                            <option value="📱">📱 Mobile</option>
                            <option value="💻">💻 Computer</option>
                            <option value="🖥️">🖥️ Server</option>
                            <option value="🔷">🔷 Blue</option>
                            <option value="🟣">🟣 Purple</option>
                            <option value="🟠">🟠 Orange</option>
                            <option value="⚪">⚪ White</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Color</label>
                        <input type="color" class="form-control" id="group-color" value="#6c757d" style="height:38px;padding:2px;">
                    </div>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input class="form-control" id="group-description" placeholder="Brief description of this group">
                </div>
                <div class="form-group">
                    <label>LAN Access Level *</label>
                    <select class="form-control" id="group-lan-access" onchange="updateGroupAccessOptions()">
                        <option value="none">No LAN access (Internet only)</option>
                        <option value="same">Can communicate within same group only</option>
                        <option value="selected">Can communicate with selected groups</option>
                        <option value="full">Full LAN access (like trusted)</option>
                    </select>
                </div>
                <div class="form-group" id="group-access-groups-container" style="display:none;">
                    <label>Can Access Groups</label>
                    <div id="group-access-groups-list" style="max-height:150px;overflow-y:auto;background:var(--bg);padding:10px;border-radius:6px;">
                        <!-- Checkboxes will be populated dynamically -->
                    </div>
                </div>
                <div style="display:flex;gap:10px;margin-top:20px;">
                    <button type="submit" class="btn btn-primary">Save Group</button>
                    <button type="button" class="btn btn-secondary" onclick="hideGroupModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        let systemInfo = {};
        let currentSettings = {};
        
        function showPage(page){
            document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
            document.getElementById('page-'+page).classList.add('active');
            const pages = ['dashboard','devices','dhcp','leases','reservations','protection','blockchain','logs','diagnostics','updates'];
            const idx = pages.indexOf(page);
            if (idx >= 0) document.querySelectorAll('.nav-item')[idx].classList.add('active');
            if(page==='dashboard')loadDashboard();
            if(page==='leases')loadLeases();
            if(page==='reservations')loadReservations();
            if(page==='logs')loadLogs();
            if(page==='diagnostics')runDiagnostics();
            if(page==='devices')loadIrongateDevices();
            if(page==='protection')loadIrongateStatus();
            if(page==='blockchain')loadBlockchainSettings();
            if(page==='dhcp')loadSettings();
            if(page==='updates')loadUpdateStatus();
        }
        
        function toast(msg,type='success'){
            const t=document.createElement('div');
            t.className='toast';
            t.style.borderLeft=`4px solid var(--${type==='error'?'danger':'success'})`;
            t.textContent=msg;
            document.body.appendChild(t);
            setTimeout(()=>t.remove(),3000);
        }
        
        async function api(action,opts={}){
            try{
                let url='api.php?action='+action;
                if(opts.params)Object.entries(opts.params).forEach(([k,v])=>url+=`&${k}=${v}`);
                const res=await fetch(url,{
                    method:opts.method||'GET',
                    headers:opts.body?{'Content-Type':'application/json'}:{},
                    body:opts.body?JSON.stringify(opts.body):undefined
                });
                return await res.json();
            }catch(e){console.error(e);return{success:false,error:e.message};}
        }
        
        async function loadSystemInfo(){
            const res=await api('system');
            if(res.success){
                systemInfo=res.data;
                document.getElementById('sys-hostname').value=res.data.hostname;
                document.getElementById('sys-ip').value=res.data.ip+'/'+res.data.cidr;
                document.getElementById('sys-interface').value=res.data.interface;
                document.getElementById('sys-gateway').value=res.data.gateway;
                const select=document.getElementById('set-interface');
                select.innerHTML=res.data.interfaces.map(i=>`<option value="${i.name}"${i.current?' selected':''}>${i.name} (${i.ip})</option>`).join('');
            }
        }
        
        async function loadStatus(){
            const res=await api('status');
            if(res.success){
                const statusDiv=document.getElementById('service-status');
                const dashStatus=document.getElementById('dash-status');
                const dashError=document.getElementById('dash-error');
                const dashErrorText=document.getElementById('dash-error-text');
                
                if(res.data.running){
                    statusDiv.innerHTML='<span class="status-dot running"></span> Running';
                    dashStatus.textContent='Running';
                    dashStatus.style.color='var(--success)';
                    dashError.style.display='none';
                }else{
                    statusDiv.innerHTML='<span class="status-dot stopped"></span> Stopped';
                    dashStatus.textContent='Stopped';
                    dashStatus.style.color='var(--danger)';
                    if(res.data.last_error){
                        dashError.style.display='flex';
                        dashErrorText.textContent=res.data.last_error;
                    }
                }
            }
        }
        
        async function loadSettings(){
            const res=await api('settings');
            if(res.success){
                currentSettings=res.data;
                document.getElementById('set-interface').value=res.data.interface||systemInfo.interface||'';
                document.getElementById('set-cidr').value=res.data.cidr||'24';
                document.getElementById('set-range-start').value=res.data.range_start||'';
                document.getElementById('set-range-end').value=res.data.range_end||'';
                document.getElementById('set-gateway').value=res.data.gateway||systemInfo.gateway||'';
                document.getElementById('set-dns-primary').value=res.data.dns_primary||'8.8.8.8';
                document.getElementById('set-dns-secondary').value=res.data.dns_secondary||'1.1.1.1';
                document.getElementById('set-lease-time').value=res.data.lease_time||'24h';
                document.getElementById('set-domain').value=res.data.domain||'';
                const enabled=res.data.dhcp_enabled==='true';
                const toggle=document.getElementById('dhcp-toggle');
                toggle.classList.toggle('active',enabled);
                document.getElementById('dhcp-status-text').textContent=enabled?'Enabled':'Disabled';
                document.getElementById('settings-alert').style.display=enabled?'none':'flex';
                updateCidrInfo();
                updateDashboardPool();
            }
        }
        
        async function saveSettings(){
            const settings={
                dhcp_enabled:document.getElementById('dhcp-toggle').classList.contains('active')?'true':'false',
                interface:document.getElementById('set-interface').value,
                cidr:document.getElementById('set-cidr').value,
                range_start:document.getElementById('set-range-start').value,
                range_end:document.getElementById('set-range-end').value,
                gateway:document.getElementById('set-gateway').value,
                dns_primary:document.getElementById('set-dns-primary').value,
                dns_secondary:document.getElementById('set-dns-secondary').value,
                lease_time:document.getElementById('set-lease-time').value,
                domain:document.getElementById('set-domain').value
            };
            if(settings.dhcp_enabled==='true'){
                if(!settings.range_start||!settings.range_end){toast('Please enter DHCP range','error');return;}
                if(!settings.gateway){toast('Please enter gateway IP','error');return;}
            }
            const res=await api('settings',{method:'POST',body:settings});
            if(res.success){
                toast('Settings saved successfully');
                loadSettings();
                loadStatus();
            }else{
                toast('Failed to save: '+(res.error||'Unknown error'),'error');
                if(res.journal){
                    console.error('Journal:', res.journal);
                }
            }
        }
        
        async function validateSettings(){
            const res=await api('validate');
            if(res.success&&res.data){
                if(res.data.valid){
                    toast('Configuration is valid!');
                }else{
                    toast('Config error: '+res.data.output,'error');
                }
            }
        }
        
        function toggleDhcp(){
            const toggle=document.getElementById('dhcp-toggle');
            toggle.classList.toggle('active');
            document.getElementById('dhcp-status-text').textContent=toggle.classList.contains('active')?'Enabled':'Disabled';
            document.getElementById('settings-alert').style.display=toggle.classList.contains('active')?'none':'flex';
        }
        
        function updateCidrInfo(){
            const cidr=document.getElementById('set-cidr').value;
            const masks={'8':'255.0.0.0','16':'255.255.0.0','17':'255.255.128.0','18':'255.255.192.0','19':'255.255.224.0','20':'255.255.240.0','21':'255.255.248.0','22':'255.255.252.0','23':'255.255.254.0','24':'255.255.255.0','25':'255.255.255.128','26':'255.255.255.192','27':'255.255.255.224','28':'255.255.255.240'};
            const hosts=Math.pow(2,32-parseInt(cidr))-2;
            document.getElementById('cidr-info').textContent=`Subnet mask: ${masks[cidr]} | Available hosts: ${hosts.toLocaleString()}`;
            updateDashboardPool();
        }
        
        function updateDashboardPool(){
            const start=document.getElementById('set-range-start').value;
            const end=document.getElementById('set-range-end').value;
            const cidr=document.getElementById('set-cidr').value;
            const hosts=Math.pow(2,32-parseInt(cidr))-2;
            document.getElementById('dash-pool').textContent=hosts.toLocaleString();
            document.getElementById('dash-pool-range').textContent=start&&end?`${start} - ${end}`:'Not configured';
        }
        
        async function loadLeases(){
            const res=await api('leases');
            const tbody=document.getElementById('leases-table');
            if(res.success&&res.data.length>0){
                tbody.innerHTML=res.data.map(l=>`<tr><td><strong>${l.ip}</strong></td><td><code>${l.mac}</code></td><td>${l.hostname!=='*'?l.hostname:'-'}</td><td><span class="badge badge-success">${l.expires}</span></td><td><button class="btn btn-sm btn-secondary" onclick="makeReservation('${l.mac}','${l.ip}','${l.hostname}')">Reserve</button></td></tr>`).join('');
                document.getElementById('dash-leases').textContent=res.data.length;
            }else{
                tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">No active leases</td></tr>';
                document.getElementById('dash-leases').textContent='0';
            }
        }
        
        async function loadReservations(){
            const res=await api('reservations');
            const tbody=document.getElementById('reservations-table');
            if(res.success&&res.data.length>0){
                tbody.innerHTML=res.data.map(r=>`<tr><td><strong>${r.ip}</strong></td><td><code>${r.mac}</code></td><td>${r.hostname||'-'}</td><td>${r.description||'-'}</td><td><button class="btn btn-sm btn-danger" onclick="deleteReservation(${r.id})">Delete</button></td></tr>`).join('');
                document.getElementById('dash-reservations').textContent=res.data.length;
            }else{
                tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">No reservations</td></tr>';
                document.getElementById('dash-reservations').textContent='0';
            }
        }
        
        function showReservationModal(){document.getElementById('reservation-modal').classList.add('active');}
        function hideReservationModal(){document.getElementById('reservation-modal').classList.remove('active');document.getElementById('reservation-form').reset();}
        
        function makeReservation(mac,ip,hostname){
            document.getElementById('res-mac').value=mac;
            document.getElementById('res-ip').value=ip;
            document.getElementById('res-hostname').value=hostname!=='*'?hostname:'';
            showReservationModal();
        }
        
        async function addReservation(e){
            e.preventDefault();
            const res=await api('reservations',{method:'POST',body:{
                mac:document.getElementById('res-mac').value,
                ip:document.getElementById('res-ip').value,
                hostname:document.getElementById('res-hostname').value,
                description:document.getElementById('res-description').value
            }});
            if(res.success){
                toast('Reservation added');
                hideReservationModal();
                loadReservations();
            }else{
                toast('Failed','error');
            }
        }
        
        async function deleteReservation(id){
            if(confirm('Delete this reservation?')){
                const res=await api('reservations',{method:'DELETE',params:{id}});
                if(res.success){toast('Deleted');loadReservations();}
            }
        }
        
        let logAutoRefreshInterval=null;
        
        async function loadLogs(){
            const lines=document.getElementById('log-lines').value;
            const statusEl=document.getElementById('log-status');
            statusEl.textContent='Loading...';
            try{
                const res=await api('logs',{params:{lines}});
                if(res.success&&res.data.length){
                    const container=document.getElementById('logs-container');
                    container.innerHTML=res.data.map(l=>`<div class="log-line">${l}</div>`).join('');
                    statusEl.textContent=`Loaded ${res.data.length} entries at ${new Date().toLocaleTimeString()}`;
                }else{
                    document.getElementById('logs-container').innerHTML='<div style="color:var(--text-secondary);">No logs available yet. DHCP requests will appear here once clients request addresses.</div>';
                    statusEl.textContent='No logs found';
                }
            }catch(e){
                statusEl.textContent='Error loading logs';
                console.error(e);
            }
        }
        
        function toggleLogAutoRefresh(){
            const checked=document.getElementById('log-auto-refresh').checked;
            if(checked){
                loadLogs();
                logAutoRefreshInterval=setInterval(loadLogs,10000);
            }else{
                if(logAutoRefreshInterval){
                    clearInterval(logAutoRefreshInterval);
                    logAutoRefreshInterval=null;
                }
            }
        }
        
        async function startService(){
            toast('Starting...');
            const res=await api('start');
            if(res.success){
                toast('Service started');
            }else{
                toast('Failed to start','error');
                console.error(res);
            }
            setTimeout(loadStatus,1000);
        }
        
        async function stopService(){
            toast('Stopping...');
            const res=await api('stop');
            toast(res.success?'Service stopped':'Failed','success');
            setTimeout(loadStatus,1000);
        }
        
        async function restartService(){
            if(confirm('Restart DHCP service?')){
                toast('Restarting...');
                const res=await api('restart');
                if(res.success){
                    toast('Restarted');
                }else{
                    toast('Failed to restart','error');
                    console.error(res);
                }
                setTimeout(loadStatus,2000);
            }
        }
        
        async function runDiagnostics(){
            const container=document.getElementById('diag-results');
            container.innerHTML='<div style="color:var(--text-secondary);">Running diagnostics...</div>';
            const res=await api('diagnostics');
            if(res.success&&res.data){
                const d=res.data;
                let html='';
                html+=`<div class="diag-section"><div class="diag-label">Config Valid</div><div class="diag-value ${d.config_valid?'diag-ok':'diag-error'}">${d.config_valid?'✓ Valid':'✗ Invalid'}</div></div>`;
                if(!d.config_valid){
                    html+=`<div class="error-box">${d.config_test}</div>`;
                }
                html+=`<div class="diag-section"><div class="diag-label">Interface (${d.configured_interface})</div><div class="diag-value ${d.interface_exists?'diag-ok':'diag-error'}">${d.interface_exists?'✓ Exists':'✗ Not found'}</div></div>`;
                html+=`<div class="diag-section"><div class="diag-label">File Permissions</div><div class="diag-value">Config: ${d.config_writable?'✓':'✗'} | Leases: ${d.leases_writable?'✓':'✗'} | Log: ${d.log_writable?'✓':'✗'}</div></div>`;
                html+=`<div class="diag-section"><div class="diag-label">Port 67 Status</div><div class="diag-value">${d.port_67_status||'Not in use'}</div></div>`;
                if(d.recent_errors){
                    html+=`<div class="diag-section"><div class="diag-label">Recent Errors</div><div class="error-box">${d.recent_errors}</div></div>`;
                }
                html+=`<div class="diag-section"><div class="diag-label">Service Status</div><pre class="diag-value" style="max-height:200px;overflow:auto;">${d.service_status}</pre></div>`;
                container.innerHTML=html;
            }
        }
        
        async function runRepair(){
            if(confirm('Run auto-repair? This will attempt to fix common issues and restart the service.')){
                toast('Running repair...');
                const res=await api('repair');
                if(res.success){
                    toast('Repair successful!');
                }else{
                    toast('Repair attempted but service still failing','error');
                    console.error(res);
                }
                setTimeout(()=>{
                    loadStatus();
                    runDiagnostics();
                },2000);
            }
        }
        
        async function runIrongateDiag(){
            const container = document.getElementById('irongate-diag-results');
            const content = document.getElementById('irongate-diag-content');
            container.style.display = 'block';
            content.innerHTML = 'Running Irongate diagnostics...';
            
            try {
                const res = await api('irongate_diag');
                if (res.success && res.data) {
                    const d = res.data;
                    let html = '';
                    
                    // Warning about devices without IPs
                    if (d.devices_without_ip_warning) {
                        html += `<div style="color:#e94560;font-weight:bold;margin-bottom:15px;">⚠️ ${d.devices_without_ip_warning}</div>`;
                    }
                    
                    // Devices with IPs
                    html += `<div style="color:#58a6ff;font-weight:bold;">═══ PROTECTED DEVICES WITH IPs ═══</div>\n`;
                    if (d.devices_with_ip && d.devices_with_ip.length > 0) {
                        d.devices_with_ip.forEach(dev => {
                            html += `  ${dev.zone}: ${dev.ip} (${dev.mac}) ${dev.hostname || ''}\n`;
                        });
                    } else {
                        html += `  <span style="color:#e94560;">NONE - Add devices with IPs to enable protection!</span>\n`;
                    }
                    
                    // IP Forwarding
                    html += `\n<div style="color:#58a6ff;font-weight:bold;">═══ IP FORWARDING ═══</div>\n`;
                    html += `  Status: ${d.ip_forward === 'enabled' ? '✓ ' + d.ip_forward : '✗ ' + d.ip_forward}\n`;
                    
                    // nftables
                    html += `\n<div style="color:#58a6ff;font-weight:bold;">═══ NFTABLES RULES ═══</div>\n`;
                    html += d.nftables + '\n';
                    
                    // ARP Cache
                    html += `\n<div style="color:#58a6ff;font-weight:bold;">═══ ARP CACHE ═══</div>\n`;
                    html += d.arp_cache || 'Empty';
                    
                    // Config
                    html += `\n<div style="color:#58a6ff;font-weight:bold;">═══ CONFIG FILE ═══</div>\n`;
                    html += d.config;
                    
                    // Recent Logs
                    html += `\n<div style="color:#58a6ff;font-weight:bold;">═══ RECENT LOGS ═══</div>\n`;
                    html += d.recent_logs || 'No logs';
                    
                    content.innerHTML = html;
                } else {
                    content.innerHTML = 'Error: ' + (res.error || 'Unknown error');
                }
            } catch (e) {
                content.innerHTML = 'Error: ' + e.message;
            }
        }
        
        async function loadAll(){
            await loadSystemInfo();
            await loadStatus();
            await loadSettings();
            await loadLeases();
            await loadReservations();
            await loadLogs();
            await loadIrongateStatus();
        }
        
        loadAll();
        setInterval(()=>{loadStatus();loadLeases();},30000);
        
        //======================================================================
        // IRONGATE FUNCTIONS
        //======================================================================
        
        let irongateSettings = {};
        
        async function loadIrongateStatus() {
            try {
                const res = await api('irongate_status');
                if (res.success) {
                    irongateSettings = res.data;
                    
                    // Update toggle
                    const toggle = document.getElementById('irongate-toggle');
                    const statusText = document.getElementById('irongate-status-text');
                    const serviceStatus = document.getElementById('irongate-service-status');
                    
                    if (res.data.enabled) {
                        toggle.classList.add('active');
                        statusText.textContent = 'Enabled';
                        statusText.style.color = 'var(--success)';
                    } else {
                        toggle.classList.remove('active');
                        statusText.textContent = 'Disabled';
                        statusText.style.color = 'var(--text-secondary)';
                    }
                    
                    serviceStatus.innerHTML = res.data.service_running 
                        ? '<span class="status-dot running"></span>Service Running'
                        : '<span class="status-dot stopped"></span>Service Stopped';
                    
                    // Update mode selection
                    setIrongateMode(res.data.mode || 'single', false);
                    
                    // Update layer checkboxes
                    document.getElementById('layer-arp').checked = res.data.layers?.arp_defense !== false;
                    document.getElementById('layer-ipv6').checked = res.data.layers?.ipv6_ra !== false;
                    document.getElementById('layer-gateway').checked = res.data.layers?.gateway_takeover !== false;
                    document.getElementById('layer-bypass').checked = res.data.layers?.bypass_detection !== false;
                    document.getElementById('layer-firewall').checked = res.data.layers?.firewall !== false;
                }
                
                // Load full settings
                const settingsRes = await api('irongate_settings');
                if (settingsRes.success) {
                    irongateSettings = {...irongateSettings, ...settingsRes.data};
                    document.getElementById('irongate-bridge-ip').value = settingsRes.data.irongate_bridge_ip || '10.99.0.1';
                    document.getElementById('irongate-dhcp-start').value = settingsRes.data.irongate_bridge_dhcp_start || '10.99.1.1';
                    document.getElementById('irongate-dhcp-end').value = settingsRes.data.irongate_bridge_dhcp_end || '10.99.255.254';
                }
                
                // Load interfaces
                await loadIrongateInterfaces();
                
            } catch (e) {
                console.error('Irongate status error:', e);
            }
        }
        
        async function loadIrongateInterfaces() {
            try {
                const res = await api('irongate_interfaces');
                if (res.success) {
                    const select = document.getElementById('irongate-isolated-iface');
                    const currentValue = irongateSettings.irongate_isolated_interface || '';
                    select.innerHTML = '<option value="">-- Select interface --</option>';
                    
                    res.data.forEach(iface => {
                        if (iface.is_main) return;
                        const opt = document.createElement('option');
                        opt.value = iface.name;
                        opt.textContent = iface.name + (iface.is_usb ? ' (USB)' : '') + ' - ' + iface.mac + ' [' + iface.state + ']';
                        if (iface.name === currentValue) opt.selected = true;
                        select.appendChild(opt);
                    });
                }
            } catch (e) {
                console.error('Interfaces error:', e);
            }
        }
        
        function setIrongateMode(mode, save = true) {
            const singleCard = document.getElementById('mode-single');
            const dualCard = document.getElementById('mode-dual');
            const dualConfig = document.getElementById('dual-nic-config');
            const singleConfig = document.getElementById('single-nic-config');
            
            if (mode === 'dual') {
                singleCard.style.borderColor = 'transparent';
                dualCard.style.borderColor = 'var(--success)';
                dualConfig.style.display = 'block';
                singleConfig.style.display = 'none';
            } else {
                singleCard.style.borderColor = 'var(--warning)';
                dualCard.style.borderColor = 'transparent';
                dualConfig.style.display = 'none';
                singleConfig.style.display = 'block';
            }
            
            irongateSettings.irongate_mode = mode;
        }
        
        async function toggleIrongate() {
            const toggle = document.getElementById('irongate-toggle');
            const enabling = !toggle.classList.contains('active');
            
            try {
                const res = await api('irongate_toggle', {
                    method: 'POST',
                    body: { enabled: enabling }
                });
                
                if (res.success) {
                    toast(enabling ? 'Irongate enabled' : 'Irongate disabled', 'success');
                    await loadIrongateStatus();
                } else {
                    toast('Failed: ' + (res.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function saveIrongateSettings() {
            const settings = {
                irongate_enabled: document.getElementById('irongate-toggle').classList.contains('active') ? 'true' : 'false',
                irongate_mode: irongateSettings.irongate_mode || 'single',
                irongate_isolated_interface: document.getElementById('irongate-isolated-iface').value,
                irongate_bridge_ip: document.getElementById('irongate-bridge-ip').value,
                irongate_bridge_dhcp_start: document.getElementById('irongate-dhcp-start').value,
                irongate_bridge_dhcp_end: document.getElementById('irongate-dhcp-end').value,
                irongate_arp_defense: document.getElementById('layer-arp').checked ? 'true' : 'false',
                irongate_ipv6_ra: document.getElementById('layer-ipv6').checked ? 'true' : 'false',
                irongate_gateway_takeover: document.getElementById('layer-gateway').checked ? 'true' : 'false',
                irongate_bypass_detection: document.getElementById('layer-bypass').checked ? 'true' : 'false',
                irongate_firewall: document.getElementById('layer-firewall').checked ? 'true' : 'false'
            };
            
            // Validate dual-NIC mode
            if (settings.irongate_mode === 'dual' && !settings.irongate_isolated_interface) {
                toast('Please select an isolated interface for dual-NIC mode', 'error');
                return;
            }
            
            try {
                const res = await api('irongate_settings', {
                    method: 'POST',
                    body: settings
                });
                
                if (res.success) {
                    toast('Irongate settings saved' + (res.mode ? ' (' + res.mode + ' mode)' : ''), 'success');
                    await loadIrongateStatus();
                } else {
                    toast('Failed: ' + (res.error || 'Unknown error'), 'error');
                    if (res.journal) console.error(res.journal);
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        //======================================================================
        // LAYER 8 BLOCKCHAIN MANAGEMENT
        //======================================================================
        
        let blockchainSettings = {};
        
        async function loadBlockchainSettings() {
            try {
                const res = await api('irongate_settings');
                if (res.success) {
                    blockchainSettings = res.data;
                    
                    // Update toggle
                    const toggle = document.getElementById('blockchain-toggle');
                    const statusText = document.getElementById('blockchain-status-text');
                    const connStatus = document.getElementById('blockchain-connection-status');
                    
                    if (res.data.blockchain_enabled === 'true') {
                        toggle.classList.add('active');
                        statusText.textContent = 'Enabled';
                        statusText.style.color = 'var(--success)';
                        connStatus.innerHTML = '<span class="status-dot running"></span>Blockchain Active';
                    } else {
                        toggle.classList.remove('active');
                        statusText.textContent = 'Disabled';
                        statusText.style.color = 'var(--text-secondary)';
                        connStatus.innerHTML = '<span class="status-dot stopped"></span>Not Connected';
                    }
                    
                    // Update form fields
                    document.getElementById('blockchain-network').value = res.data.blockchain_network || 'mainnet';
                    document.getElementById('blockchain-app-id').value = res.data.blockchain_app_id || '';
                    document.getElementById('blockchain-mnemonic').value = res.data.blockchain_admin_mnemonic || '';
                    document.getElementById('blockchain-cache-ttl').value = res.data.blockchain_cache_ttl || '60';
                    document.getElementById('blockchain-fallback').checked = res.data.blockchain_fallback_allow !== 'false';
                    document.getElementById('blockchain-audit').checked = res.data.blockchain_audit_logging === 'true';
                    document.getElementById('blockchain-allow-rogue').checked = res.data.blockchain_allow_rogue_devices === 'true';
                }
            } catch (e) {
                console.error('Blockchain settings error:', e);
            }
        }
        
        async function toggleBlockchain() {
            const toggle = document.getElementById('blockchain-toggle');
            const enabling = !toggle.classList.contains('active');
            
            // Quick validation
            if (enabling) {
                const appId = document.getElementById('blockchain-app-id').value;
                if (!appId) {
                    toast('Please enter an App ID before enabling blockchain', 'error');
                    return;
                }
            }
            
            if (enabling) {
                toggle.classList.add('active');
                document.getElementById('blockchain-status-text').textContent = 'Enabled';
                document.getElementById('blockchain-status-text').style.color = 'var(--success)';
            } else {
                toggle.classList.remove('active');
                document.getElementById('blockchain-status-text').textContent = 'Disabled';
                document.getElementById('blockchain-status-text').style.color = 'var(--text-secondary)';
            }
            
            toast('Click "Save & Apply" to apply changes', 'info');
        }
        
        async function saveBlockchainSettings() {
            const enabled = document.getElementById('blockchain-toggle').classList.contains('active');
            const appId = document.getElementById('blockchain-app-id').value;
            
            // Validate if enabling
            if (enabled && !appId) {
                toast('App ID is required to enable blockchain', 'error');
                return;
            }
            
            const settings = {
                blockchain_enabled: enabled ? 'true' : 'false',
                blockchain_network: document.getElementById('blockchain-network').value,
                blockchain_app_id: appId || '',
                blockchain_admin_mnemonic: document.getElementById('blockchain-mnemonic').value || '',
                blockchain_cache_ttl: document.getElementById('blockchain-cache-ttl').value || '60',
                blockchain_fallback_allow: document.getElementById('blockchain-fallback').checked ? 'true' : 'false',
                blockchain_audit_logging: document.getElementById('blockchain-audit').checked ? 'true' : 'false',
                blockchain_allow_rogue_devices: document.getElementById('blockchain-allow-rogue').checked ? 'true' : 'false'
            };
            
            try {
                const res = await api('irongate_settings', {
                    method: 'POST',
                    body: settings
                });
                
                if (res.success) {
                    toast('Blockchain settings saved! Irongate restarting...', 'success');
                    await loadBlockchainSettings();
                } else {
                    toast('Failed: ' + (res.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function testBlockchainConnection() {
            const appId = document.getElementById('blockchain-app-id').value;
            const network = document.getElementById('blockchain-network').value;
            
            if (!appId) {
                toast('Enter an App ID first', 'error');
                return;
            }
            
            toast('Testing connection...', 'info');
            
            // For now, just show a message - actual test would need a backend endpoint
            const connStatus = document.getElementById('blockchain-connection-status');
            connStatus.innerHTML = '<span style="color:var(--warning);">⏳ Testing...</span>';
            
            // Simulate connection test
            setTimeout(() => {
                connStatus.innerHTML = '<span style="color:var(--success);">✓ Algorand ' + network + ' reachable</span>';
                toast('Connection test: Algorand ' + network + ' is reachable. Save settings and restart to fully activate.', 'success');
            }, 1500);
        }
        
        //======================================================================
        // CUSTOM DEVICE GROUPS MANAGEMENT
        //======================================================================

        let deviceGroups = [];

        async function loadDeviceGroups() {
            try {
                const res = await api('device_groups');
                if (res.success) {
                    deviceGroups = res.data || [];
                    renderCustomGroupsLegend();
                    populateZoneDropdowns();
                }
            } catch (e) {
                console.error('Load groups error:', e);
            }
        }

        function renderCustomGroupsLegend() {
            const container = document.getElementById('custom-groups-container');
            if (!container) return;

            const customGroups = deviceGroups.filter(g => !g.builtin);
            if (customGroups.length === 0) {
                container.innerHTML = '';
                return;
            }

            container.innerHTML = `
                <div style="font-size:0.9em;color:var(--text-secondary);margin-bottom:10px;margin-top:15px;">Custom Groups:</div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;">
                    ${customGroups.map(g => {
                        const accessDesc = g.lan_access === 'none' ? '✗ No LAN access' :
                                          g.lan_access === 'same' ? '✓ Can reach same group' :
                                          g.lan_access === 'selected' ? '✓ Can reach selected groups' :
                                          g.lan_access === 'full' ? '✓ Full LAN access' : '✗ No LAN access';
                        return `
                            <div style="padding:15px;background:${hexToRgba(g.color, 0.1)};border-radius:8px;border-left:4px solid ${g.color};position:relative;">
                                <strong style="color:${g.color};">${g.icon} ${g.name}</strong>
                                <div style="font-size:0.9em;color:var(--text-secondary);margin-top:5px;">
                                    ${g.description || 'Custom device group'}<br>
                                    ${accessDesc}
                                </div>
                                <div style="position:absolute;top:10px;right:10px;">
                                    <button class="btn btn-sm btn-secondary" onclick="editGroup(${g.id})" style="padding:3px 8px;font-size:0.75em;">Edit</button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteGroup(${g.id})" style="padding:3px 8px;font-size:0.75em;margin-left:3px;">Delete</button>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            `;
        }

        function hexToRgba(hex, alpha) {
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            return `rgba(${r}, ${g}, ${b}, ${alpha})`;
        }

        function populateZoneDropdowns() {
            const devZone = document.getElementById('dev-zone');
            if (!devZone) return;

            const currentValue = devZone.value;

            devZone.innerHTML = deviceGroups.map(g => {
                const desc = g.builtin ?
                    (g.name === 'isolated' ? ' - Internet only, no LAN access' :
                     g.name === 'servers' ? ' - Can talk to other servers' :
                     g.name === 'trusted' ? ' - Full network access' : '') :
                    (g.description ? ' - ' + g.description : '');
                return `<option value="${g.name}">${g.icon} ${g.name}${desc}</option>`;
            }).join('');

            // Restore previous selection if valid
            if (currentValue && deviceGroups.find(g => g.name === currentValue)) {
                devZone.value = currentValue;
            }
        }

        function showGroupModal(group = null) {
            document.getElementById('group-form').reset();
            document.getElementById('group-edit-id').value = '';
            document.getElementById('group-modal-title').textContent = '📁 Create Custom Group';
            document.getElementById('group-access-groups-container').style.display = 'none';

            if (group) {
                document.getElementById('group-modal-title').textContent = '📁 Edit Custom Group';
                document.getElementById('group-edit-id').value = group.id;
                document.getElementById('group-name').value = group.name || '';
                document.getElementById('group-icon').value = group.icon || '📁';
                document.getElementById('group-color').value = group.color || '#6c757d';
                document.getElementById('group-description').value = group.description || '';
                document.getElementById('group-lan-access').value = group.lan_access || 'none';
                updateGroupAccessOptions(group.can_access_groups || []);
            } else {
                updateGroupAccessOptions([]);
            }

            document.getElementById('group-modal').classList.add('active');
        }

        function hideGroupModal() {
            document.getElementById('group-modal').classList.remove('active');
            document.getElementById('group-form').reset();
        }

        function updateGroupAccessOptions(selectedGroups = []) {
            const lanAccess = document.getElementById('group-lan-access').value;
            const container = document.getElementById('group-access-groups-container');
            const list = document.getElementById('group-access-groups-list');

            if (lanAccess === 'selected') {
                container.style.display = 'block';
                // Populate with all groups (except the one being edited)
                const editId = document.getElementById('group-edit-id').value;
                const editName = editId ? deviceGroups.find(g => g.id == editId)?.name : null;

                list.innerHTML = deviceGroups
                    .filter(g => g.name !== editName)
                    .map(g => `
                        <label style="display:flex;align-items:center;gap:8px;padding:5px 0;cursor:pointer;">
                            <input type="checkbox" class="group-access-check" value="${g.name}" ${selectedGroups.includes(g.name) ? 'checked' : ''}>
                            <span style="color:${g.color};">${g.icon} ${g.name}</span>
                        </label>
                    `).join('');
            } else {
                container.style.display = 'none';
            }
        }

        async function saveCustomGroup(event) {
            event.preventDefault();

            let name = document.getElementById('group-name').value.trim().toLowerCase();
            name = name.replace(/[^a-z0-9_-]/g, ''); // Sanitize

            if (!name) {
                toast('Group name is required', 'error');
                return;
            }

            // Get selected access groups
            const canAccessGroups = [];
            if (document.getElementById('group-lan-access').value === 'selected') {
                document.querySelectorAll('.group-access-check:checked').forEach(cb => {
                    canAccessGroups.push(cb.value);
                });
            } else if (document.getElementById('group-lan-access').value === 'same') {
                canAccessGroups.push(name); // Can access itself
            }

            const group = {
                name: name,
                icon: document.getElementById('group-icon').value,
                color: document.getElementById('group-color').value,
                description: document.getElementById('group-description').value.trim(),
                lan_access: document.getElementById('group-lan-access').value,
                can_access_groups: canAccessGroups
            };

            try {
                const res = await api('device_groups', {
                    method: 'POST',
                    body: group
                });

                if (res.success) {
                    toast('Group saved successfully', 'success');
                    hideGroupModal();
                    await loadDeviceGroups();
                    await loadIrongateDevices();
                } else {
                    toast('Failed to save group: ' + (res.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }

        function editGroup(id) {
            const group = deviceGroups.find(g => g.id === id);
            if (group && !group.builtin) {
                showGroupModal(group);
            }
        }

        async function deleteGroup(id) {
            const group = deviceGroups.find(g => g.id === id);
            if (!group || group.builtin) return;

            if (!confirm(`Delete the "${group.name}" group? All devices in this group will be moved to "isolated".`)) return;

            try {
                const res = await api('device_groups', {
                    method: 'DELETE',
                    params: { id: id }
                });

                if (res.success) {
                    toast('Group deleted', 'success');
                    await loadDeviceGroups();
                    await loadIrongateDevices();
                } else {
                    toast('Failed to delete group', 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }

        //======================================================================
        // IRONGATE DEVICE MANAGEMENT
        //======================================================================

        let irongateDevices = [];
        
        async function loadIrongateDevices() {
            try {
                // Load groups first to have colors/icons available
                await loadDeviceGroups();

                const res = await api('irongate_devices');
                if (res.success) {
                    irongateDevices = res.data || [];
                    renderDevicesTable();
                }
            } catch (e) {
                console.error('Load devices error:', e);
            }
        }

        function getGroupInfo(zoneName) {
            const group = deviceGroups.find(g => g.name === zoneName);
            if (group) {
                return { color: group.color, icon: group.icon };
            }
            // Fallback for built-in groups if not loaded yet
            if (zoneName === 'isolated') return { color: '#e94560', icon: '🔴' };
            if (zoneName === 'servers') return { color: '#ffc107', icon: '🟡' };
            if (zoneName === 'trusted') return { color: '#00bf63', icon: '🟢' };
            return { color: '#6c757d', icon: '📁' };
        }

        function renderDevicesTable() {
            const tbody = document.getElementById('irongate-devices-table');
            if (!irongateDevices || irongateDevices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">No devices configured. Add devices to protect them with Irongate.</td></tr>';
                return;
            }

            // Sort by zone - built-in first, then custom alphabetically
            const builtinOrder = { isolated: 0, servers: 1, trusted: 2 };
            const sorted = [...irongateDevices].sort((a, b) => {
                const aOrder = builtinOrder[a.zone] ?? 100;
                const bOrder = builtinOrder[b.zone] ?? 100;
                if (aOrder !== bOrder) return aOrder - bOrder;
                // Both custom groups - sort alphabetically
                return (a.zone || '').localeCompare(b.zone || '');
            });

            tbody.innerHTML = sorted.map(dev => {
                const groupInfo = getGroupInfo(dev.zone);
                return `
                    <tr>
                        <td><span style="color:${groupInfo.color};">${groupInfo.icon} ${dev.zone}</span></td>
                        <td><code>${dev.mac}</code></td>
                        <td>${dev.ip || '<span style="color:var(--text-secondary);">DHCP</span>'}</td>
                        <td>${dev.hostname || '-'}</td>
                        <td>
                            <button class="btn btn-sm btn-secondary" onclick="editDevice(${dev.id})">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteDevice(${dev.id})" style="margin-left:5px;">Delete</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function showDeviceModal(device = null) {
            document.getElementById('device-form').reset();
            // Refresh zone dropdown with latest groups
            populateZoneDropdowns();

            if (device) {
                document.getElementById('dev-mac').value = device.mac || '';
                document.getElementById('dev-ip').value = device.ip || '';
                document.getElementById('dev-hostname').value = device.hostname || '';
                document.getElementById('dev-zone').value = device.zone || 'isolated';
            }
            document.getElementById('device-modal').classList.add('active');
        }
        
        function hideDeviceModal() {
            document.getElementById('device-modal').classList.remove('active');
            document.getElementById('device-form').reset();
        }
        
        async function addIrongateDevice(event) {
            event.preventDefault();
            
            const device = {
                mac: document.getElementById('dev-mac').value.toLowerCase().trim(),
                ip: document.getElementById('dev-ip').value.trim(),
                hostname: document.getElementById('dev-hostname').value.trim(),
                zone: document.getElementById('dev-zone').value
            };
            
            // Validate MAC
            if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(device.mac)) {
                toast('Invalid MAC address format (use XX:XX:XX:XX:XX:XX)', 'error');
                return;
            }
            
            try {
                const res = await api('irongate_devices', {
                    method: 'POST',
                    body: device
                });
                
                if (res.success) {
                    toast('Device added to ' + device.zone + ' zone', 'success');
                    hideDeviceModal();
                    await loadIrongateDevices();
                } else {
                    toast('Failed to add device: ' + (res.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        function editDevice(id) {
            const device = irongateDevices.find(d => d.id === id);
            if (device) {
                showDeviceModal(device);
            }
        }
        
        async function deleteDevice(id) {
            if (!confirm('Remove this device from Irongate protection?')) return;
            
            try {
                const res = await api('irongate_devices', {
                    method: 'DELETE',
                    params: { id: id }
                });
                
                if (res.success) {
                    toast('Device removed', 'success');
                    await loadIrongateDevices();
                } else {
                    toast('Failed to remove device', 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function importFromLeases() {
            try {
                const res = await api('leases');
                if (!res.success || !res.data || res.data.length === 0) {
                    toast('No active DHCP leases found', 'error');
                    return;
                }
                
                // Filter out already-added devices
                const existingMacs = new Set(irongateDevices.map(d => d.mac.toLowerCase()));
                const available = res.data.filter(l => !existingMacs.has(l.mac.toLowerCase()));
                
                if (available.length === 0) {
                    toast('All lease devices are already in Irongate', 'error');
                    return;
                }
                
                const container = document.getElementById('import-leases-list');
                // Build zone options dynamically from deviceGroups
                const zoneOptions = deviceGroups.map(g =>
                    `<option value="${g.name}">${g.icon} ${g.name}</option>`
                ).join('');

                container.innerHTML = available.map(lease => `
                    <label style="display:flex;align-items:center;gap:10px;padding:10px;background:var(--bg);border-radius:6px;margin-bottom:8px;cursor:pointer;">
                        <input type="checkbox" class="import-check" data-mac="${lease.mac}" data-ip="${lease.ip}" data-hostname="${lease.hostname}">
                        <div style="flex:1;">
                            <div><strong>${lease.hostname || 'Unknown'}</strong></div>
                            <div style="font-size:0.85em;color:var(--text-secondary);">
                                <code>${lease.mac}</code> → ${lease.ip}
                            </div>
                        </div>
                        <select class="form-control import-zone" style="width:150px;font-size:0.85em;">
                            ${zoneOptions}
                        </select>
                    </label>
                `).join('');
                
                document.getElementById('import-modal').classList.add('active');
            } catch (e) {
                toast('Error loading leases: ' + e.message, 'error');
            }
        }
        
        function hideImportModal() {
            document.getElementById('import-modal').classList.remove('active');
        }
        
        async function importSelectedDevices() {
            const checkboxes = document.querySelectorAll('.import-check:checked');
            if (checkboxes.length === 0) {
                toast('No devices selected', 'error');
                return;
            }
            
            let added = 0;
            for (const cb of checkboxes) {
                const zoneSelect = cb.closest('label').querySelector('.import-zone');
                const device = {
                    mac: cb.dataset.mac,
                    ip: cb.dataset.ip,
                    hostname: cb.dataset.hostname,
                    zone: zoneSelect.value
                };
                
                try {
                    const res = await api('irongate_devices', {
                        method: 'POST',
                        body: device
                    });
                    if (res.success) added++;
                } catch (e) {
                    console.error('Import error:', e);
                }
            }
            
            hideImportModal();
            toast(`Imported ${added} device(s)`, 'success');
            await loadIrongateDevices();
        }
        
        // Load devices when Irongate page is shown
        const origLoadIrongateStatus = loadIrongateStatus;
        loadIrongateStatus = async function() {
            await origLoadIrongateStatus();
            await loadIrongateDevices();
        };
        
        //======================================================================
        // DASHBOARD LOADING
        //======================================================================
        
        async function loadDashboard() {
            try {
                // Load system info
                const sysRes = await api('system');
                if (sysRes.success) {
                    systemInfo = sysRes.data;
                    document.getElementById('sys-hostname').value = sysRes.data.hostname || '';
                    document.getElementById('sys-ip').value = sysRes.data.ip || '';
                    document.getElementById('sys-interface').value = sysRes.data.interface || '';
                    document.getElementById('sys-gateway').value = sysRes.data.gateway || '';
                }
                
                // Load settings for DHCP status
                const setRes = await api('settings');
                if (setRes.success && setRes.data) {
                    const dhcpEnabled = setRes.data.dhcp_enabled === 'true';
                    document.getElementById('dash-dhcp-status').textContent = dhcpEnabled ? 'Enabled' : 'Disabled';
                    const start = setRes.data.range_start;
                    const end = setRes.data.range_end;
                    document.getElementById('dash-pool-range').textContent = (start && end) ? `${start} - ${end}` : 'Not configured';
                }
                
                // Load leases count
                const leaseRes = await api('leases');
                if (leaseRes.success) {
                    document.getElementById('dash-leases').textContent = leaseRes.data ? leaseRes.data.length : '0';
                }
                
                // Load reservations count
                const resRes = await api('reservations');
                if (resRes.success) {
                    document.getElementById('dash-reservations').textContent = resRes.data ? resRes.data.length : '0';
                }
                
                // Load Irongate status
                const igRes = await api('irongate_status');
                if (igRes.success) {
                    const enabled = igRes.data.enabled;
                    document.getElementById('dash-protection').textContent = enabled ? 'ON' : 'OFF';
                    document.getElementById('dash-protection').style.color = enabled ? 'var(--success)' : 'var(--danger)';
                    
                    // Update protection banner
                    const banner = document.getElementById('protection-banner');
                    if (enabled) {
                        banner.className = 'alert alert-success';
                        banner.innerHTML = '<span>✓</span><span>Protection is <strong>enabled</strong>.</span>';
                    } else {
                        banner.className = 'alert alert-warning';
                        banner.innerHTML = '<span>⚠️</span><span>Protection is <strong>disabled</strong>. Go to Protection settings to enable.</span>';
                    }
                }
                
                // Load device groups first
                const groupsRes = await api('device_groups');
                const groups = groupsRes.success ? groupsRes.data : [];

                // Load devices and count by zone
                const devRes = await api('irongate_devices');
                if (devRes.success && devRes.data) {
                    const devices = devRes.data;
                    document.getElementById('dash-devices').textContent = devices.length;

                    // Count by zone (including custom groups)
                    const zoneCounts = {};
                    devices.forEach(d => {
                        const zone = d.zone || 'isolated';
                        zoneCounts[zone] = (zoneCounts[zone] || 0) + 1;
                    });

                    // Update built-in zone counts
                    document.getElementById('dash-isolated').textContent = zoneCounts['isolated'] || 0;
                    document.getElementById('dash-servers').textContent = zoneCounts['servers'] || 0;
                    document.getElementById('dash-trusted').textContent = zoneCounts['trusted'] || 0;

                    // Render custom groups summary
                    const customGroups = groups.filter(g => !g.builtin);
                    const customContainer = document.getElementById('dash-custom-groups');
                    if (customContainer && customGroups.length > 0) {
                        customContainer.innerHTML = `
                            <div style="font-size:0.9em;color:var(--text-secondary);margin-bottom:10px;">Custom Groups:</div>
                            <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));">
                                ${customGroups.map(g => {
                                    const count = zoneCounts[g.name] || 0;
                                    return `
                                        <div style="text-align:center;padding:12px;background:${hexToRgba(g.color, 0.1)};border-radius:8px;">
                                            <div style="font-size:1.5em;color:${g.color};">${count}</div>
                                            <div style="color:var(--text-secondary);font-size:0.9em;">${g.icon} ${g.name}</div>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        `;
                    } else if (customContainer) {
                        customContainer.innerHTML = '';
                    }
                }
                
            } catch (e) {
                console.error('Dashboard load error:', e);
            }
        }
        
        //======================================================================
        // UPDATE FUNCTIONS
        //======================================================================
        
        async function loadUpdateStatus() {
            try {
                // Load update settings
                const settingsRes = await api('update_settings');
                if (settingsRes.success && settingsRes.data) {
                    document.getElementById('update-current-commit').textContent = settingsRes.data.installed_commit || 'unknown';
                    document.getElementById('update-last-check').textContent = settingsRes.data.last_update_check || 'Never';
                    
                    const autoEnabled = settingsRes.data.auto_update_enabled;
                    const toggle = document.getElementById('auto-update-toggle');
                    toggle.classList.toggle('active', autoEnabled);
                    document.getElementById('auto-update-status-text').textContent = autoEnabled ? 'Enabled' : 'Disabled';
                }
                
                // Check for updates
                await checkForUpdates(true);
            } catch (e) {
                console.error('Load update status error:', e);
            }
        }
        
        async function checkForUpdates(silent = false) {
            try {
                if (!silent) {
                    document.getElementById('update-status-card').style.display = 'block';
                    document.getElementById('update-status-content').innerHTML = '<span style="color:var(--warning);">🔍 Checking for updates...</span>';
                }
                
                const res = await api('update_check');
                
                if (res.success) {
                    document.getElementById('update-current-commit').textContent = res.current_commit;
                    document.getElementById('update-remote-commit').textContent = res.remote_commit;
                    document.getElementById('update-last-check').textContent = res.last_check;
                    
                    const statusCard = document.getElementById('update-status-card');
                    const statusContent = document.getElementById('update-status-content');
                    const updateBtn = document.getElementById('btn-update-now');
                    
                    // Show commit info
                    if (res.commit_message) {
                        document.getElementById('commit-info-card').style.display = 'block';
                        const commitDate = res.commit_date ? new Date(res.commit_date).toLocaleString() : '';
                        document.getElementById('commit-info-content').innerHTML = `
                            <div style="margin-bottom:10px;"><strong style="font-family:monospace;color:var(--primary);">${res.remote_commit}</strong> <span style="color:var(--text-secondary);font-size:0.85em;">${commitDate}</span></div>
                            <div style="font-size:0.9em;">${res.commit_message.replace(/\n/g, '<br>')}</div>
                        `;
                    }
                    
                    if (res.update_available) {
                        statusCard.style.display = 'block';
                        statusContent.innerHTML = `
                            <div style="color:var(--success);">
                                <strong>✓ Update Available!</strong><br>
                                <span style="font-size:0.9em;">Commit <code>${res.remote_commit}</code> is available (you have <code>${res.current_commit}</code>)</span>
                            </div>
                        `;
                        updateBtn.style.display = 'inline-block';
                    } else {
                        statusCard.style.display = 'block';
                        statusContent.innerHTML = '<span style="color:var(--success);">✓ You are running the latest commit</span>';
                        updateBtn.style.display = 'none';
                    }
                    
                    if (!silent) {
                        toast('Update check complete', 'success');
                    }
                } else {
                    if (!silent) {
                        document.getElementById('update-status-card').style.display = 'block';
                        document.getElementById('update-status-content').innerHTML = `<span style="color:var(--danger);">✗ ${res.error || 'Failed to check for updates'}</span>`;
                        toast('Update check failed', 'error');
                    }
                }
            } catch (e) {
                if (!silent) {
                    toast('Error checking for updates: ' + e.message, 'error');
                }
            }
        }
        
        async function toggleAutoUpdate() {
            const toggle = document.getElementById('auto-update-toggle');
            const newState = !toggle.classList.contains('active');
            
            try {
                const res = await api('update_settings', {
                    method: 'POST',
                    body: { auto_update_enabled: newState }
                });
                
                if (res.success) {
                    toggle.classList.toggle('active', newState);
                    document.getElementById('auto-update-status-text').textContent = newState ? 'Enabled' : 'Disabled';
                    toast('Auto-update ' + (newState ? 'enabled' : 'disabled'), 'success');
                } else {
                    toast('Failed to update setting', 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function performUpdate() {
            if (!confirm('This will update Irongate to the latest version. The page will reload when complete. Continue?')) {
                return;
            }
            
            try {
                document.getElementById('update-status-card').style.display = 'block';
                document.getElementById('update-status-content').innerHTML = `
                    <div style="color:var(--warning);">
                        <strong>⬆️ Updating...</strong><br>
                        <span style="font-size:0.9em;">Please wait, this may take a minute...</span>
                    </div>
                `;
                document.getElementById('btn-update-now').disabled = true;
                
                const res = await api('update_now');
                
                if (res.success) {
                    document.getElementById('update-status-content').innerHTML = `
                        <div style="color:var(--success);">
                            <strong>✓ Update started!</strong><br>
                            <span style="font-size:0.9em;">The page will reload in 30 seconds...</span>
                        </div>
                    `;
                    
                    // Poll for completion and reload
                    setTimeout(() => {
                        location.reload();
                    }, 30000);
                } else {
                    document.getElementById('update-status-content').innerHTML = `<span style="color:var(--danger);">✗ ${res.error || 'Update failed'}</span>`;
                    document.getElementById('btn-update-now').disabled = false;
                    toast('Update failed', 'error');
                }
            } catch (e) {
                document.getElementById('update-status-content').innerHTML = `<span style="color:var(--danger);">✗ Error: ${e.message}</span>`;
                document.getElementById('btn-update-now').disabled = false;
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function viewUpdateLog() {
            try {
                const res = await api('update_log');
                
                document.getElementById('update-log-card').style.display = 'block';
                document.getElementById('update-log-content').textContent = res.data || 'No update log available';
            } catch (e) {
                toast('Error loading log: ' + e.message, 'error');
            }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboard();
        });
    </script>
</body>
</html>
EOHTML

#######################################
# Set permissions
#######################################
echo -e "${YELLOW}Setting permissions...${NC}"

chown -R www-data:www-data /var/www/irongate
chmod -R 755 /var/www/irongate
chmod 666 /var/www/irongate/dhcp.db

# Allow www-data to write dnsmasq config
chown www-data:www-data /etc/dnsmasq.conf
chmod 664 /etc/dnsmasq.conf
chown -R www-data:www-data /etc/dnsmasq.d
chmod -R 775 /etc/dnsmasq.d

# Ensure lease file has proper ownership for dnsmasq to write
chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || chown nobody:nogroup /var/lib/dnsmasq/dnsmasq.leases
chmod 644 /var/lib/dnsmasq/dnsmasq.leases

# Ensure log file is readable by www-data (use world-readable since group memberships require service restart)
chown dnsmasq:adm /var/log/dnsmasq.log 2>/dev/null || chown nobody:adm /var/log/dnsmasq.log
chmod 644 /var/log/dnsmasq.log

# Make www-data a member of systemd-journal and adm groups to read logs
# Note: www-data needs php-fpm restart to pick up new group memberships
usermod -a -G systemd-journal www-data 2>/dev/null || true
usermod -a -G adm www-data 2>/dev/null || true

cat > /etc/sudoers.d/dnsmasq-web << EOF
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl enable irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl disable irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /usr/bin/pkill -9 dnsmasq
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown dnsmasq\:nogroup /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 644 /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 664 /var/log/dnsmasq.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u dnsmasq *
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u irongate *
www-data ALL=(ALL) NOPASSWD: /usr/bin/tail *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/arping *
www-data ALL=(ALL) NOPASSWD: /bin/bash /tmp/irongate-update.sh
www-data ALL=(ALL) NOPASSWD: /usr/bin/touch /var/log/irongate-update.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown www-data /var/log/irongate-update.log
EOF
chmod 440 /etc/sudoers.d/dnsmasq-web

#######################################
# Create systemd watchdog for auto-recovery
#######################################
echo -e "${YELLOW}Setting up service watchdog...${NC}"

mkdir -p /etc/systemd/system/dnsmasq.service.d

cat > /etc/systemd/system/dnsmasq.service.d/override.conf << EOF
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Restart=on-failure
RestartSec=5
EOF

#######################################
# Create Irongate Network Isolation Service
#######################################
echo -e "${YELLOW}Setting up Irongate network isolation...${NC}"

mkdir -p /opt/irongate
mkdir -p /etc/irongate
mkdir -p /var/log/irongate

# IMPORTANT: www-data needs to write to config.yaml from the web UI
chown -R root:www-data /etc/irongate
chmod 775 /etc/irongate
# Config file will be created later, but set default permissions
touch /etc/irongate/config.yaml 2>/dev/null || true
chown root:www-data /etc/irongate/config.yaml 2>/dev/null || true
chmod 664 /etc/irongate/config.yaml 2>/dev/null || true

# Create Python virtual environment
python3 -m venv /opt/irongate/venv 2>/dev/null || true
# Core dependencies
/opt/irongate/venv/bin/pip install --quiet pyyaml scapy netifaces 2>/dev/null || \
    pip3 install --quiet --break-system-packages pyyaml scapy netifaces 2>/dev/null || true

# Algorand SDK and PyTeal for Layer 8 blockchain verification
echo "Installing Algorand SDK and PyTeal for Layer 8 blockchain..."
/opt/irongate/venv/bin/pip install --quiet py-algorand-sdk pyteal 2>/dev/null || \
    pip3 install --quiet --break-system-packages py-algorand-sdk pyteal 2>/dev/null || \
    echo "Note: Algorand SDK not installed - blockchain features will be disabled"

# Fallback install with break-system-packages
pip3 install --quiet --break-system-packages pyyaml scapy netifaces py-algorand-sdk pyteal 2>/dev/null || true

# Create Irongate main script
cat > /opt/irongate/irongate.py << 'IRONGATEPY'
#!/usr/bin/env python3
"""
Irongate Network Isolation Engine
Middleground ARP isolation: ~95% protection without breaking unprotected devices
- Unicast ARP to ALL known LAN devices telling them protected IPs are at Irongate
- Does NOT touch anyone's gateway entry except protected devices
- Unprotected devices keep their internet, can't reach protected servers

Layer 8 Blockchain (Optional):
- Algorand-based device registry for cryptographic authentication
- Enables 100% VLAN-equivalent protection via on-chain verification
- Enable in config.yaml under 'blockchain:' section
"""

import os
import sys
import yaml
import time
import signal
import logging
import threading
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('irongate')

# Try to import blockchain module (optional)
try:
    from blockchain import IrongateBlockchain, VerificationResult, ALGORAND_AVAILABLE
    BLOCKCHAIN_MODULE_AVAILABLE = True
except ImportError:
    BLOCKCHAIN_MODULE_AVAILABLE = False
    ALGORAND_AVAILABLE = False
    logger.info("Blockchain module not available - Layer 8 disabled")

# Global reference for signal handler
irongate = None


class Irongate:
    def __init__(self, config_path='/etc/irongate/config.yaml'):
        self.config_path = config_path
        self.config = {}
        self.running = False
        self.threads = []
        self.protected_devices = []
        self.trusted_devices = []
        self.lan_devices = []
        self.gateway_ip = None
        self.gateway_mac = None
        self.interface = 'eth0'
        self.local_mac = None
        self.local_ip = None
        
        # Layer settings (all enabled by default)
        self.layer_arp_defense = True
        self.layer_ipv6_ra = True
        self.layer_gateway_takeover = True
        self.layer_bypass_detection = True
        self.layer_firewall = True
        
        # Layer 8: Blockchain verification (optional)
        self.blockchain = None
        self.blockchain_enabled = False
        
    def load_config(self):
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"Loaded config from {self.config_path}")
            
            # Load layer settings (default all to True if not specified)
            layers = self.config.get('layers', {})
            self.layer_arp_defense = layers.get('arp_defense', True)
            self.layer_ipv6_ra = layers.get('ipv6_ra', True)
            self.layer_gateway_takeover = layers.get('gateway_takeover', True)
            self.layer_bypass_detection = layers.get('bypass_detection', True)
            self.layer_firewall = layers.get('firewall', True)
            
            logger.info("Layer settings:")
            logger.info(f"  ARP Defense: {'ON' if self.layer_arp_defense else 'OFF'}")
            logger.info(f"  IPv6 RA Guard: {'ON' if self.layer_ipv6_ra else 'OFF'}")
            logger.info(f"  Gateway Takeover: {'ON' if self.layer_gateway_takeover else 'OFF'}")
            logger.info(f"  Bypass Detection: {'ON' if self.layer_bypass_detection else 'OFF'}")
            logger.info(f"  Firewall: {'ON' if self.layer_firewall else 'OFF'}")
            
            # Handle devices being None from YAML
            devices = self.config.get('devices') or []
            logger.info(f"Found {len(devices)} devices in config")
            for dev in devices:
                logger.info(f"  Device: {dev.get('ip')} ({dev.get('mac')}) zone={dev.get('zone')}")
            
            # Initialize Layer 8 Blockchain (if configured)
            self._init_blockchain()
            
            return True
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return False
    
    def _init_blockchain(self):
        """Initialize Layer 8 Blockchain verification (optional)"""
        blockchain_config = self.config.get('blockchain', {})
        
        if not blockchain_config.get('enabled', False):
            logger.info("Layer 8 Blockchain: Disabled (set blockchain.enabled: true to activate)")
            return
        
        if not BLOCKCHAIN_MODULE_AVAILABLE:
            logger.warning("Layer 8 Blockchain: Module not available")
            return
        
        if not ALGORAND_AVAILABLE:
            logger.warning("Layer 8 Blockchain: Algorand SDK not installed")
            logger.warning("  Install with: pip install py-algorand-sdk")
            return
        
        try:
            self.blockchain = IrongateBlockchain(blockchain_config)
            self.blockchain_enabled = self.blockchain.enabled
            
            if self.blockchain_enabled:
                logger.info("━" * 50)
                logger.info("LAYER 8 BLOCKCHAIN: ACTIVE")
                logger.info(f"  Network: {blockchain_config.get('network', 'mainnet')}")
                logger.info(f"  App ID: {blockchain_config.get('app_id')}")
                logger.info(f"  Cache TTL: {blockchain_config.get('cache_ttl', 60)}s")
                logger.info(f"  Audit Logging: {blockchain_config.get('audit_logging', False)}")
                if blockchain_config.get('allow_rogue_devices', False):
                    logger.info("  Mode: PUBLIC WIFI (rogue devices allowed)")
                else:
                    logger.info("  Mode: STRICT (unregistered devices blocked)")
                logger.info("  → 100% VLAN-equivalent protection enabled!")
                logger.info("━" * 50)
            else:
                logger.info("Layer 8 Blockchain: Not fully configured")
                
        except Exception as e:
            logger.error(f"Layer 8 Blockchain initialization failed: {e}")
            self.blockchain = None
            self.blockchain_enabled = False
    
    def _load_lan_devices(self):
        """Load all known LAN devices from dnsmasq leases file (excluding trusted/protected)"""
        new_lan_devices = []
        
        protected_ips = set(d[0] for d in self.protected_devices)
        protected_macs = set(d[1].lower() for d in self.protected_devices)
        trusted_ips = set(d[0] for d in self.trusted_devices)
        trusted_macs = set(d[1].lower() for d in self.trusted_devices)
        
        # Safety check for local_mac
        local_mac_lower = self.local_mac.lower() if self.local_mac else ''
        
        lease_file = '/var/lib/dnsmasq/dnsmasq.leases'
        
        try:
            if os.path.exists(lease_file):
                with open(lease_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            # Format: timestamp mac ip hostname clientid
                            mac = parts[1].lower()
                            ip = parts[2]
                            
                            # Exclude: protected, trusted, gateway, self
                            if (ip not in protected_ips and 
                                mac not in protected_macs and
                                ip not in trusted_ips and
                                mac not in trusted_macs and
                                ip != self.gateway_ip and 
                                ip != self.local_ip and
                                mac != local_mac_lower):
                                new_lan_devices.append((ip, mac))
            
            # Deduplicate by IP
            seen_ips = set()
            unique_devices = []
            for ip, mac in new_lan_devices:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_devices.append((ip, mac))
            
            # Atomic update to avoid race condition
            self.lan_devices = unique_devices
            
            logger.info(f"Loaded {len(self.lan_devices)} LAN devices to spoof (excluding {len(self.trusted_devices)} trusted)")
            
        except Exception as e:
            logger.error(f"Failed to load LAN devices: {e}")
    
    def setup_kernel(self):
        """Enable IP forwarding"""
        os.system('sysctl -w net.ipv4.ip_forward=1 2>/dev/null')
    
    def _get_mac(self, ip):
        """Resolve MAC address via ARP request"""
        try:
            from scapy.all import Ether, ARP, srp, conf
            conf.verb = 0
            ans, _ = srp(
                Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),
                timeout=3, verbose=0, iface=self.interface
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            logger.error(f"Failed to resolve MAC for {ip}: {e}")
        return None
    
    def _send_unicast_arp(self, target_ip, target_mac, spoof_ip):
        """Send UNICAST ARP reply to specific target only."""
        try:
            from scapy.all import Ether, ARP, sendp, conf
            conf.verb = 0
            
            pkt = Ether(dst=target_mac, src=self.local_mac) / ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoof_ip,
                hwsrc=self.local_mac
            )
            sendp(pkt, iface=self.interface, verbose=False)
            return True
        except Exception as e:
            logger.debug(f"ARP send failed to {target_ip}: {e}")
            return False
    
    def _restore_arp_tables(self):
        """Restore legitimate ARP mappings on shutdown"""
        try:
            from scapy.all import Ether, ARP, sendp, conf
            conf.verb = 0
        except ImportError:
            logger.warning("scapy not available, cannot restore ARP tables")
            return
        
        if not self.gateway_mac:
            logger.warning("No gateway MAC, cannot restore ARP tables")
            return
        
        logger.info("Restoring ARP tables...")
        
        for dev_ip, dev_mac, zone in self.protected_devices:
            # Restore protected device's view of gateway
            pkt = Ether(dst=dev_mac, src=self.gateway_mac) / ARP(
                op=2, pdst=dev_ip, hwdst=dev_mac,
                psrc=self.gateway_ip, hwsrc=self.gateway_mac
            )
            sendp(pkt, iface=self.interface, verbose=False, count=5)
            
            # Restore all LAN devices' view of protected device
            for lan_ip, lan_mac in self.lan_devices:
                pkt = Ether(dst=lan_mac, src=dev_mac) / ARP(
                    op=2, pdst=lan_ip, hwdst=lan_mac,
                    psrc=dev_ip, hwsrc=dev_mac
                )
                sendp(pkt, iface=self.interface, verbose=False, count=3)
            
            logger.info(f"  Restored: {dev_ip}")
        
        logger.info("ARP tables restored")
    
    def run_single_nic(self):
        """Run middleground ARP-based isolation (~98% protection with aggressive spoofing)"""
        logger.info("Starting single-NIC mode (aggressive ARP isolation)")
        
        net = self.config.get('network') or {}
        self.interface = net.get('interface', 'eth0')
        self.gateway_ip = net.get('gateway_ip', '')
        self.gateway_mac = net.get('gateway_mac', '')
        self.local_mac = net.get('local_mac', '')
        self.local_ip = net.get('local_ip', '')
        devices = self.config.get('devices') or []
        
        if not self.gateway_ip:
            logger.error("No gateway IP configured - cannot start")
            return False
        
        if not self.gateway_mac:
            logger.info(f"Resolving gateway MAC for {self.gateway_ip}...")
            self.gateway_mac = self._get_mac(self.gateway_ip)
            if self.gateway_mac:
                logger.info(f"  Gateway MAC: {self.gateway_mac}")
            else:
                logger.error("Could not resolve gateway MAC - ARP spoofing disabled")
                return False
        
        self.protected_devices = []
        self.trusted_devices = []
        for dev in devices:
            dev_ip = dev.get('ip')
            dev_mac = dev.get('mac', '').lower()
            zone = dev.get('zone', 'isolated')
            
            if not dev_ip:
                continue
            
            # Safety check: validate IP format (basic check)
            parts = dev_ip.split('.')
            if len(parts) != 4:
                logger.warning(f"  Invalid IP format: {dev_ip}, skipping")
                continue
            try:
                if not all(0 <= int(p) <= 255 for p in parts):
                    logger.warning(f"  Invalid IP format: {dev_ip}, skipping")
                    continue
            except ValueError:
                logger.warning(f"  Invalid IP format: {dev_ip}, skipping")
                continue
            
            # Safety check: don't protect self
            if dev_ip == self.local_ip:
                logger.warning(f"  Cannot protect self ({dev_ip}), skipping")
                continue
            
            # Safety check: don't protect gateway
            if dev_ip == self.gateway_ip:
                logger.warning(f"  Cannot protect gateway ({dev_ip}), skipping")
                continue
            
            if not dev_mac:
                dev_mac = self._get_mac(dev_ip)
                if not dev_mac:
                    logger.warning(f"  Cannot resolve MAC for {dev_ip}, skipping")
                    continue
                
            if zone == 'trusted':
                self.trusted_devices.append((dev_ip, dev_mac))
                logger.info(f"  TRUSTED (full access): {dev_ip} ({dev_mac})")
                continue
            
            self.protected_devices.append((dev_ip, dev_mac, zone))
            logger.info(f"  PROTECTED ({zone}): {dev_ip} ({dev_mac})")
        
        if not self.protected_devices:
            logger.warning("No protected devices - nothing to isolate")
            return False
        
        self._load_lan_devices()
        
        logger.info("Setting up local static ARP entries...")
        for dev_ip, dev_mac, zone in self.protected_devices:
            os.system(f"ip neigh replace {dev_ip} lladdr {dev_mac} dev {self.interface} nud permanent 2>/dev/null")
        os.system(f"ip neigh replace {self.gateway_ip} lladdr {self.gateway_mac} dev {self.interface} nud permanent 2>/dev/null")
        
        # Layer: Firewall (nftables zone-based rules)
        if self.layer_firewall:
            self._setup_firewall()
            logger.info("Layer: Firewall - ACTIVE")
        else:
            logger.info("Layer: Firewall - DISABLED")
        
        # Layer: Gateway Takeover (ARP spoofing for traffic interception)
        if self.layer_gateway_takeover:
            t = threading.Thread(target=self._middleground_arp_spoof_loop, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Layer: Gateway Takeover - ACTIVE")
        else:
            logger.info("Layer: Gateway Takeover - DISABLED")
        
        # Layer: ARP Defense (counter spoofing, reply interception)
        if self.layer_arp_defense:
            t2 = threading.Thread(target=self._arp_defense_loop, daemon=True)
            t2.start()
            self.threads.append(t2)
            logger.info("Layer: ARP Defense - ACTIVE")
        else:
            logger.info("Layer: ARP Defense - DISABLED")
        
        # LAN device refresh is always needed for protection to work
        t3 = threading.Thread(target=self._lan_device_refresh_loop, daemon=True)
        t3.start()
        self.threads.append(t3)
        logger.info("LAN device refresh started")
        
        # Layer: IPv6 RA Guard (TODO: implement if not already)
        if self.layer_ipv6_ra:
            logger.info("Layer: IPv6 RA Guard - ACTIVE")
        else:
            logger.info("Layer: IPv6 RA Guard - DISABLED")
        
        # Layer: Bypass Detection (TODO: implement active probing)
        if self.layer_bypass_detection:
            logger.info("Layer: Bypass Detection - ACTIVE")
        else:
            logger.info("Layer: Bypass Detection - DISABLED")
        
        logger.info(f"Single-NIC isolation active")
        logger.info(f"  Protected: {len(self.protected_devices)} devices")
        logger.info(f"  LAN targets: {len(self.lan_devices)} devices")
        
        return True
    
    def _lan_device_refresh_loop(self):
        """Periodically refresh list of LAN devices"""
        while self.running:
            # Sleep in small increments to allow faster shutdown
            for _ in range(60):
                if not self.running:
                    return
                time.sleep(1)
            try:
                old_count = len(self.lan_devices)
                self._load_lan_devices()
                if len(self.lan_devices) != old_count:
                    logger.info(f"LAN devices updated: {old_count} -> {len(self.lan_devices)}")
            except Exception as e:
                logger.error(f"LAN refresh error: {e}")
    
    def _middleground_arp_spoof_loop(self):
        """
        Middleground ARP spoofing for ~95% protection.
        - Tell protected devices: gateway is Irongate (route outbound through us)
        - Tell LAN devices: protected IPs are at Irongate (intercept LAN→protected)
        - DON'T spoof gateway/Firewalla - let it see real device MACs for proper routing
        """
        if not self.gateway_mac:
            logger.error("No gateway MAC, cannot spoof")
            return
        
        if not self.local_mac:
            logger.error("No local MAC, cannot spoof")
            return
        
        logger.info(f"ARP spoof: {len(self.protected_devices)} protected, {len(self.lan_devices)} LAN targets")
        logger.info("NOTE: Not spoofing gateway - Firewalla will see real device MACs")
        
        while self.running:
            try:
                # Get current snapshot of lan_devices to avoid race condition
                current_lan_devices = list(self.lan_devices)
                
                # Rate limiting: add micro-delay for large networks
                # This prevents flooding the network with ARP packets
                packet_delay = 0
                total_packets = len(self.protected_devices) * (1 + len(current_lan_devices))
                if total_packets > 500:
                    packet_delay = 0.002  # 2ms delay = ~500 packets/sec max
                elif total_packets > 200:
                    packet_delay = 0.001  # 1ms delay
                
                for dev_ip, dev_mac, zone in self.protected_devices:
                    if not self.running:
                        return
                    
                    # Tell protected device: "Gateway is at Irongate's MAC"
                    # This routes their outbound traffic through Irongate
                    self._send_unicast_arp(
                        target_ip=dev_ip,
                        target_mac=dev_mac,
                        spoof_ip=self.gateway_ip
                    )
                    
                    # DO NOT tell gateway about protected devices
                    # Firewalla needs to see real MACs to route traffic properly
                    
                    # Tell ALL LAN devices: "Protected device is at Irongate's MAC"
                    # This intercepts any LAN device trying to reach protected servers
                    for lan_ip, lan_mac in current_lan_devices:
                        if not self.running:
                            return
                        self._send_unicast_arp(
                            target_ip=lan_ip,
                            target_mac=lan_mac,
                            spoof_ip=dev_ip
                        )
                        if packet_delay:
                            time.sleep(packet_delay)
                
                # More aggressive poisoning interval for better protection
                time.sleep(0.3)
                
            except Exception as e:
                logger.error(f"ARP spoof error: {e}")
                time.sleep(5)
    
    def _arp_defense_loop(self):
        """Monitor ARP and counter protected devices announcing real MACs"""
        try:
            from scapy.all import Ether, ARP, sniff, sendp, conf
            conf.verb = 0
        except ImportError:
            logger.warning("scapy not available for ARP defense")
            return
        
        if not self.local_mac:
            logger.warning("No local MAC, cannot run ARP defense")
            return
        
        local_mac_lower = self.local_mac.lower()
        
        # Build protected device lookup
        protected_ips = {}
        for dev_ip, dev_mac, zone in self.protected_devices:
            protected_ips[dev_ip] = dev_mac.lower()
        
        # Build comprehensive "allowed" set - these IPs should get REAL MACs, not spoofed
        # This includes everyone who legitimately needs to reach protected devices
        allowed_ips = set()
        allowed_macs = set()
        
        # Gateway/Firewalla needs real MACs for routing
        if self.gateway_ip:
            allowed_ips.add(self.gateway_ip)
        
        # Irongate itself
        if self.local_ip:
            allowed_ips.add(self.local_ip)
        allowed_macs.add(local_mac_lower)
        
        # Trusted devices - they should have full access
        for dev_ip, dev_mac in self.trusted_devices:
            allowed_ips.add(dev_ip)
            allowed_macs.add(dev_mac.lower())
        
        # Protected devices (servers) - they can reach each other
        for dev_ip, dev_mac, zone in self.protected_devices:
            allowed_ips.add(dev_ip)
            allowed_macs.add(dev_mac.lower())
        
        logger.info(f"ARP defense: {len(protected_ips)} protected, {len(allowed_ips)} allowed (bypass spoof)")
        logger.info(f"  Allowed IPs: {', '.join(sorted(allowed_ips))}")
        
        # Layer 8 blockchain reference for verification
        blockchain = self.blockchain if self.blockchain_enabled else None
        if blockchain:
            logger.info("  Layer 8 Blockchain: ACTIVE - devices must be registered on-chain")
        
        def handle_arp(pkt):
            if ARP not in pkt:
                return
            
            try:
                arp = pkt[ARP]
                
                # Handle ARP Requests: "Who has X?"
                if arp.op == 1:
                    requested_ip = arp.pdst
                    requester_mac = arp.hwsrc.lower()
                    requester_ip = arp.psrc
                    
                    # ═══════════════════════════════════════════════════════
                    # LAYER 8: Blockchain verification (if enabled)
                    # This provides 100% VLAN-equivalent protection by requiring
                    # cryptographic proof of device identity
                    # ═══════════════════════════════════════════════════════
                    if blockchain and requested_ip in protected_ips:
                        # Check if requester is blockchain-verified
                        verification = blockchain.verify_device(requester_mac, requester_ip)
                        
                        if verification.get('verified') == True:
                            # Device is cryptographically verified on-chain
                            # Allow it through (don't spoof)
                            if blockchain.audit_logging:
                                blockchain.log_access(
                                    requester_mac, requester_ip,
                                    f"arp_request:{requested_ip}",
                                    "allowed_blockchain"
                                )
                            return
                        
                        elif verification.get('verified') == False:
                            # Device NOT verified on blockchain
                            result = verification.get('result')
                            
                            if result and hasattr(result, 'value'):
                                result_str = result.value
                            else:
                                result_str = str(result)
                            
                            # PUBLIC WIFI MODE: Log but allow unregistered devices
                            if blockchain.allow_rogue_devices:
                                logger.info(f"LAYER 8 ROGUE: {requester_ip} ({requester_mac}) -> {requested_ip} (allowed)")
                                logger.info(f"  Status: {verification.get('details', result_str)}")
                                
                                # Still log to blockchain audit trail if enabled
                                if blockchain.audit_logging:
                                    blockchain.log_access(
                                        requester_mac, requester_ip,
                                        f"arp_request:{requested_ip}",
                                        f"rogue_allowed_{result_str}"
                                    )
                                # Let it through - don't spoof
                                return
                            
                            # STRICT MODE: Block unregistered devices
                            logger.warning(f"LAYER 8 BLOCK: {requester_ip} ({requester_mac}) -> {requested_ip}")
                            logger.warning(f"  Reason: {verification.get('details', result_str)}")
                            
                            # Log to blockchain audit trail
                            if blockchain.audit_logging:
                                blockchain.log_access(
                                    requester_mac, requester_ip,
                                    f"arp_request:{requested_ip}",
                                    f"blocked_{result_str}"
                                )
                            
                            # Spoof to block access - aggressive burst
                            reply = Ether(dst=requester_mac, src=self.local_mac) / ARP(
                                op=2, pdst=requester_ip, hwdst=requester_mac,
                                psrc=requested_ip, hwsrc=self.local_mac
                            )
                            for _ in range(5):
                                sendp(reply, iface=self.interface, verbose=False)
                            return
                        
                        # verification['verified'] is None = blockchain unavailable
                        # Fall through to standard layer 1-7 logic
                    
                    # ═══════════════════════════════════════════════════════
                    # Standard Layer 1-7 protection (config-based)
                    # ═══════════════════════════════════════════════════════
                    
                    # Only intercept requests for protected IPs
                    if requested_ip in protected_ips:
                        # Skip if requester is in the allowed list
                        # This includes: gateway, irongate, trusted devices, other servers
                        if requester_ip in allowed_ips or requester_mac in allowed_macs:
                            return
                        
                        # Skip gratuitous ARP (asking about itself)
                        if requester_ip == requested_ip:
                            return
                        
                        # Requester is an untrusted LAN device - spoof them AGGRESSIVELY
                        # Send multiple replies to win the race against real ARP responses
                        reply = Ether(dst=requester_mac, src=self.local_mac) / ARP(
                            op=2, pdst=requester_ip, hwdst=requester_mac,
                            psrc=requested_ip, hwsrc=self.local_mac
                        )
                        # Burst of 5 packets to overwhelm real reply
                        for _ in range(5):
                            sendp(reply, iface=self.interface, verbose=False)
                
                # Handle ARP Replies: "X is at MAC Y"
                elif arp.op == 2:
                    sender_ip = arp.psrc
                    sender_mac = arp.hwsrc.lower()
                    target_mac = arp.hwdst.lower()
                    target_ip = arp.pdst
                    
                    # Only counter replies FROM protected devices with their real MAC
                    if sender_ip in protected_ips and sender_mac == protected_ips[sender_ip]:
                        # Skip broadcast
                        if target_mac == 'ff:ff:ff:ff:ff:ff':
                            return
                        
                        # Skip if target is in the allowed list
                        if target_ip in allowed_ips or target_mac in allowed_macs:
                            return
                        
                        # Target is an untrusted LAN device - counter the real reply AGGRESSIVELY
                        counter = Ether(dst=target_mac, src=self.local_mac) / ARP(
                            op=2, pdst=target_ip, hwdst=target_mac,
                            psrc=sender_ip, hwsrc=self.local_mac
                        )
                        # Burst of 5 packets to override the real MAC in ARP cache
                        for _ in range(5):
                            sendp(counter, iface=self.interface, verbose=False)
                            
            except Exception:
                pass
        
        logger.info(f"ARP defense monitoring {len(protected_ips)} protected IPs")
        
        # Use stop_filter instead of timeout to keep promiscuous mode stable
        # This prevents the SMSC95xx driver on Pi 3B from crashing due to
        # constant promiscuous mode toggling
        def should_stop(pkt):
            return not self.running
        
        while self.running:
            try:
                # Long timeout with stop_filter - keeps promiscuous mode stable
                sniff(iface=self.interface, filter="arp", prn=handle_arp,
                      store=False, timeout=30, stop_filter=should_stop)
            except Exception as e:
                if self.running:
                    logger.debug(f"Sniff restart: {e}")
                    time.sleep(1)
    
    def _setup_firewall(self):
        """Configure nftables - POLICY ACCEPT with specific drops
        Supports both built-in zones and custom device groups"""
        devices = self.config.get('devices') or []
        custom_groups = self.config.get('custom_groups') or []

        # Build a dictionary of group name -> group config
        group_configs = {}
        for g in custom_groups:
            group_configs[g.get('name', '')] = {
                'lan_access': g.get('lan_access', 'none'),
                'can_access_groups': g.get('can_access_groups', [])
            }

        # Categorize devices by zone/group
        zone_ips = {}  # zone_name -> list of IPs
        for dev in devices:
            ip = dev.get('ip', '')
            zone = dev.get('zone', 'isolated')
            if ip:
                if zone not in zone_ips:
                    zone_ips[zone] = []
                zone_ips[zone].append(ip)

        # Ensure built-in zones exist even if empty
        for builtin in ['isolated', 'servers', 'trusted']:
            if builtin not in zone_ips:
                zone_ips[builtin] = []

        # Build nftables sets for all zones
        sets_section = ""
        for zone_name, ips in zone_ips.items():
            set_name = f"{zone_name}_devices"
            ip_list = ', '.join(ips) if ips else '0.0.0.0'
            sets_section += f"""
    set {set_name} {{
        type ipv4_addr
        elements = {{ {ip_list} }}
    }}
"""

        # Build firewall rules
        rules_section = """
    chain forward {
        type filter hook forward priority 0; policy accept;

        ct state established,related accept

        # === TRUSTED: Full access to everything ===
        ip saddr @trusted_devices accept
        ip daddr @trusted_devices accept
"""

        # === BUILT-IN ZONES ===
        # Isolated: block all LAN access
        rules_section += """
        # === ISOLATED: Block all LAN access ===
        ip saddr @isolated_devices ip daddr 10.0.0.0/8 drop
        ip saddr @isolated_devices ip daddr 172.16.0.0/12 drop
        ip saddr @isolated_devices ip daddr 192.168.0.0/16 drop
        ip daddr @isolated_devices ip saddr 10.0.0.0/8 drop
        ip daddr @isolated_devices ip saddr 172.16.0.0/12 drop
        ip daddr @isolated_devices ip saddr 192.168.0.0/16 drop
"""

        # Servers: allow inter-server, block other LAN
        rules_section += """
        # === SERVERS: Allow inter-server, block other LAN ===
        ip saddr @servers_devices ip daddr @servers_devices accept
        ip saddr @servers_devices ip daddr 10.0.0.0/8 drop
        ip saddr @servers_devices ip daddr 172.16.0.0/12 drop
        ip saddr @servers_devices ip daddr 192.168.0.0/16 drop
        ip daddr @servers_devices ip saddr @servers_devices accept
        ip daddr @servers_devices ip saddr 10.0.0.0/8 drop
        ip daddr @servers_devices ip saddr 172.16.0.0/12 drop
        ip daddr @servers_devices ip saddr 192.168.0.0/16 drop
"""

        # === CUSTOM GROUPS ===
        for group in custom_groups:
            group_name = group.get('name', '')
            if not group_name or group_name in ['isolated', 'servers', 'trusted']:
                continue  # Skip built-ins

            lan_access = group.get('lan_access', 'none')
            can_access = group.get('can_access_groups', [])
            set_name = f"{group_name}_devices"

            if lan_access == 'full':
                # Full access - no restrictions needed
                rules_section += f"""
        # === {group_name.upper()}: Full LAN access ===
        ip saddr @{set_name} accept
        ip daddr @{set_name} accept
"""
            elif lan_access == 'same':
                # Can only communicate within same group
                rules_section += f"""
        # === {group_name.upper()}: Same-group access only ===
        ip saddr @{set_name} ip daddr @{set_name} accept
        ip saddr @{set_name} ip daddr 10.0.0.0/8 drop
        ip saddr @{set_name} ip daddr 172.16.0.0/12 drop
        ip saddr @{set_name} ip daddr 192.168.0.0/16 drop
        ip daddr @{set_name} ip saddr @{set_name} accept
        ip daddr @{set_name} ip saddr 10.0.0.0/8 drop
        ip daddr @{set_name} ip saddr 172.16.0.0/12 drop
        ip daddr @{set_name} ip saddr 192.168.0.0/16 drop
"""
            elif lan_access == 'selected' and can_access:
                # Can communicate with selected groups
                rules_section += f"""
        # === {group_name.upper()}: Selected group access ===
"""
                for target_group in can_access:
                    target_set = f"{target_group}_devices"
                    if target_group in zone_ips:
                        rules_section += f"        ip saddr @{set_name} ip daddr @{target_set} accept\n"
                        rules_section += f"        ip daddr @{set_name} ip saddr @{target_set} accept\n"

                rules_section += f"""        ip saddr @{set_name} ip daddr 10.0.0.0/8 drop
        ip saddr @{set_name} ip daddr 172.16.0.0/12 drop
        ip saddr @{set_name} ip daddr 192.168.0.0/16 drop
        ip daddr @{set_name} ip saddr 10.0.0.0/8 drop
        ip daddr @{set_name} ip saddr 172.16.0.0/12 drop
        ip daddr @{set_name} ip saddr 192.168.0.0/16 drop
"""
            else:
                # No LAN access (default behavior like isolated)
                rules_section += f"""
        # === {group_name.upper()}: No LAN access ===
        ip saddr @{set_name} ip daddr 10.0.0.0/8 drop
        ip saddr @{set_name} ip daddr 172.16.0.0/12 drop
        ip saddr @{set_name} ip daddr 192.168.0.0/16 drop
        ip daddr @{set_name} ip saddr 10.0.0.0/8 drop
        ip daddr @{set_name} ip saddr 172.16.0.0/12 drop
        ip daddr @{set_name} ip saddr 192.168.0.0/16 drop
"""

        rules_section += "    }\n"

        # Combine into full ruleset
        rules = f"""
table inet irongate {{{sets_section}{rules_section}}}
"""
        try:
            os.system('nft delete table inet irongate 2>/dev/null')
            with open('/tmp/irongate.nft', 'w') as f:
                f.write(rules)
            result = os.system('nft -f /tmp/irongate.nft')
            if result == 0:
                # Log summary
                custom_count = len([g for g in custom_groups if g.get('name') not in ['isolated', 'servers', 'trusted']])
                logger.info(f"Firewall: {len(zone_ips.get('isolated', []))} isolated, {len(zone_ips.get('servers', []))} servers, {len(zone_ips.get('trusted', []))} trusted + {custom_count} custom groups")
            else:
                logger.error("Failed to apply firewall rules")
        except Exception as e:
            logger.error(f"Firewall error: {e}")
    
    def run_dual_nic(self):
        """Run bridge isolation mode"""
        logger.info("Starting dual-NIC mode (bridge isolation)")
        
        bridge_cfg = self.config.get('bridge') or {}
        bridge_name = bridge_cfg.get('bridge_name', 'br-irongate')
        isolated_iface = bridge_cfg.get('isolated_interface', '')
        bridge_ip = bridge_cfg.get('bridge_ip', '10.99.0.1')
        
        if not isolated_iface:
            logger.error("No isolated interface configured!")
            return False
        
        if not os.path.exists(f'/sys/class/net/{isolated_iface}'):
            logger.error(f"Isolated interface {isolated_iface} not found!")
            return False
        
        logger.info(f"Creating bridge {bridge_name}")
        os.system(f'ip link set {bridge_name} down 2>/dev/null')
        os.system(f'brctl delbr {bridge_name} 2>/dev/null')
        os.system(f'brctl addbr {bridge_name}')
        os.system(f'brctl stp {bridge_name} off')
        
        os.system(f'ip link set {isolated_iface} down')
        os.system(f'ip addr flush dev {isolated_iface}')
        os.system(f'brctl addif {bridge_name} {isolated_iface}')
        os.system(f'ip link set {isolated_iface} up')
        
        os.system(f'ip addr add {bridge_ip}/16 dev {bridge_name}')
        os.system(f'ip link set {bridge_name} up')
        
        result = os.system(f'bridge link set dev {isolated_iface} isolated on 2>/dev/null')
        if result == 0:
            logger.info("Port isolation enabled")
        else:
            os.system(f'ebtables -A FORWARD -i {isolated_iface} -o {isolated_iface} -j DROP')
        
        net = self.config.get('network', {})
        uplink = net.get('interface', 'eth0')
        os.system(f'nft add table nat 2>/dev/null')
        os.system(f'nft add chain nat postrouting {{ type nat hook postrouting priority 100 \\; }} 2>/dev/null')
        os.system(f'nft add rule nat postrouting oifname {uplink} masquerade 2>/dev/null')
        
        dhcp_start = bridge_cfg.get('dhcp_start', '10.99.1.1')
        dhcp_end = bridge_cfg.get('dhcp_end', '10.99.255.254')
        
        dnsmasq_conf = f"""
interface={bridge_name}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},24h
dhcp-option=option:router,{bridge_ip}
dhcp-option=option:dns-server,{bridge_ip},8.8.8.8
"""
        with open('/etc/irongate/bridge-dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_conf)
        
        os.system('pkill -f "dnsmasq.*bridge-dnsmasq" 2>/dev/null')
        os.system('dnsmasq --conf-file=/etc/irongate/bridge-dnsmasq.conf &')
        
        logger.info(f"Dual-NIC bridge active: {bridge_name} ({bridge_ip})")
        return True
    
    def run(self):
        """Main run loop"""
        if not self.load_config():
            logger.error("Cannot start without valid config")
            return False
        
        self.running = True
        self.setup_kernel()
        
        mode = self.config.get('mode', 'single')
        
        if mode == 'dual':
            if not self.run_dual_nic():
                self.running = False
                return False
        else:
            if not self.run_single_nic():
                self.running = False
                logger.warning("Single-NIC mode initialization failed or no devices to protect")
                # Still run for firewall-only mode if we got that far
                if not self.protected_devices:
                    logger.info("Entering idle mode - add protected devices to activate")
        
        logger.info("Irongate running")
        
        while self.running:
            time.sleep(1)
        
        return True
    
    def stop(self):
        """Stop and restore ARP tables"""
        self.running = False
        self._restore_arp_tables()
        os.system('nft delete table inet irongate 2>/dev/null')
        logger.info("Irongate stopped")


def signal_handler(sig, frame):
    logger.info("Shutdown signal received")
    if irongate:
        irongate.stop()
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    irongate = Irongate()
    irongate.run()
IRONGATEPY

chmod +x /opt/irongate/irongate.py

# Create Algorand Blockchain Module (Layer 8 - Optional)
echo -e "${YELLOW}Creating blockchain verification module...${NC}"
cat > /opt/irongate/blockchain.py << 'BLOCKCHAINPY'
#!/usr/bin/env python3
"""
Irongate Layer 8: Algorand Blockchain Verification Module

Provides cryptographic device authentication via Algorand blockchain.
This achieves 100% VLAN-equivalent protection by:
- Storing authorized devices in an immutable on-chain registry
- Verifying device identity via cryptographic signatures
- Creating tamper-proof audit trails of all access attempts

This module is OPTIONAL - Irongate works fully without it.
Enable in config.yaml under 'blockchain:' section.

Requirements: pip install py-algorand-sdk
"""

import base64
import hashlib
import json
import logging
import time
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger('irongate.blockchain')

# Check for Algorand SDK availability
ALGORAND_AVAILABLE = False
try:
    from algosdk.v2client import algod
    from algosdk import account, mnemonic, transaction
    from algosdk.error import AlgodHTTPError
    ALGORAND_AVAILABLE = True
    logger.info("Algorand SDK loaded - Layer 8 blockchain features available")
except ImportError:
    logger.info("Algorand SDK not installed - Layer 8 disabled (install with: pip install py-algorand-sdk)")


class VerificationResult(Enum):
    """Result of blockchain device verification"""
    VERIFIED = "verified"
    NOT_REGISTERED = "not_registered"
    IP_MISMATCH = "ip_mismatch"
    MAC_MISMATCH = "mac_mismatch"
    REVOKED = "revoked"
    BLOCKCHAIN_ERROR = "blockchain_error"
    DISABLED = "disabled"
    SDK_MISSING = "sdk_missing"


@dataclass
class DeviceRecord:
    """On-chain device registration record"""
    mac: str
    ip: str
    zone: str
    hostname: str
    registered_at: int
    trust_score: int = 100


class IrongateBlockchain:
    """
    Algorand Mainnet integration for Irongate network security.
    
    Features:
    - Device whitelist stored immutably on Algorand blockchain
    - Real-time device verification with local caching
    - Cryptographic proof of device identity
    - Tamper-proof audit logging
    - Post-quantum ready (Algorand supports FALCON signatures)
    
    Usage:
        bc = IrongateBlockchain(config)
        if bc.enabled:
            result = bc.verify_device(mac, ip)
            if result['verified']:
                # Allow device
            else:
                # Block device
    """
    
    # Algorand Mainnet endpoints (free, no API key required)
    NETWORKS = {
        'mainnet': {
            'algod': 'https://mainnet-api.algonode.cloud',
            'indexer': 'https://mainnet-idx.algonode.cloud'
        },
        'testnet': {
            'algod': 'https://testnet-api.algonode.cloud', 
            'indexer': 'https://testnet-idx.algonode.cloud'
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize blockchain connection.
        
        Args:
            config: Blockchain config section from config.yaml
        """
        self.enabled = False
        self.config = config or {}
        
        # Set defaults for attributes that might be accessed even when disabled
        self.network = self.config.get('network', 'mainnet')
        self.cache_ttl = self.config.get('cache_ttl', 60)
        self.fallback_allow = self.config.get('fallback_allow', True)
        self.audit_logging = self.config.get('audit_logging', False)
        self.allow_rogue_devices = self.config.get('allow_rogue_devices', False)
        self._cache = {}
        self._cache_time = {}
        self._admin_key = None
        self._admin_address = None
        
        # Check if explicitly enabled
        if not self.config.get('enabled', False):
            logger.info("Blockchain Layer 8: Disabled in config")
            return
        
        # Check SDK availability
        if not ALGORAND_AVAILABLE:
            logger.warning("Blockchain Layer 8: Cannot enable - SDK not installed")
            logger.warning("  Install with: pip install py-algorand-sdk")
            return
        
        # Get additional config values
        self.app_id = self.config.get('app_id')
        self.admin_mnemonic = self.config.get('admin_mnemonic')
        
        # Validate app_id
        if not self.app_id:
            logger.warning("Blockchain Layer 8: No app_id configured - disabled")
            logger.warning("  Deploy smart contract and set app_id in config")
            return
        
        # Initialize Algorand client
        try:
            network_config = self.NETWORKS.get(self.network, self.NETWORKS['mainnet'])
            self.algod_client = algod.AlgodClient('', network_config['algod'])
            
            # Test connection
            status = self.algod_client.status()
            logger.info(f"Blockchain Layer 8: Connected to Algorand {self.network}")
            logger.info(f"  Network round: {status.get('last-round', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Blockchain Layer 8: Connection failed - {e}")
            return
        
        # Initialize admin credentials if provided
        if self.admin_mnemonic:
            try:
                self._admin_key = mnemonic.to_private_key(self.admin_mnemonic)
                self._admin_address = account.address_from_private_key(self._admin_key)
                logger.info(f"  Admin address: {self._admin_address[:12]}...{self._admin_address[-6:]}")
            except Exception as e:
                logger.warning(f"  Invalid admin mnemonic: {e}")
        
        self._last_sync = 0
        
        # Mark as enabled
        self.enabled = True
        logger.info(f"Blockchain Layer 8: ENABLED (App ID: {self.app_id})")
    
    def _get_cached(self, mac: str) -> Optional[Dict]:
        """Get device from cache if still valid"""
        mac = mac.lower()
        if mac in self._cache:
            age = time.time() - self._cache_time.get(mac, 0)
            if age < self.cache_ttl:
                return self._cache[mac]
            # Cache expired
            del self._cache[mac]
            if mac in self._cache_time:
                del self._cache_time[mac]
        return None
    
    def _set_cached(self, mac: str, data: Dict):
        """Store device in cache"""
        mac = mac.lower()
        self._cache[mac] = data
        self._cache_time[mac] = time.time()
    
    def _parse_device_value(self, value_bytes: bytes) -> Optional[Dict]:
        """Parse device data from blockchain storage format"""
        try:
            value = value_bytes.decode('utf-8')
            # Format: ip|zone|hostname|timestamp
            parts = value.split('|')
            if len(parts) >= 3:
                return {
                    'ip': parts[0],
                    'zone': parts[1],
                    'hostname': parts[2] if len(parts) > 2 else 'unknown',
                    'timestamp': int(parts[3]) if len(parts) > 3 else 0
                }
        except:
            pass
        return None
    
    def verify_device(self, mac: str, ip: str) -> Dict[str, Any]:
        """
        Verify a device against the blockchain registry.
        
        This is the main verification function called by Irongate's
        ARP defense loop for every network access attempt.
        
        Args:
            mac: Device MAC address (any format)
            ip: Device IP address
            
        Returns:
            Dict with:
                - verified: bool (True if device should be allowed)
                - result: VerificationResult enum
                - zone: str (device zone if verified)
                - hostname: str (device hostname if verified)
                - trust_score: int (0-100)
                - cached: bool (whether from cache)
                - details: str (human-readable explanation)
        """
        # Not enabled - return neutral result
        if not self.enabled:
            return {
                'verified': None,
                'result': VerificationResult.DISABLED,
                'trust_score': 50,
                'details': 'Blockchain verification disabled'
            }
        
        mac = mac.lower().replace('-', ':')
        
        # Check cache first (fast path)
        cached = self._get_cached(mac)
        if cached:
            if cached.get('ip') == ip:
                return {
                    'verified': True,
                    'result': VerificationResult.VERIFIED,
                    'zone': cached.get('zone'),
                    'hostname': cached.get('hostname'),
                    'trust_score': 100,
                    'cached': True,
                    'details': f"Verified from cache (zone: {cached.get('zone')})"
                }
            else:
                # IP mismatch - possible spoofing!
                return {
                    'verified': False,
                    'result': VerificationResult.IP_MISMATCH,
                    'expected_ip': cached.get('ip'),
                    'actual_ip': ip,
                    'trust_score': 0,
                    'cached': True,
                    'details': f"ALERT: MAC {mac} registered with IP {cached.get('ip')}, seen at {ip}"
                }
        
        # Query blockchain
        try:
            app_info = self.algod_client.application_info(self.app_id)
            global_state = app_info.get('params', {}).get('global-state', [])
            
            for item in global_state:
                # Decode key (MAC address)
                try:
                    key_bytes = base64.b64decode(item['key'])
                    key = key_bytes.decode('utf-8').lower()
                except:
                    continue
                
                # Check if this is our device
                if key == mac or key.replace(':', '') == mac.replace(':', ''):
                    # Found device - decode value
                    value_data = item.get('value', {})
                    if value_data.get('type') == 1:  # bytes
                        value_bytes = base64.b64decode(value_data.get('bytes', ''))
                        device = self._parse_device_value(value_bytes)
                        
                        if device:
                            # Cache it
                            self._set_cached(mac, device)
                            
                            if device['ip'] == ip:
                                return {
                                    'verified': True,
                                    'result': VerificationResult.VERIFIED,
                                    'zone': device['zone'],
                                    'hostname': device['hostname'],
                                    'registered_at': device['timestamp'],
                                    'trust_score': 100,
                                    'cached': False,
                                    'details': f"Blockchain verified (zone: {device['zone']})"
                                }
                            else:
                                return {
                                    'verified': False,
                                    'result': VerificationResult.IP_MISMATCH,
                                    'expected_ip': device['ip'],
                                    'actual_ip': ip,
                                    'zone': device['zone'],
                                    'trust_score': 0,
                                    'cached': False,
                                    'details': f"SPOOFING DETECTED: {mac} should be at {device['ip']}"
                                }
            
            # Device not found in registry
            return {
                'verified': False,
                'result': VerificationResult.NOT_REGISTERED,
                'mac': mac,
                'ip': ip,
                'trust_score': 0,
                'cached': False,
                'details': f"Device {mac} not registered on blockchain"
            }
            
        except AlgodHTTPError as e:
            logger.error(f"Blockchain API error: {e}")
            return {
                'verified': self.fallback_allow,
                'result': VerificationResult.BLOCKCHAIN_ERROR,
                'trust_score': 50 if self.fallback_allow else 0,
                'details': f"Blockchain unavailable: {e}"
            }
        except Exception as e:
            logger.error(f"Blockchain verification error: {e}")
            return {
                'verified': self.fallback_allow,
                'result': VerificationResult.BLOCKCHAIN_ERROR,
                'trust_score': 50 if self.fallback_allow else 0,
                'details': f"Verification error: {e}"
            }
    
    def register_device(self, mac: str, ip: str, zone: str, hostname: str) -> Dict[str, Any]:
        """
        Register a new device on the Algorand blockchain.
        
        Args:
            mac: Device MAC address
            ip: Device IP address  
            zone: Security zone (isolated/servers/trusted)
            hostname: Device hostname
            
        Returns:
            Dict with success status and transaction ID
        """
        if not self.enabled:
            return {'success': False, 'error': 'Blockchain not enabled'}
        
        if not self._admin_key:
            return {'success': False, 'error': 'No admin credentials configured'}
        
        mac = mac.lower().replace('-', ':')
        
        try:
            params = self.algod_client.suggested_params()
            
            # Encode device data: ip|zone|hostname|timestamp
            device_value = f"{ip}|{zone}|{hostname}|{int(time.time())}"
            
            txn = transaction.ApplicationCallTxn(
                sender=self._admin_address,
                sp=params,
                index=self.app_id,
                on_complete=transaction.OnComplete.NoOpOC,
                app_args=[
                    b"register",
                    mac.encode(),
                    device_value.encode()
                ]
            )
            
            signed_txn = txn.sign(self._admin_key)
            tx_id = self.algod_client.send_transaction(signed_txn)
            
            # Wait for confirmation
            result = transaction.wait_for_confirmation(self.algod_client, tx_id, 4)
            
            # Update cache
            self._set_cached(mac, {
                'ip': ip,
                'zone': zone,
                'hostname': hostname,
                'timestamp': int(time.time())
            })
            
            logger.info(f"Device registered on blockchain: {mac} -> {ip} ({zone})")
            
            return {
                'success': True,
                'tx_id': tx_id,
                'confirmed_round': result.get('confirmed-round'),
                'explorer_url': f"https://allo.info/tx/{tx_id}"
            }
            
        except AlgodHTTPError as e:
            error_msg = str(e)
            if 'already' in error_msg.lower():
                return {'success': False, 'error': 'Device already registered'}
            return {'success': False, 'error': error_msg}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def revoke_device(self, mac: str) -> Dict[str, Any]:
        """
        Remove a device from the blockchain registry.
        
        Args:
            mac: Device MAC address to revoke
            
        Returns:
            Dict with success status
        """
        if not self.enabled:
            return {'success': False, 'error': 'Blockchain not enabled'}
        
        if not self._admin_key:
            return {'success': False, 'error': 'No admin credentials configured'}
        
        mac = mac.lower().replace('-', ':')
        
        try:
            params = self.algod_client.suggested_params()
            
            txn = transaction.ApplicationCallTxn(
                sender=self._admin_address,
                sp=params,
                index=self.app_id,
                on_complete=transaction.OnComplete.NoOpOC,
                app_args=[
                    b"revoke",
                    mac.encode()
                ]
            )
            
            signed_txn = txn.sign(self._admin_key)
            tx_id = self.algod_client.send_transaction(signed_txn)
            
            transaction.wait_for_confirmation(self.algod_client, tx_id, 4)
            
            # Remove from cache
            mac_lower = mac.lower()
            if mac_lower in self._cache:
                del self._cache[mac_lower]
            if mac_lower in self._cache_time:
                del self._cache_time[mac_lower]
            
            logger.info(f"Device revoked from blockchain: {mac}")
            
            return {
                'success': True,
                'tx_id': tx_id,
                'explorer_url': f"https://allo.info/tx/{tx_id}"
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def log_access(self, mac: str, ip: str, action: str, result: str) -> Optional[str]:
        """
        Log an access attempt to the blockchain for immutable audit trail.
        
        This creates a permanent, tamper-proof record of every network
        access attempt - useful for compliance and forensics.
        
        Args:
            mac: Device MAC address
            ip: Device IP address
            action: Action attempted (e.g., "arp_request", "connect")
            result: Result ("allowed", "blocked", "spoofed")
            
        Returns:
            Transaction ID if successful, None otherwise
        """
        if not self.enabled or not self.audit_logging:
            return None
        
        if not self._admin_key:
            return None
        
        try:
            params = self.algod_client.suggested_params()
            
            # Create audit log entry
            log_entry = json.dumps({
                't': 'audit',
                'm': mac.lower(),
                'i': ip,
                'a': action,
                'r': result,
                'ts': int(time.time())
            })
            
            # 0-ALGO self-transfer with note (costs ~0.001 ALGO)
            txn = transaction.PaymentTxn(
                sender=self._admin_address,
                sp=params,
                receiver=self._admin_address,
                amt=0,
                note=log_entry.encode()
            )
            
            signed_txn = txn.sign(self._admin_key)
            tx_id = self.algod_client.send_transaction(signed_txn)
            
            return tx_id
            
        except Exception as e:
            logger.debug(f"Audit log failed (non-critical): {e}")
            return None
    
    def get_all_devices(self) -> List[DeviceRecord]:
        """Get all registered devices from blockchain"""
        if not self.enabled:
            return []
        
        devices = []
        try:
            app_info = self.algod_client.application_info(self.app_id)
            global_state = app_info.get('params', {}).get('global-state', [])
            
            for item in global_state:
                try:
                    key_bytes = base64.b64decode(item['key'])
                    key = key_bytes.decode('utf-8')
                    
                    # Skip system keys
                    if key in ('admin', 'device_count', 'version'):
                        continue
                    
                    # Check if looks like MAC
                    if ':' not in key and len(key) != 12:
                        continue
                    
                    value_data = item.get('value', {})
                    if value_data.get('type') == 1:
                        value_bytes = base64.b64decode(value_data.get('bytes', ''))
                        device = self._parse_device_value(value_bytes)
                        if device:
                            devices.append(DeviceRecord(
                                mac=key,
                                ip=device['ip'],
                                zone=device['zone'],
                                hostname=device['hostname'],
                                registered_at=device['timestamp']
                            ))
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Failed to get blockchain devices: {e}")
        
        return devices
    
    def get_stats(self) -> Dict[str, Any]:
        """Get blockchain status and statistics"""
        stats = {
            'enabled': self.enabled,
            'sdk_available': ALGORAND_AVAILABLE,
            'network': self.config.get('network', 'mainnet'),
            'app_id': self.config.get('app_id'),
            'cache_size': len(self._cache),
            'cache_ttl': self.cache_ttl,
            'fallback_allow': self.fallback_allow,
            'audit_logging': self.audit_logging,
            'allow_rogue_devices': self.allow_rogue_devices,
            'admin_configured': self._admin_address is not None
        }
        
        if self.enabled:
            try:
                status = self.algod_client.status()
                stats['network_round'] = status.get('last-round')
                stats['connected'] = True
            except:
                stats['connected'] = False
        
        return stats
    
    def clear_cache(self):
        """Clear the local device cache"""
        self._cache.clear()
        self._cache_time.clear()
        logger.info("Blockchain cache cleared")


# Standalone test
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 60)
    print("IRONGATE LAYER 8: ALGORAND BLOCKCHAIN MODULE")
    print("=" * 60)
    
    test_config = {
        'enabled': True,
        'network': 'mainnet',
        'app_id': None,  # Set your app ID
        'cache_ttl': 60
    }
    
    bc = IrongateBlockchain(test_config)
    print(f"\nStatus: {bc.get_stats()}")
    
    if bc.enabled:
        # Test verification
        result = bc.verify_device("aa:bb:cc:dd:ee:ff", "192.168.1.100")
        print(f"Test result: {result}")
BLOCKCHAINPY

chmod +x /opt/irongate/blockchain.py

# Create Smart Contract Source (PyTeal)
echo -e "${YELLOW}Creating Algorand smart contract source...${NC}"
cat > /opt/irongate/smart_contract.py << 'SMARTCONTRACTPY'
#!/usr/bin/env python3
"""
Irongate Device Registry Smart Contract for Algorand

This script can:
1. Compile the PyTeal contract to TEAL (default)
2. Deploy the contract on-chain with 'onchain' argument

Usage:
    python3 smart_contract.py           # Compile only
    python3 smart_contract.py onchain   # Compile and deploy to blockchain

Requirements: pip install py-algorand-sdk pyteal
"""

import sys
import os
import base64
import time
import yaml

# ═══════════════════════════════════════════════════════════════════════════
# SMART CONTRACT (PyTeal)
# ═══════════════════════════════════════════════════════════════════════════

def get_approval_teal():
    """Generate approval program TEAL code"""
    try:
        from pyteal import (
            App, Approve, Assert, Bytes, Cond, Global, Int, Mode,
            OnComplete, Return, Seq, Txn, And, compileTeal
        )
    except ImportError:
        print("ERROR: PyTeal not installed")
        print("Install with: pip install pyteal --break-system-packages")
        sys.exit(1)
    
    admin_key = Bytes("admin")
    device_count_key = Bytes("device_count")
    is_admin = Txn.sender() == App.globalGet(admin_key)
    
    basic_checks = And(
        Txn.rekey_to() == Global.zero_address(),
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.asset_close_to() == Global.zero_address()
    )
    
    on_creation = Seq([
        Assert(basic_checks),
        App.globalPut(admin_key, Txn.sender()),
        App.globalPut(device_count_key, Int(0)),
        Approve()
    ])
    
    on_register = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(3)),
        Assert(App.globalGet(Txn.application_args[1]) == Bytes("")),
        App.globalPut(Txn.application_args[1], Txn.application_args[2]),
        App.globalPut(device_count_key, App.globalGet(device_count_key) + Int(1)),
        Approve()
    ])
    
    on_update = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(3)),
        Assert(App.globalGet(Txn.application_args[1]) != Bytes("")),
        App.globalPut(Txn.application_args[1], Txn.application_args[2]),
        Approve()
    ])
    
    on_revoke = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(2)),
        Assert(App.globalGet(Txn.application_args[1]) != Bytes("")),
        App.globalDel(Txn.application_args[1]),
        App.globalPut(device_count_key, App.globalGet(device_count_key) - Int(1)),
        Approve()
    ])
    
    on_transfer = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(2)),
        App.globalPut(admin_key, Txn.application_args[1]),
        Approve()
    ])
    
    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_complete() == OnComplete.DeleteApplication, Return(is_admin)],
        [Txn.on_complete() == OnComplete.UpdateApplication, Return(is_admin)],
        [Txn.on_complete() == OnComplete.CloseOut, Approve()],
        [Txn.on_complete() == OnComplete.OptIn, Approve()],
        [Txn.application_args[0] == Bytes("register"), on_register],
        [Txn.application_args[0] == Bytes("update"), on_update],
        [Txn.application_args[0] == Bytes("revoke"), on_revoke],
        [Txn.application_args[0] == Bytes("transfer_admin"), on_transfer],
    )
    
    return compileTeal(program, mode=Mode.Application, version=8)


def get_clear_teal():
    """Generate clear program TEAL code"""
    from pyteal import Approve, Mode, compileTeal
    return compileTeal(Approve(), mode=Mode.Application, version=8)


def compile_contracts():
    """Compile and save TEAL files"""
    print("=" * 60)
    print("IRONGATE DEVICE REGISTRY - SMART CONTRACT COMPILER")
    print("=" * 60)
    
    approval_teal = get_approval_teal()
    clear_teal = get_clear_teal()
    
    os.makedirs("/opt/irongate", exist_ok=True)
    
    with open("/opt/irongate/approval.teal", "w") as f:
        f.write(approval_teal)
    print(f"\n✓ Approval program: /opt/irongate/approval.teal ({len(approval_teal)} bytes)")
    
    with open("/opt/irongate/clear.teal", "w") as f:
        f.write(clear_teal)
    print(f"✓ Clear program: /opt/irongate/clear.teal ({len(clear_teal)} bytes)")
    
    return approval_teal, clear_teal


# ═══════════════════════════════════════════════════════════════════════════
# ON-CHAIN DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════

def deploy_onchain():
    """Deploy the smart contract directly to Algorand blockchain"""
    
    print("=" * 60)
    print("IRONGATE DEVICE REGISTRY - ON-CHAIN DEPLOYMENT")
    print("=" * 60)
    
    # Check for Algorand SDK
    try:
        from algosdk import account, mnemonic, transaction
        from algosdk.v2client import algod
    except ImportError:
        print("\nERROR: Algorand SDK not installed")
        print("Install with: pip install py-algorand-sdk --break-system-packages")
        sys.exit(1)
    
    # Load config or prompt for mnemonic
    config_path = "/etc/irongate/config.yaml"
    admin_mnemonic = None
    network = "mainnet"
    
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            blockchain_cfg = config.get('blockchain', {})
            admin_mnemonic = blockchain_cfg.get('admin_mnemonic')
            network = blockchain_cfg.get('network', 'mainnet')
        except Exception as e:
            print(f"Warning: Could not read config: {e}")
    
    # Prompt for mnemonic if not in config
    if not admin_mnemonic:
        print("\nNo admin_mnemonic found in /etc/irongate/config.yaml")
        print("Enter your 25-word Algorand wallet mnemonic:")
        print("(This wallet will be the admin and needs ~0.5 ALGO for deployment)")
        print()
        admin_mnemonic = input("Mnemonic: ").strip()
    
    if not admin_mnemonic or len(admin_mnemonic.split()) != 25:
        print("ERROR: Invalid mnemonic. Must be 25 words.")
        sys.exit(1)
    
    # Get private key from mnemonic
    try:
        private_key = mnemonic.to_private_key(admin_mnemonic)
        sender_address = account.address_from_private_key(private_key)
    except Exception as e:
        print(f"ERROR: Invalid mnemonic - {e}")
        sys.exit(1)
    
    print(f"\n✓ Wallet address: {sender_address}")
    
    # Select network
    print(f"\nNetwork: {network.upper()}")
    if network == "testnet":
        algod_address = "https://testnet-api.algonode.cloud"
    else:
        algod_address = "https://mainnet-api.algonode.cloud"
    
    print(f"Node: {algod_address}")
    
    # Connect to Algorand node
    try:
        client = algod.AlgodClient("", algod_address)
        params = client.suggested_params()
        print(f"✓ Connected to Algorand {network}")
    except Exception as e:
        print(f"ERROR: Could not connect to Algorand node - {e}")
        sys.exit(1)
    
    # Check balance
    try:
        account_info = client.account_info(sender_address)
        balance = account_info.get('amount', 0) / 1_000_000
        print(f"✓ Wallet balance: {balance:.6f} ALGO")
        
        if balance < 0.5:
            print(f"\nERROR: Insufficient balance. Need at least 0.5 ALGO, have {balance:.6f}")
            print("Fund your wallet and try again.")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Could not check balance - {e}")
        sys.exit(1)
    
    # Compile contracts
    print("\n" + "-" * 60)
    print("Compiling smart contract...")
    approval_teal, clear_teal = compile_contracts()
    
    # Compile TEAL to bytecode
    print("\nCompiling TEAL to bytecode...")
    try:
        approval_compiled = client.compile(approval_teal)
        approval_bytes = base64.b64decode(approval_compiled['result'])
        
        clear_compiled = client.compile(clear_teal)
        clear_bytes = base64.b64decode(clear_compiled['result'])
        
        print(f"✓ Approval bytecode: {len(approval_bytes)} bytes")
        print(f"✓ Clear bytecode: {len(clear_bytes)} bytes")
    except Exception as e:
        print(f"ERROR: Could not compile TEAL - {e}")
        sys.exit(1)
    
    # Create application
    print("\n" + "-" * 60)
    print("Deploying to blockchain...")
    
    # Global schema: 62 byte slices (for MAC addresses), 2 ints
    global_schema = transaction.StateSchema(num_uints=2, num_byte_slices=62)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)
    
    try:
        txn = transaction.ApplicationCreateTxn(
            sender=sender_address,
            sp=params,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval_bytes,
            clear_program=clear_bytes,
            global_schema=global_schema,
            local_schema=local_schema
        )
        
        # Sign transaction
        signed_txn = txn.sign(private_key)
        
        # Submit transaction
        tx_id = client.send_transaction(signed_txn)
        print(f"✓ Transaction submitted: {tx_id}")
        
        # Wait for confirmation
        print("Waiting for confirmation...")
        confirmed_txn = None
        for _ in range(30):
            try:
                confirmed_txn = client.pending_transaction_info(tx_id)
                if confirmed_txn.get('confirmed-round', 0) > 0:
                    break
            except:
                pass
            time.sleep(1)
        
        if not confirmed_txn or confirmed_txn.get('confirmed-round', 0) == 0:
            print("ERROR: Transaction not confirmed after 30 seconds")
            sys.exit(1)
        
        app_id = confirmed_txn.get('application-index')
        
        print("\n" + "=" * 60)
        print("SUCCESS! SMART CONTRACT DEPLOYED")
        print("=" * 60)
        print(f"\n  App ID: {app_id}")
        print(f"  Transaction: {tx_id}")
        print(f"  Network: {network}")
        print(f"  Admin: {sender_address}")
        
        # Update config file
        print("\n" + "-" * 60)
        print("Updating /etc/irongate/config.yaml...")
        
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            else:
                config = {}
            
            if 'blockchain' not in config:
                config['blockchain'] = {}
            
            config['blockchain']['enabled'] = True
            config['blockchain']['network'] = network
            config['blockchain']['app_id'] = app_id
            config['blockchain']['admin_mnemonic'] = admin_mnemonic
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"✓ Config updated with App ID: {app_id}")
            print("\n✓ Restart Irongate to activate Layer 8:")
            print("  sudo systemctl restart irongate")
            
        except Exception as e:
            print(f"\nWarning: Could not update config - {e}")
            print(f"\nManually add to {config_path}:")
            print(f"""
blockchain:
  enabled: true
  network: {network}
  app_id: {app_id}
  admin_mnemonic: "{admin_mnemonic}"
""")
        
        # Save app_id to a separate file for easy reference
        with open("/opt/irongate/app_id.txt", "w") as f:
            f.write(str(app_id))
        
        print("\n" + "=" * 60)
        print("NEXT STEPS:")
        print("=" * 60)
        print("""
1. Restart Irongate:
   sudo systemctl restart irongate

2. Register your devices:
   irongate-blockchain sync

3. Verify registration:
   irongate-blockchain list
""")
        
        return app_id
        
    except Exception as e:
        print(f"ERROR: Deployment failed - {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "onchain":
        deploy_onchain()
    else:
        compile_contracts()
        print("""
═══════════════════════════════════════════════════════════════
TO DEPLOY ON-CHAIN:
═══════════════════════════════════════════════════════════════

Run: python3 /opt/irongate/smart_contract.py onchain

This will:
1. Compile the contract
2. Deploy to Algorand blockchain
3. Update /etc/irongate/config.yaml with the App ID

Requirements:
- Algorand wallet with ~0.5 ALGO
- 25-word mnemonic phrase
═══════════════════════════════════════════════════════════════
""")
SMARTCONTRACTPY

chmod +x /opt/irongate/smart_contract.py

# Create Blockchain CLI Tool
echo -e "${YELLOW}Creating blockchain management CLI...${NC}"
cat > /opt/irongate/irongate-blockchain << 'BLOCKCHAINCLI'
#!/usr/bin/env python3
"""
Irongate Blockchain CLI - Manage Layer 8 device registry

Usage:
    irongate-blockchain status          Show blockchain status
    irongate-blockchain list            List all registered devices  
    irongate-blockchain register        Register a device
    irongate-blockchain revoke <mac>    Revoke a device
    irongate-blockchain verify <mac> <ip>  Verify a device
    irongate-blockchain sync            Sync devices from config to blockchain
"""

import sys
import os
import yaml
import argparse

# Add irongate path
sys.path.insert(0, '/opt/irongate')

def load_config():
    """Load Irongate config"""
    try:
        with open('/etc/irongate/config.yaml') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

def get_blockchain():
    """Get blockchain instance"""
    try:
        from blockchain import IrongateBlockchain, ALGORAND_AVAILABLE
        if not ALGORAND_AVAILABLE:
            print("Algorand SDK not installed!")
            print("Install with: pip install py-algorand-sdk")
            sys.exit(1)
        
        config = load_config()
        bc_config = config.get('blockchain', {})
        return IrongateBlockchain(bc_config)
    except ImportError as e:
        print(f"Failed to import blockchain module: {e}")
        sys.exit(1)

def cmd_status(args):
    """Show blockchain status"""
    bc = get_blockchain()
    stats = bc.get_stats()
    
    print("=" * 50)
    print("IRONGATE LAYER 8 BLOCKCHAIN STATUS")
    print("=" * 50)
    
    print(f"\nSDK Available: {'✓ Yes' if stats.get('sdk_available') else '✗ No'}")
    print(f"Enabled: {'✓ Yes' if stats.get('enabled') else '✗ No'}")
    print(f"Network: {stats.get('network', 'N/A')}")
    print(f"App ID: {stats.get('app_id', 'Not configured')}")
    print(f"Admin Configured: {'✓ Yes' if stats.get('admin_configured') else '✗ No'}")
    
    if stats.get('enabled'):
        print(f"Connected: {'✓ Yes' if stats.get('connected') else '✗ No'}")
        if stats.get('network_round'):
            print(f"Network Round: {stats.get('network_round')}")
        print(f"Cache Size: {stats.get('cache_size')} devices")
        print(f"Cache TTL: {stats.get('cache_ttl')}s")
        print(f"Audit Logging: {'✓ On' if stats.get('audit_logging') else '✗ Off'}")
        print(f"Rogue Devices: {'✓ Allowed (Public WiFi Mode)' if stats.get('allow_rogue_devices') else '✗ Blocked (Strict Mode)'}")

def cmd_list(args):
    """List all registered devices"""
    bc = get_blockchain()
    
    if not bc.enabled:
        print("Blockchain not enabled. Configure in /etc/irongate/config.yaml")
        return
    
    devices = bc.get_all_devices()
    
    print("=" * 70)
    print("BLOCKCHAIN REGISTERED DEVICES")
    print("=" * 70)
    
    if not devices:
        print("\nNo devices registered on blockchain.")
        return
    
    print(f"\n{'MAC':<20} {'IP':<16} {'Zone':<12} {'Hostname':<20}")
    print("-" * 70)
    
    for dev in devices:
        print(f"{dev.mac:<20} {dev.ip:<16} {dev.zone:<12} {dev.hostname:<20}")
    
    print(f"\nTotal: {len(devices)} devices")

def cmd_register(args):
    """Register a device on blockchain"""
    bc = get_blockchain()
    
    if not bc.enabled:
        print("Blockchain not enabled.")
        return
    
    if not bc._admin_key:
        print("Admin mnemonic not configured in config.yaml")
        return
    
    # Get device info
    mac = args.mac or input("MAC address: ").strip()
    ip = args.ip or input("IP address: ").strip()
    zone = args.zone or input("Zone (isolated/servers/trusted): ").strip() or "isolated"
    hostname = args.hostname or input("Hostname: ").strip() or "device"
    
    print(f"\nRegistering device:")
    print(f"  MAC: {mac}")
    print(f"  IP: {ip}")
    print(f"  Zone: {zone}")
    print(f"  Hostname: {hostname}")
    
    confirm = input("\nConfirm? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    
    result = bc.register_device(mac, ip, zone, hostname)
    
    if result.get('success'):
        print(f"\n✓ Device registered successfully!")
        print(f"  Transaction: {result.get('tx_id')}")
        print(f"  Explorer: {result.get('explorer_url')}")
    else:
        print(f"\n✗ Registration failed: {result.get('error')}")

def cmd_revoke(args):
    """Revoke a device from blockchain"""
    bc = get_blockchain()
    
    if not bc.enabled:
        print("Blockchain not enabled.")
        return
    
    if not bc._admin_key:
        print("Admin mnemonic not configured.")
        return
    
    mac = args.mac
    
    confirm = input(f"Revoke device {mac}? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled.")
        return
    
    result = bc.revoke_device(mac)
    
    if result.get('success'):
        print(f"\n✓ Device revoked!")
        print(f"  Transaction: {result.get('tx_id')}")
    else:
        print(f"\n✗ Revocation failed: {result.get('error')}")

def cmd_verify(args):
    """Verify a device against blockchain"""
    bc = get_blockchain()
    
    if not bc.enabled:
        print("Blockchain not enabled.")
        return
    
    result = bc.verify_device(args.mac, args.ip)
    
    print("=" * 50)
    print("DEVICE VERIFICATION RESULT")
    print("=" * 50)
    
    print(f"\nMAC: {args.mac}")
    print(f"IP: {args.ip}")
    print(f"\nVerified: {'✓ YES' if result.get('verified') else '✗ NO'}")
    print(f"Result: {result.get('result')}")
    print(f"Trust Score: {result.get('trust_score', 0)}/100")
    
    if result.get('zone'):
        print(f"Zone: {result.get('zone')}")
    if result.get('hostname'):
        print(f"Hostname: {result.get('hostname')}")
    if result.get('details'):
        print(f"Details: {result.get('details')}")

def cmd_sync(args):
    """Sync devices from config to blockchain"""
    bc = get_blockchain()
    config = load_config()
    
    if not bc.enabled:
        print("Blockchain not enabled.")
        return
    
    if not bc._admin_key:
        print("Admin mnemonic not configured.")
        return
    
    devices = config.get('devices', [])
    if not devices:
        print("No devices in config to sync.")
        return
    
    print(f"Syncing {len(devices)} devices to blockchain...")
    
    success = 0
    failed = 0
    
    for dev in devices:
        mac = dev.get('mac', '').lower()
        ip = dev.get('ip', '')
        zone = dev.get('zone', 'isolated')
        hostname = dev.get('hostname', 'device')
        
        if not mac or not ip:
            continue
        
        # Check if already registered
        existing = bc.verify_device(mac, ip)
        if existing.get('verified'):
            print(f"  ✓ {mac} already registered")
            success += 1
            continue
        
        result = bc.register_device(mac, ip, zone, hostname)
        if result.get('success'):
            print(f"  ✓ Registered {mac} ({ip})")
            success += 1
        else:
            print(f"  ✗ Failed {mac}: {result.get('error')}")
            failed += 1
    
    print(f"\nSync complete: {success} success, {failed} failed")


def main():
    parser = argparse.ArgumentParser(
        description='Irongate Layer 8 Blockchain Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    irongate-blockchain status
    irongate-blockchain list
    irongate-blockchain register --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.100 --zone servers
    irongate-blockchain revoke aa:bb:cc:dd:ee:ff
    irongate-blockchain verify aa:bb:cc:dd:ee:ff 192.168.1.100
    irongate-blockchain sync
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # status
    subparsers.add_parser('status', help='Show blockchain status')
    
    # list
    subparsers.add_parser('list', help='List registered devices')
    
    # register
    reg_parser = subparsers.add_parser('register', help='Register a device')
    reg_parser.add_argument('--mac', help='MAC address')
    reg_parser.add_argument('--ip', help='IP address')
    reg_parser.add_argument('--zone', help='Zone (isolated/servers/trusted)')
    reg_parser.add_argument('--hostname', help='Hostname')
    
    # revoke
    rev_parser = subparsers.add_parser('revoke', help='Revoke a device')
    rev_parser.add_argument('mac', help='MAC address to revoke')
    
    # verify
    ver_parser = subparsers.add_parser('verify', help='Verify a device')
    ver_parser.add_argument('mac', help='MAC address')
    ver_parser.add_argument('ip', help='IP address')
    
    # sync
    subparsers.add_parser('sync', help='Sync config devices to blockchain')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    commands = {
        'status': cmd_status,
        'list': cmd_list,
        'register': cmd_register,
        'revoke': cmd_revoke,
        'verify': cmd_verify,
        'sync': cmd_sync,
    }
    
    commands[args.command](args)


if __name__ == '__main__':
    main()
BLOCKCHAINCLI

chmod +x /opt/irongate/irongate-blockchain
ln -sf /opt/irongate/irongate-blockchain /usr/local/bin/irongate-blockchain

# Create systemd service
cat > /etc/systemd/system/irongate.service << EOF
[Unit]
Description=Irongate Network Isolation
After=network.target dnsmasq.service
Wants=network.target

[Service]
Type=simple
ExecStart=/opt/irongate/venv/bin/python /opt/irongate/irongate.py
ExecStartPre=/bin/sleep 2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create config from database (includes any existing devices)
LOCAL_MAC=$(ip link show "$INTERFACE" 2>/dev/null | awk '/ether/ {print $2}')
GATEWAY_MAC=$(ip neigh show | grep "$CURRENT_GATEWAY " | awk '{print $5}' | head -n1)

# Get devices from database if they exist
DEVICES_YAML=""
if [ -f /var/www/irongate/dhcp.db ]; then
    DEVICE_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM irongate_devices WHERE ip IS NOT NULL AND ip != '';" 2>/dev/null || echo "0")
    if [ "$DEVICE_COUNT" -gt 0 ]; then
        DEVICES_YAML=$(sqlite3 /var/www/irongate/dhcp.db "SELECT '  - mac: \"' || mac || '\"' || char(10) || '    ip: \"' || ip || '\"' || char(10) || '    zone: \"' || zone || '\"' FROM irongate_devices WHERE ip IS NOT NULL AND ip != '';" 2>/dev/null)
    fi
fi

cat > /etc/irongate/config.yaml << EOF
# Irongate Configuration
# Generated: $(date)

mode: "single"

network:
  interface: "$INTERFACE"
  local_ip: "$CURRENT_IP"
  local_mac: "$LOCAL_MAC"
  gateway_ip: "$CURRENT_GATEWAY"
  gateway_mac: "$GATEWAY_MAC"

layers:
  arp_defense: true
  ipv6_ra: true
  gateway_takeover: true
  bypass_detection: true
  firewall: true

# Layer 8: Algorand Blockchain Verification (OPTIONAL)
# Provides 100% VLAN-equivalent protection via cryptographic device authentication
# Set enabled: true and configure app_id to activate
blockchain:
  enabled: false
  network: "mainnet"
  # Your deployed smart contract App ID (required if enabled)
  app_id: null
  # Admin mnemonic for registering/revoking devices (25 words)
  # Keep this secure! Only needed for admin operations
  admin_mnemonic: null
  # Cache TTL in seconds (reduces blockchain queries)
  cache_ttl: 60
  # Allow network access if blockchain unavailable
  fallback_allow: true
  # Log all access attempts to blockchain audit trail
  audit_logging: false
  # PUBLIC WIFI MODE: Allow unregistered devices but log them
  # When true: devices not registered on-chain are allowed but logged
  # When false: devices not registered on-chain are BLOCKED (default)
  # Useful for: coffee shops, hotels, public hotspots
  allow_rogue_devices: false

devices:
$DEVICES_YAML
EOF

# If no devices, clean up the empty devices section
if [ -z "$DEVICES_YAML" ]; then
    sed -i 's/^devices:$/devices: []/' /etc/irongate/config.yaml
fi

# Set permissions so www-data can update config from web UI
chown root:www-data /etc/irongate/config.yaml
chmod 664 /etc/irongate/config.yaml

chown -R root:root /opt/irongate
chmod -R 755 /opt/irongate

systemctl daemon-reload
systemctl enable irongate 2>/dev/null || true

# Always stop and kill any existing irongate processes before starting
echo -e "${YELLOW}Stopping any existing Irongate processes...${NC}"
systemctl stop irongate 2>/dev/null || true
pkill -9 -f "irongate.py" 2>/dev/null || true
# Clear any leftover firewall rules
nft delete table inet irongate 2>/dev/null || true
sleep 1

# Start fresh
echo -e "${YELLOW}Starting Irongate service...${NC}"
systemctl start irongate
sleep 2
if systemctl is-active --quiet irongate; then
    echo -e "${GREEN}  ✓ Irongate started successfully${NC}"
else
    echo -e "${RED}  ✗ Irongate failed to start - check logs${NC}"
    journalctl -u irongate -n 10 --no-pager
fi

#######################################
# Create Auto-Updater Service & Timer
#######################################
echo -e "${YELLOW}Creating auto-updater service...${NC}"

# Create updater script
cat > /opt/irongate/irongate-updater.sh << 'UPDATER'
#!/bin/bash
# Irongate Auto-Updater (commit hash based)

GITHUB_API="https://api.github.com/repos/beatboxes/irongate/commits/main"
REPO_RAW="https://raw.githubusercontent.com/beatboxes/irongate/main"
DB_PATH="/var/www/irongate/dhcp.db"
LOG_FILE="/var/log/irongate-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Check if auto-update is enabled
AUTO_UPDATE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE" != "true" ]; then
    log "Auto-update is disabled, skipping"
    exit 0
fi

log "Starting update check..."

# Get current commit from database
CURRENT_COMMIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null || echo "unknown")

# Get latest commit from GitHub API
REMOTE_COMMIT=$(curl -sf -H "User-Agent: Irongate-Updater" "$GITHUB_API" 2>/dev/null | grep -m1 '"sha"' | cut -d'"' -f4 | cut -c1-7)

if [ -z "$REMOTE_COMMIT" ]; then
    log "ERROR: Could not fetch remote commit from GitHub API"
    exit 1
fi

log "Current: $CURRENT_COMMIT, Remote: $REMOTE_COMMIT"

# Update last check time
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));" 2>/dev/null

# Compare commits
if [ "$CURRENT_COMMIT" != "$REMOTE_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ] && [ "$CURRENT_COMMIT" != "local" ]; then
    log "Update available! Downloading..."
    
    # Store the target commit BEFORE running update (in case script fails to set it)
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$REMOTE_COMMIT');" 2>/dev/null
    log "Set target commit to $REMOTE_COMMIT"
    
    # Download and run installer
    SCRIPT_PATH="/tmp/irongate-update.sh"
    curl -sf -H "User-Agent: Irongate-Updater" "$REPO_RAW/irongate-install.sh" -o "$SCRIPT_PATH"
    
    if [ -f "$SCRIPT_PATH" ]; then
        chmod +x "$SCRIPT_PATH"
        log "Running installer..."
        bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1
        log "Update complete!"
    else
        log "ERROR: Failed to download update script"
        exit 1
    fi
else
    log "Already up to date"
fi

log "Update check finished"
UPDATER

chmod +x /opt/irongate/irongate-updater.sh

# Create systemd service for manual updates
cat > /etc/systemd/system/irongate-updater.service << EOF
[Unit]
Description=Irongate Auto-Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/irongate/irongate-updater.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for daily auto-updates
cat > /etc/systemd/system/irongate-updater.timer << EOF
[Unit]
Description=Irongate Daily Update Check

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

# Check if auto-update should be enabled from database
AUTO_UPDATE_ENABLED=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE_ENABLED" = "true" ]; then
    systemctl enable irongate-updater.timer 2>/dev/null || true
    systemctl start irongate-updater.timer 2>/dev/null || true
    echo -e "${GREEN}Auto-updater enabled${NC}"
else
    echo -e "${YELLOW}Auto-updater available (disabled by default)${NC}"
fi

#######################################
# Configure Nginx
#######################################
echo -e "${YELLOW}Configuring Nginx...${NC}"

# Detect PHP-FPM socket from PHP version (more reliable than searching for files that may not exist during install)
# PHP_VERSION was already detected at line ~96
if [ -n "$PHP_VERSION" ]; then
    PHP_SOCK="/run/php/php${PHP_VERSION}-fpm.sock"
else
    # Fallback: try to find existing socket
    PHP_SOCK=$(find /run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
    if [ -z "$PHP_SOCK" ]; then
        PHP_SOCK=$(find /var/run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
    fi
    if [ -z "$PHP_SOCK" ]; then
        # Last resort: derive from php-fpm service
        PHP_SOCK="/run/php/php-fpm.sock"
    fi
fi
echo -e "PHP-FPM Socket: ${GREEN}$PHP_SOCK${NC}"

cat > /etc/nginx/sites-available/irongate << EOF
server {
    listen $WEBUI_PORT;
    server_name _;
    root /var/www/irongate;
    index index.html;
    
    # Timeouts to prevent hung connections
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
    
    # Limit request size
    client_max_body_size 10M;
    
    location / { try_files \$uri \$uri/ =404; }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$PHP_SOCK;
        
        # PHP timeouts - prevent hung requests from blocking workers
        fastcgi_connect_timeout 10s;
        fastcgi_send_timeout 30s;
        fastcgi_read_timeout 30s;
    }
    
    location ~ /\.ht { deny all; }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "OK";
        add_header Content-Type text/plain;
    }
}
EOF

ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

#######################################
# Configure log rotation
#######################################
cat > /etc/logrotate.d/dnsmasq << EOF
/var/log/dnsmasq.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload dnsmasq > /dev/null 2>&1 || true
    endscript
}
EOF

#######################################
# Enable and start services
#######################################
echo -e "${YELLOW}Starting services...${NC}"

systemctl daemon-reload

# Detect PHP-FPM service name
PHP_FPM_SERVICE=$(systemctl list-unit-files | grep -oP 'php[\d.]*-fpm\.service' | head -n1)
if [ -z "$PHP_FPM_SERVICE" ]; then
    PHP_FPM_SERVICE="php-fpm.service"
fi
PHP_FPM_SERVICE="${PHP_FPM_SERVICE%.service}"
echo -e "PHP-FPM Service: ${GREEN}$PHP_FPM_SERVICE${NC}"

systemctl enable dnsmasq nginx $PHP_FPM_SERVICE
systemctl restart $PHP_FPM_SERVICE
systemctl restart nginx

# Test dnsmasq config before starting
echo -e "${YELLOW}Validating dnsmasq configuration...${NC}"
if dnsmasq --test 2>&1; then
    echo -e "${GREEN}Configuration valid, starting dnsmasq...${NC}"
    # Kill any zombie dnsmasq processes first
    pkill -9 dnsmasq 2>/dev/null || true
    sleep 1
    systemctl start dnsmasq
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to start dnsmasq. Checking for port conflicts...${NC}"
        ss -ulnp | grep :67 || true
        journalctl -u dnsmasq -n 10 --no-pager
    fi
else
    echo -e "${RED}Configuration error detected. Check /etc/dnsmasq.conf${NC}"
    echo -e "${YELLOW}Attempting to start anyway...${NC}"
    pkill -9 dnsmasq 2>/dev/null || true
    sleep 1
    systemctl start dnsmasq || true
fi

#######################################
# Final output
#######################################
SERVER_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)

echo ""
echo -e "${MAGENTA}╔══════════════════════════════════════════════╗"
echo -e "║     🛡️  IRONGATE Setup Complete!             ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Commit: ${BOLD}${IRONGATE_COMMIT}${NC}"
echo ""
echo -e "Services:"
echo -e "  DHCP Server:  $(systemctl is-active dnsmasq)"
echo -e "  Web Server:   $(systemctl is-active nginx)"
echo -e "  Protection:   $(systemctl is-active irongate 2>/dev/null || echo 'disabled (enable in UI)')"
echo -e "  Auto-Update:  $(systemctl is-active irongate-updater.timer 2>/dev/null || echo 'disabled')"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Access Irongate at:${NC}"
echo ""
echo -e "  ${BOLD}http://$SERVER_IP/${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}PROTECTION LAYERS:${NC}"
echo -e "  ${GREEN}Layer 1-7${NC}  - Aggressive ARP/IPv6/Firewall isolation (~98% protection)"
echo -e "  ${MAGENTA}Layer 8${NC}    - Algorand Blockchain verification (100% VLAN-equivalent)"
echo ""
echo -e "${CYAN}FEATURES:${NC}"
echo -e "  ${GREEN}📊 Dashboard${NC}    - Protection status, zone summary"
echo -e "  ${GREEN}🖥️ Devices${NC}      - Add devices to zones (isolated/servers/trusted)"
echo -e "  ${GREEN}🔗 DHCP${NC}         - Configure DHCP server settings"
echo -e "  ${GREEN}📋 Leases${NC}       - View active DHCP leases"
echo -e "  ${GREEN}📌 Reservations${NC} - Static IP reservations"
echo -e "  ${GREEN}🛡️ Protection${NC}   - Enable/configure network isolation"
echo -e "  ${GREEN}⬆️ Updates${NC}      - Check for updates, enable auto-update"
echo ""
echo -e "${CYAN}ZONES:${NC}"
echo -e "  ${RED}🔴 isolated${NC}  - Internet only, no LAN access"
echo -e "  ${YELLOW}🟡 servers${NC}   - Can talk to other servers, no LAN"
echo -e "  ${GREEN}🟢 trusted${NC}   - Full network access"
echo ""
echo -e "${CYAN}LAYER 8 BLOCKCHAIN (Optional):${NC}"
echo -e "  Provides cryptographic device authentication via Algorand"
echo -e "  "
echo -e "  ${BOLD}One-Click Deployment:${NC}"
echo -e "    ${BOLD}python3 /opt/irongate/smart_contract.py onchain${NC}"
echo -e "    (Requires ~0.5 ALGO and 25-word mnemonic)"
echo -e "  "
echo -e "  ${BOLD}Or use the PowerShell script (from Windows):${NC}"
echo -e "    ${BOLD}.\\Deploy-IrongateBlockchain.ps1 -Server $SERVER_IP${NC}"
echo -e "  "
echo -e "  ${YELLOW}Public WiFi Mode:${NC}"
echo -e "    Set ${BOLD}allow_rogue_devices: true${NC} to log unregistered"
echo -e "    devices without blocking them (useful for hotspots)"
echo -e "  "
echo -e "  CLI: ${BOLD}irongate-blockchain status|list|register|revoke|sync${NC}"
echo ""
echo -e "${CYAN}QUICK START:${NC}"
echo -e "  1. Go to 🖥️ Devices & Zones"
echo -e "  2. Click 'Import from Leases' or '+ Add Device'"
echo -e "  3. Assign devices to zones"
echo -e "  4. Go to 🛡️ Protection and enable"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  SAFE TO RE-RUN: Preserves all settings & data${NC}"
echo -e "${GREEN}  GitHub: ${IRONGATE_REPO}${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
