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

# Stop services during configuration and kill any zombie processes
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
EOSQL
fi

#######################################
# Create PHP Backend API
#######################################
echo -e "${YELLOW}Creating web application...${NC}"

cat > /var/www/irongate/api.php << 'EOPHP'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

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
                    'arp_defense' => getSetting($db, 'irongate_arp_defense') === 'true',
                    'ipv6_ra' => getSetting($db, 'irongate_ipv6_ra') === 'true',
                    'gateway_takeover' => getSetting($db, 'irongate_gateway_takeover') === 'true',
                    'bypass_detection' => getSetting($db, 'irongate_bypass_detection') === 'true'
                ]
            ]
        ]);
        break;
    
    case 'irongate_settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            foreach ($data as $key => $value) {
                if (strpos($key, 'irongate_') === 0) {
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
                      'irongate_bypass_detection'] as $key) {
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
    
    default:
        echo json_encode(['error' => 'Unknown action', 'available' => [
            'system', 'status', 'settings', 'apply', 'leases', 
            'reservations', 'logs', 'restart', 'stop', 'start',
            'diagnostics', 'repair', 'validate',
            'irongate_status', 'irongate_settings', 'irongate_interfaces',
            'irongate_toggle', 'irongate_apply', 'irongate_logs', 'irongate_devices'
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
    $config .= "  firewall: true\n\n";
    
    // Get protected devices from database
    $results = $db->query('SELECT mac, ip, zone FROM irongate_devices');
    $devices = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $devices[] = $row;
    }
    
    if (!empty($devices)) {
        $config .= "devices:\n";
        foreach ($devices as $dev) {
            $config .= "  - mac: \"" . $dev['mac'] . "\"\n";
            $config .= "    ip: \"" . $dev['ip'] . "\"\n";
            $config .= "    zone: \"" . $dev['zone'] . "\"\n";
        }
    }
    
    // Write config
    @mkdir('/etc/irongate', 0755, true);
    file_put_contents('/etc/irongate/config.yaml', $config);
    
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
            <div class="nav-item" onclick="showPage('logs')">📜 Logs</div>
            <div class="nav-item" onclick="showPage('diagnostics')">🔧 Diagnostics</div>
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
                    <div class="card-title">Zone Access Rules</div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;">
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
                    </div>
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
                        <div class="form-group"><label>Lease Time</label><input class="form-control" id="set-lease-time" placeholder="e.g., 24h"></div>
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
                                <span style="color:var(--warning);">~95% effective</span>
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
                            <strong>Single-NIC Mode:</strong>
                            <ol style="margin:10px 0 0 20px;color:var(--text-secondary);">
                                <li>ARP cache poisoning to intercept traffic</li>
                                <li>IPv6 RA to capture IPv6 devices</li>
                                <li>nftables zone-based firewall rules</li>
                                <li>Gateway takeover prevents bypass</li>
                                <li>Active monitoring detects evasion</li>
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

    <script>
        let systemInfo = {};
        let currentSettings = {};
        
        function showPage(page){
            document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
            document.getElementById('page-'+page).classList.add('active');
            const pages = ['dashboard','devices','dhcp','leases','reservations','protection','logs','diagnostics'];
            const idx = pages.indexOf(page);
            if (idx >= 0) document.querySelectorAll('.nav-item')[idx].classList.add('active');
            if(page==='leases')loadLeases();
            if(page==='reservations')loadReservations();
            if(page==='logs')loadLogs();
            if(page==='diagnostics')runDiagnostics();
            if(page==='devices')loadIrongateDevices();
            if(page==='protection')loadIrongateStatus();
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
                irongate_bypass_detection: document.getElementById('layer-bypass').checked ? 'true' : 'false'
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
        // IRONGATE DEVICE MANAGEMENT
        //======================================================================
        
        let irongateDevices = [];
        
        async function loadIrongateDevices() {
            try {
                const res = await api('irongate_devices');
                if (res.success) {
                    irongateDevices = res.data || [];
                    renderDevicesTable();
                }
            } catch (e) {
                console.error('Load devices error:', e);
            }
        }
        
        function renderDevicesTable() {
            const tbody = document.getElementById('irongate-devices-table');
            if (!irongateDevices || irongateDevices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);">No devices configured. Add devices to protect them with Irongate.</td></tr>';
                return;
            }
            
            // Sort by zone
            const zoneOrder = { isolated: 0, servers: 1, trusted: 2 };
            const sorted = [...irongateDevices].sort((a, b) => 
                (zoneOrder[a.zone] || 99) - (zoneOrder[b.zone] || 99)
            );
            
            tbody.innerHTML = sorted.map(dev => {
                const zoneColor = dev.zone === 'isolated' ? '#e94560' : 
                                  dev.zone === 'servers' ? '#ffc107' : '#00bf63';
                const zoneIcon = dev.zone === 'isolated' ? '🔴' : 
                                 dev.zone === 'servers' ? '🟡' : '🟢';
                return \`
                    <tr>
                        <td><span style="color:\${zoneColor};">\${zoneIcon} \${dev.zone}</span></td>
                        <td><code>\${dev.mac}</code></td>
                        <td>\${dev.ip || '<span style="color:var(--text-secondary);">DHCP</span>'}</td>
                        <td>\${dev.hostname || '-'}</td>
                        <td>
                            <button class="btn btn-sm btn-secondary" onclick="editDevice(\${dev.id})">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteDevice(\${dev.id})" style="margin-left:5px;">Delete</button>
                        </td>
                    </tr>
                \`;
            }).join('');
        }
        
        function showDeviceModal(device = null) {
            document.getElementById('device-form').reset();
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
                container.innerHTML = available.map(lease => \`
                    <label style="display:flex;align-items:center;gap:10px;padding:10px;background:var(--bg);border-radius:6px;margin-bottom:8px;cursor:pointer;">
                        <input type="checkbox" class="import-check" data-mac="\${lease.mac}" data-ip="\${lease.ip}" data-hostname="\${lease.hostname}">
                        <div style="flex:1;">
                            <div><strong>\${lease.hostname || 'Unknown'}</strong></div>
                            <div style="font-size:0.85em;color:var(--text-secondary);">
                                <code>\${lease.mac}</code> → \${lease.ip}
                            </div>
                        </div>
                        <select class="form-control import-zone" style="width:150px;font-size:0.85em;">
                            <option value="isolated">🔴 isolated</option>
                            <option value="servers">🟡 servers</option>
                            <option value="trusted">🟢 trusted</option>
                        </select>
                    </label>
                \`).join('');
                
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
            toast(\`Imported \${added} device(s)\`, 'success');
            await loadIrongateDevices();
        }
        
        // Load devices when Irongate page is shown
        const origLoadIrongateStatus = loadIrongateStatus;
        loadIrongateStatus = async function() {
            await origLoadIrongateStatus();
            await loadIrongateDevices();
        };
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
www-data ALL=(ALL) NOPASSWD: /usr/bin/pkill -9 dnsmasq
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown dnsmasq\:nogroup /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 644 /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 664 /var/log/dnsmasq.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u dnsmasq *
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u irongate *
www-data ALL=(ALL) NOPASSWD: /usr/bin/tail *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/arping *
EOF
chmod 440 /etc/sudoers.d/dnsmasq-web

#######################################
# Create systemd watchdog for auto-recovery
#######################################
echo -e "${YELLOW}Setting up service watchdog...${NC}"

mkdir -p /etc/systemd/system/dnsmasq.service.d

cat > /etc/systemd/system/dnsmasq.service.d/override.conf << EOF
[Service]
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

[Unit]
StartLimitIntervalSec=60
StartLimitBurst=3
EOF

#######################################
# Create Irongate Network Isolation Service
#######################################
echo -e "${YELLOW}Setting up Irongate network isolation...${NC}"

mkdir -p /opt/irongate
mkdir -p /etc/irongate
mkdir -p /var/log/irongate

# Create Python virtual environment
python3 -m venv /opt/irongate/venv 2>/dev/null || true
/opt/irongate/venv/bin/pip install --quiet pyyaml scapy netifaces 2>/dev/null || \
    pip3 install --break-system-packages pyyaml scapy netifaces 2>/dev/null || true

# Create Irongate main script
cat > /opt/irongate/irongate.py << 'IRONGATEPY'
#!/usr/bin/env python3
"""
Irongate Network Isolation Engine
Provides 6-layer defense (single-NIC) or bridge isolation (dual-NIC)
"""

import os
import sys
import yaml
import time
import signal
import logging
import threading
import subprocess
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('irongate')

class Irongate:
    def __init__(self, config_path='/etc/irongate/config.yaml'):
        self.config_path = config_path
        self.config = {}
        self.running = False
        self.threads = []
        
    def load_config(self):
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f)
            logger.info(f"Loaded config from {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return False
    
    def setup_kernel(self):
        """Enable required kernel features"""
        commands = [
            'sysctl -w net.ipv4.ip_forward=1',
            'sysctl -w net.ipv4.conf.all.arp_filter=1',
            'sysctl -w net.ipv4.conf.all.arp_announce=2',
        ]
        for cmd in commands:
            os.system(cmd + ' 2>/dev/null')
    
    def run_single_nic(self):
        """Run 6-layer software isolation"""
        logger.info("Starting single-NIC mode (6-layer isolation)")
        
        net = self.config.get('network', {})
        layers = self.config.get('layers', {})
        interface = net.get('interface', 'eth0')
        gateway_ip = net.get('gateway_ip', '')
        gateway_mac = net.get('gateway_mac', '')
        local_ip = net.get('local_ip', '')
        local_mac = net.get('local_mac', '')
        
        if not gateway_mac:
            logger.warning("Gateway MAC not known, attempting to discover...")
            os.system(f"arping -c 1 -I {interface} {gateway_ip} 2>/dev/null")
            time.sleep(1)
        
        # Layer 2: ARP Defense
        if layers.get('arp_defense', True):
            t = threading.Thread(target=self._arp_defense_loop, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Layer 2: ARP Defense started")
        
        # Layer 3: IPv6 RA
        if layers.get('ipv6_ra', True):
            t = threading.Thread(target=self._ipv6_ra_loop, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Layer 3: IPv6 RA Attack started")
        
        # Layer 4: Firewall
        self._setup_firewall()
        logger.info("Layer 4: Firewall configured")
        
        # Layer 5+6: Gateway Takeover + Bypass Detection
        if layers.get('gateway_takeover', True):
            t = threading.Thread(target=self._gateway_takeover_loop, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Layer 5+6: Gateway Takeover started")
        
        logger.info("Single-NIC isolation active")
    
    def run_dual_nic(self):
        """Run bridge isolation mode"""
        logger.info("Starting dual-NIC mode (bridge isolation)")
        
        bridge_cfg = self.config.get('bridge', {})
        bridge_name = bridge_cfg.get('bridge_name', 'br-irongate')
        isolated_iface = bridge_cfg.get('isolated_interface', '')
        bridge_ip = bridge_cfg.get('bridge_ip', '10.99.0.1')
        
        if not isolated_iface:
            logger.error("No isolated interface configured!")
            return False
        
        # Check interface exists
        if not os.path.exists(f'/sys/class/net/{isolated_iface}'):
            logger.error(f"Isolated interface {isolated_iface} not found!")
            return False
        
        # Create bridge
        logger.info(f"Creating bridge {bridge_name}")
        os.system(f'ip link set {bridge_name} down 2>/dev/null')
        os.system(f'brctl delbr {bridge_name} 2>/dev/null')
        os.system(f'brctl addbr {bridge_name}')
        os.system(f'brctl stp {bridge_name} off')
        
        # Add isolated interface
        os.system(f'ip link set {isolated_iface} down')
        os.system(f'ip addr flush dev {isolated_iface}')
        os.system(f'brctl addif {bridge_name} {isolated_iface}')
        os.system(f'ip link set {isolated_iface} up')
        
        # Configure bridge IP
        os.system(f'ip addr add {bridge_ip}/16 dev {bridge_name}')
        os.system(f'ip link set {bridge_name} up')
        
        # Enable port isolation (kernel-enforced)
        result = os.system(f'bridge link set dev {isolated_iface} isolated on 2>/dev/null')
        if result == 0:
            logger.info("Port isolation enabled (kernel-enforced)")
        else:
            logger.warning("Port isolation not available, using ebtables")
            os.system(f'ebtables -A FORWARD -i {isolated_iface} -o {isolated_iface} -j DROP')
        
        # Setup NAT
        net = self.config.get('network', {})
        uplink = net.get('interface', 'eth0')
        os.system(f'nft add table nat')
        os.system(f'nft add chain nat postrouting {{ type nat hook postrouting priority 100 \\; }}')
        os.system(f'nft add rule nat postrouting oifname {uplink} masquerade')
        
        # Setup DHCP for bridge (using dnsmasq)
        dhcp_start = bridge_cfg.get('dhcp_start', '10.99.1.1')
        dhcp_end = bridge_cfg.get('dhcp_end', '10.99.255.254')
        
        dnsmasq_conf = f"""
# Irongate Bridge DHCP
interface={bridge_name}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},24h
dhcp-option=option:router,{bridge_ip}
dhcp-option=option:dns-server,{bridge_ip},8.8.8.8
log-dhcp
"""
        with open('/etc/irongate/bridge-dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_conf)
        
        # Start bridge DHCP
        os.system('pkill -f "dnsmasq.*bridge-dnsmasq" 2>/dev/null')
        os.system('dnsmasq --conf-file=/etc/irongate/bridge-dnsmasq.conf &')
        
        logger.info("Dual-NIC bridge isolation active")
        logger.info(f"  Bridge: {bridge_name} ({bridge_ip})")
        logger.info(f"  Isolated: {isolated_iface}")
        logger.info(f"  DHCP: {dhcp_start} - {dhcp_end}")
        
        return True
    
    def _arp_defense_loop(self):
        """Continuous ARP poisoning for gateway"""
        try:
            from scapy.all import Ether, ARP, sendp, conf
            conf.verb = 0
        except ImportError:
            logger.warning("scapy not available, ARP defense disabled")
            return
        
        net = self.config.get('network', {})
        interface = net.get('interface', 'eth0')
        gateway_ip = net.get('gateway_ip')
        local_mac = net.get('local_mac')
        gateway_mac = net.get('gateway_mac')
        
        if not all([gateway_ip, local_mac]):
            logger.error("Missing network config for ARP defense")
            return
        
        while self.running:
            try:
                # Gratuitous ARP: tell everyone we are the gateway
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac) / ARP(
                    op=2, psrc=gateway_ip, hwsrc=local_mac,
                    pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(pkt, iface=interface, verbose=False)
                time.sleep(2)
            except Exception as e:
                logger.error(f"ARP defense error: {e}")
                time.sleep(5)
    
    def _ipv6_ra_loop(self):
        """Send IPv6 Router Advertisements"""
        try:
            from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, sendp, conf
            conf.verb = 0
        except ImportError:
            logger.warning("scapy not available, IPv6 RA disabled")
            return
        
        net = self.config.get('network', {})
        interface = net.get('interface', 'eth0')
        local_mac = net.get('local_mac')
        
        while self.running:
            try:
                pkt = Ether(src=local_mac, dst="33:33:00:00:00:01") / \
                      IPv6(src="fe80::1", dst="ff02::1") / \
                      ICMPv6ND_RA(routerlifetime=1800) / \
                      ICMPv6NDOptPrefixInfo(prefix="fd00:iron:gate::", prefixlen=64)
                sendp(pkt, iface=interface, verbose=False)
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"IPv6 RA error: {e}")
                time.sleep(5)
    
    def _gateway_takeover_loop(self):
        """Bidirectional ARP poisoning + gateway MAC spoofing"""
        try:
            from scapy.all import Ether, ARP, sendp, conf
            conf.verb = 0
        except ImportError:
            return
        
        net = self.config.get('network', {})
        interface = net.get('interface', 'eth0')
        gateway_ip = net.get('gateway_ip')
        gateway_mac = net.get('gateway_mac')
        local_mac = net.get('local_mac')
        
        devices = self.config.get('devices', [])
        
        while self.running:
            try:
                # Poison gateway for each protected device
                for dev in devices:
                    dev_ip = dev.get('ip')
                    if dev_ip and gateway_mac:
                        # Tell gateway that device is at our MAC
                        pkt = Ether(dst=gateway_mac, src=local_mac) / ARP(
                            op=2, psrc=dev_ip, hwsrc=local_mac,
                            pdst=gateway_ip, hwdst=gateway_mac
                        )
                        sendp(pkt, iface=interface, verbose=False)
                
                time.sleep(1)
            except Exception as e:
                logger.error(f"Gateway takeover error: {e}")
                time.sleep(5)
    
    def _setup_firewall(self):
        """Configure nftables firewall with zone-based rules"""
        net = self.config.get('network', {})
        interface = net.get('interface', 'eth0')
        gateway_ip = net.get('gateway_ip', '')
        local_ip = net.get('local_ip', '')
        devices = self.config.get('devices', [])
        
        # Group devices by zone
        isolated_ips = []
        servers_ips = []
        trusted_ips = []
        
        for dev in devices:
            ip = dev.get('ip', '')
            zone = dev.get('zone', 'isolated')
            if ip:
                if zone == 'isolated':
                    isolated_ips.append(ip)
                elif zone == 'servers':
                    servers_ips.append(ip)
                elif zone == 'trusted':
                    trusted_ips.append(ip)
        
        # Build IP sets
        isolated_set = ', '.join(isolated_ips) if isolated_ips else '0.0.0.0'
        servers_set = ', '.join(servers_ips) if servers_ips else '0.0.0.0'
        
        # RFC1918 private ranges (LAN)
        lan_ranges = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'
        
        rules = f"""
# Irongate Zone-Based Firewall
# Generated by Irongate Engine

table inet irongate {{
    # IP Sets for zones
    set isolated_devices {{
        type ipv4_addr
        flags interval
        elements = {{ {isolated_set} }}
    }}
    
    set servers_devices {{
        type ipv4_addr
        flags interval
        elements = {{ {servers_set} }}
    }}
    
    set lan_ranges {{
        type ipv4_addr
        flags interval
        elements = {{ {lan_ranges} }}
    }}
    
    chain input {{
        type filter hook input priority 0; policy accept;
    }}
    
    chain forward {{
        type filter hook forward priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # ISOLATED zone: Only internet, no LAN, no other devices
        ip saddr @isolated_devices ip daddr @lan_ranges drop
        ip saddr @isolated_devices ip daddr @isolated_devices drop
        ip saddr @isolated_devices ip daddr @servers_devices drop
        ip saddr @isolated_devices accept  # Internet only
        
        # SERVERS zone: Can talk to other servers, no LAN
        ip saddr @servers_devices ip daddr @lan_ranges drop
        ip saddr @servers_devices ip daddr @isolated_devices drop
        ip saddr @servers_devices ip daddr @servers_devices accept  # Inter-server OK
        ip saddr @servers_devices accept  # Internet OK
        
        # TRUSTED zone: Full access (handled by default accept below)
        
        # Block same-interface forwarding for unclassified traffic
        iifname "{interface}" oifname "{interface}" drop
    }}
    
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
    
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        oifname "{interface}" masquerade
    }}
}}
"""
        try:
            # Flush existing irongate table
            os.system('nft delete table inet irongate 2>/dev/null')
            
            with open('/tmp/irongate.nft', 'w') as f:
                f.write(rules)
            
            result = os.system('nft -f /tmp/irongate.nft 2>/dev/null')
            if result == 0:
                logger.info(f"Firewall configured: {len(isolated_ips)} isolated, {len(servers_ips)} servers, {len(trusted_ips)} trusted")
            else:
                logger.error("Failed to apply nftables rules")
        except Exception as e:
            logger.error(f"Firewall setup error: {e}")
    
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
                return False
        else:
            self.run_single_nic()
        
        logger.info("Irongate running")
        
        # Keep alive
        while self.running:
            time.sleep(1)
        
        return True
    
    def stop(self):
        """Stop all services"""
        self.running = False
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

# Create default config
cat > /etc/irongate/config.yaml << EOF
# Irongate Default Configuration
# This file is auto-generated - use Web UI to configure

mode: "single"

network:
  interface: "$INTERFACE"
  local_ip: "$CURRENT_IP"
  gateway_ip: "$CURRENT_GATEWAY"

layers:
  arp_defense: true
  ipv6_ra: true
  gateway_takeover: true
  bypass_detection: true
  firewall: true

devices: []
EOF

chown -R root:root /opt/irongate
chmod -R 755 /opt/irongate

systemctl daemon-reload
systemctl enable irongate 2>/dev/null || true

echo -e "${GREEN}Irongate service installed${NC}"

#######################################
# Configure Nginx
#######################################
echo -e "${YELLOW}Configuring Nginx...${NC}"

# Detect PHP-FPM socket dynamically
PHP_SOCK=$(find /run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
if [ -z "$PHP_SOCK" ]; then
    PHP_SOCK=$(find /var/run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
fi
if [ -z "$PHP_SOCK" ]; then
    PHP_SOCK="/run/php/php-fpm.sock"
fi
echo -e "PHP-FPM Socket: ${GREEN}$PHP_SOCK${NC}"

cat > /etc/nginx/sites-available/irongate << EOF
server {
    listen $WEBUI_PORT;
    server_name _;
    root /var/www/irongate;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
    location ~ \.php\$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:$PHP_SOCK; }
    location ~ /\.ht { deny all; }
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
echo -e "Services:"
echo -e "  DHCP Server:  $(systemctl is-active dnsmasq)"
echo -e "  Web Server:   $(systemctl is-active nginx)"
echo -e "  Protection:   $(systemctl is-active irongate 2>/dev/null || echo 'disabled (enable in UI)')"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Access Irongate at:${NC}"
echo ""
echo -e "  ${BOLD}http://$SERVER_IP/${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}FEATURES:${NC}"
echo -e "  ${GREEN}📊 Dashboard${NC}    - Protection status, zone summary"
echo -e "  ${GREEN}🖥️ Devices${NC}      - Add devices to zones (isolated/servers/trusted)"
echo -e "  ${GREEN}🔗 DHCP${NC}         - Configure DHCP server settings"
echo -e "  ${GREEN}📋 Leases${NC}       - View active DHCP leases"
echo -e "  ${GREEN}📌 Reservations${NC} - Static IP reservations"
echo -e "  ${GREEN}🛡️ Protection${NC}   - Enable/configure network isolation"
echo ""
echo -e "${CYAN}ZONES:${NC}"
echo -e "  ${RED}🔴 isolated${NC}  - Internet only, no LAN access"
echo -e "  ${YELLOW}🟡 servers${NC}   - Can talk to other servers, no LAN"
echo -e "  ${GREEN}🟢 trusted${NC}   - Full network access"
echo ""
echo -e "${CYAN}QUICK START:${NC}"
echo -e "  1. Go to 🖥️ Devices & Zones"
echo -e "  2. Click 'Import from Leases' or '+ Add Device'"
echo -e "  3. Assign devices to zones"
echo -e "  4. Go to 🛡️ Protection and enable"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  SAFE TO RE-RUN: Preserves all settings & data${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
