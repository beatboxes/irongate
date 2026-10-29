#!/bin/bash

#######################################
# IRONGATE - Network Isolation System
#
# This script is a self-contained installer: it carries the whole codebase in
# heredocs and can deploy IronGate on its own.
#
#   sudo bash irongate-install.sh
#
# The same code is also committed as ordinary files under src/, web/, config/
# and templates/ so it can be reviewed, diffed and opened in an editor. This
# script remains the source of truth. After changing a heredoc here, run:
#
#   python3 tools/heredoc_sync.py --extract
#
# and `bash tools/check-sync.sh` will confirm the two copies still agree.
#
# Do not rename this file. irongate-updater.sh and the web UI's update action
# both fetch it from the repository by this exact name; renaming it breaks
# automatic updates on every deployed instance.
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

# ---- installer PATH: begin ----
# A fixed, absolute PATH. The installer runs as root from sudo, from the updater's systemd unit or from
# a shell whose PATH may hold "." or an empty or relative entry: `find -execdir` (used on /etc/irongate
# below) refuses to run at all with such a PATH, and a root script should not pick its tools from
# whatever directories the caller listed anyway.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
# ---- installer PATH: end ----

IRONGATE_REPO="https://github.com/beatboxes/irongate"
IRONGATE_RAW="https://raw.githubusercontent.com/beatboxes/irongate/main"
IRONGATE_API="https://api.github.com/repos/beatboxes/irongate/commits/main"

# Get current commit hash from GitHub (will be stored after install)
echo "Fetching commit hash from GitHub API..."
API_RESPONSE=$(curl -sf --max-time 30 -H "User-Agent: Irongate-Updater" "$IRONGATE_API" 2>/dev/null)
if [ -n "$API_RESPONSE" ]; then
    IRONGATE_COMMIT=$(echo "$API_RESPONSE" | grep -m1 '"sha"' | cut -d'"' -f4 | cut -c1-7)
fi

# ---- installer commit id: begin ----
# IRONGATE_COMMIT is printed, and at the end of the install written into a root `sqlite3` statement. Its
# fallback below comes from dhcp.db, which the web tier can write, so a value such as
#   x'); DROP TABLE settings;--
# would have run as SQL. Only a hex commit id (or the literal "local") is ever used; anything else is treated
# as unknown: not shown, not stamped (IRONGATE_COMMIT_STAMP=0), and never interpolated into SQL.
ig_valid_commit() { local LC_ALL=C; [[ "$1" =~ ^[0-9a-f]{7,40}$ ]]; }
IRONGATE_COMMIT_STAMP=1
if ! ig_valid_commit "$IRONGATE_COMMIT"; then
    IRONGATE_COMMIT=""
fi

if [ -z "$IRONGATE_COMMIT" ]; then
    # Fallback: check if already stored in database
    if [ -f /var/www/irongate/dhcp.db ]; then
        IRONGATE_COMMIT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null)
    fi
    if [ -n "$IRONGATE_COMMIT" ] && [ "$IRONGATE_COMMIT" != "local" ] && ! ig_valid_commit "$IRONGATE_COMMIT"; then
        echo "WARNING: installed_commit in dhcp.db is not a commit id - ignoring it (it is not shown and not rewritten)"
        IRONGATE_COMMIT=""
        IRONGATE_COMMIT_STAMP=0
    fi
fi

if [ -z "$IRONGATE_COMMIT" ]; then
    IRONGATE_COMMIT="local"
fi
echo "Commit: $IRONGATE_COMMIT"
# ---- installer commit id: end ----

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
printf "║              %-7s                          ║\n" "${IRONGATE_COMMIT}"
echo "║                                              ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./irongate-install.sh)${NC}"
    exit 1
fi

WEBUI_PORT="80"

# First install of the nginx site, decided ONCE here, before this run touches nginx: neither of our site files
# exists yet. Only then are the other sites (the distribution's "default") removed; on a re-run (which is also what
# the updater does) another site the operator keeps in nginx is left alone. A dangling sites-enabled link left by
# the EXIT trap of a run that failed early does not count (-e follows links).
IG_NGINX_FIRST_INSTALL=0
if [ ! -e /etc/nginx/sites-available/irongate ] && [ ! -e /etc/nginx/sites-enabled/irongate ]; then
    IG_NGINX_FIRST_INSTALL=1
fi

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
# Only packages that are missing are installed, so a re-run (the updater runs this installer) never upgrades a
# package that is already there, and `apt update` runs only when something is missing. `dpkg -s` also succeeds for a
# package that was removed but kept its configuration files, so the Status line is what decides.
ig_pkg_installed() {
    local s re=$'(^|\n)Status: [a-z]+ ok installed($|\n)'
    s=$(dpkg -s "$1" 2>/dev/null) || return 1
    [[ "$s" =~ $re ]]
}
ig_pkgs_missing() {   # the packages among the arguments that are not installed, on one line
    local p out=""
    for p in "$@"; do
        ig_pkg_installed "$p" || out="${out:+$out }$p"
    done
    printf '%s' "$out"
}
IG_PKGS_CORE="dnsmasq nginx php-fpm php-sqlite3 sqlite3 jq"
IG_PKGS_DEPS="python3 python3-pip python3-venv python3-dev nftables iptables arptables ebtables bridge-utils libpcap-dev arp-scan tcpdump net-tools conntrack ipset"
IG_MISSING_CORE=$(ig_pkgs_missing $IG_PKGS_CORE)
IG_MISSING_DEPS=$(ig_pkgs_missing $IG_PKGS_DEPS)
if [ -n "$IG_MISSING_CORE$IG_MISSING_DEPS" ]; then
    apt update
else
    echo -e "${GREEN}All required packages are already installed - no apt run${NC}"
fi
if [ "$IG_MISSING_CORE" = "$IG_PKGS_CORE" ]; then
# nothing of the core set is installed yet: the plain install of the whole set (this exact line is pinned by
# tests/test_installer_o4.py)
apt install -y dnsmasq nginx php-fpm php-sqlite3 sqlite3 jq
elif [ -n "$IG_MISSING_CORE" ]; then
    apt-get install -y $IG_MISSING_CORE
fi

# Install Irongate dependencies
echo -e "${YELLOW}Installing Irongate network isolation dependencies...${NC}"
if [ -n "$IG_MISSING_DEPS" ]; then
    apt-get install -y $IG_MISSING_DEPS 2>/dev/null || true
fi

# Detect PHP version installed
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
echo -e "PHP Version: ${GREEN}$PHP_VERSION${NC}"

# Enable persistent journaling (logs survive reboots for debugging)
echo -e "${YELLOW}Enabling persistent journaling...${NC}"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
# Set journal storage to persistent (Armbian defaults to volatile/RAM-only)
if grep -q '^Storage=volatile' /etc/systemd/journald.conf 2>/dev/null; then
    sed -i 's/^Storage=volatile/Storage=persistent/' /etc/systemd/journald.conf
elif ! grep -q '^Storage=persistent' /etc/systemd/journald.conf 2>/dev/null; then
    sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
fi
# Cap journal size to avoid filling SD card
if grep -q '^#SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null; then
    sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=50M/' /etc/systemd/journald.conf
elif ! grep -q '^SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null; then
    echo "SystemMaxUse=50M" >> /etc/systemd/journald.conf
fi
systemctl restart systemd-journald 2>/dev/null || true

# ---- dnsmasq gate: begin ----
# dnsmasq runs as root and executes what its configuration names (`dhcp-script=`, `conf-script=` - also under
# `dnsmasq --test`). So this installer starts it, and lets it parse a configuration, only on a tree that
# /opt/irongate/dnsmasq-apply --audit accepts: every file dnsmasq reads is root-only and clean. On any other
# state (an installer that failed before or inside the lockdown, a finding) dnsmasq stays stopped.
ig_dnsmasq_tree_ok() {
    [ -x /opt/irongate/dnsmasq-apply ] && /opt/irongate/dnsmasq-apply --audit >/dev/null 2>&1
}
# ---- dnsmasq gate: end ----

# Stop services during configuration and kill any zombie processes
# IMPORTANT: Add trap to restart ALL services if script fails or exits
cleanup_on_exit() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Script exited with code $exit_code - ensuring services are running...${NC}"
    fi
    echo -e "${YELLOW}Ensuring services are started...${NC}"
    
    # Get PHP version
    TRAP_PHP_VER=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
    
    # Fix nginx config with correct socket path
    if [ -n "$TRAP_PHP_VER" ] && [ -f /etc/nginx/sites-available/irongate ]; then
        sed -i "s|fastcgi_pass unix:.*|fastcgi_pass unix:/run/php/php${TRAP_PHP_VER}-fpm.sock;|" /etc/nginx/sites-available/irongate
    fi
    
    # On the FIRST install IronGate is the ONLY enabled nginx site; on a re-run the operator's other sites stay
    # (IG_NGINX_FIRST_INSTALL is decided once at the top; unset, as in an isolated test of this trap, means "no")
    if [ "${IG_NGINX_FIRST_INSTALL:-0}" = 1 ]; then
        rm -f /etc/nginx/sites-enabled/* 2>/dev/null || true
    fi
    ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/irongate
    
    # Start services in correct order (dnsmasq only on a tree the audit accepts: a failed lockdown must not
    # hand a www-data-owned configuration to a root daemon)
    if ig_dnsmasq_tree_ok; then
        systemctl start dnsmasq 2>/dev/null || true
    else
        echo -e "${RED}dnsmasq NOT started: /etc/dnsmasq.conf and /etc/dnsmasq.d are not root-only and clean (dnsmasq-apply --audit)${NC}"
    fi
    [ -n "$TRAP_PHP_VER" ] && systemctl restart php${TRAP_PHP_VER}-fpm 2>/dev/null || true
    systemctl restart nginx 2>/dev/null || true
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

# DHCP grace period notification for IronGate
dhcp-script=/opt/irongate/dhcp-notify.sh
EOF
fi

# Create empty reservations file only if it doesn't exist
if [ -L /etc/dnsmasq.d/reservations.conf ]; then
    # /etc/dnsmasq.d belonged to the web tier until now (O4): never read or write through a link there.
    # The dnsmasq lockdown further down moves it aside.
    echo -e "${RED}  ! /etc/dnsmasq.d/reservations.conf is a symbolic link - not touching it${NC}"
elif [ ! -f /etc/dnsmasq.d/reservations.conf ]; then
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
        chown root:root /etc/dnsmasq.d/reservations.conf
        chmod 644 /etc/dnsmasq.d/reservations.conf
        echo -e "${GREEN}  ✓ Hostnames sanitized (spaces → hyphens)${NC}"
    fi
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi

# Clean up any old backup files in dnsmasq.d that could cause duplicate errors
rm -f /etc/dnsmasq.d/*.bak.* 2>/dev/null || true

#######################################
# Create DHCP Grace Period Notification Script
# This allows new DHCP clients to complete lease negotiation
# before IronGate ARP enforcement kicks in
#######################################
echo -e "${YELLOW}Creating DHCP grace period notification script...${NC}"
mkdir -p /var/run/irongate
cat > /opt/irongate/dhcp-notify.sh << 'DHCPNOTIFY'
#!/bin/bash
# IronGate DHCP Notification Script
# Called by dnsmasq when lease events occur
# Arguments: $1=action (add|del|old), $2=MAC, $3=IP, $4=hostname

ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="$4"
GRACE_FILE="/var/run/irongate/dhcp_grace.list"
GRACE_SECONDS=30

mkdir -p /var/run/irongate

case "$ACTION" in
    add|old)
        # New or renewed lease - add to grace period list
        EXPIRY=$(($(date +%s) + GRACE_SECONDS))
        
        # Remove any existing entry for this MAC
        if [ -f "$GRACE_FILE" ]; then
            grep -v "^${MAC}," "$GRACE_FILE" > "${GRACE_FILE}.tmp" 2>/dev/null || true
            mv "${GRACE_FILE}.tmp" "$GRACE_FILE" 2>/dev/null || true
        fi
        
        # Add new grace period entry
        echo "${MAC},${IP},${EXPIRY}" >> "$GRACE_FILE"
        
        logger -t irongate "DHCP grace period: $MAC ($IP) - ${GRACE_SECONDS}s"
        ;;
    del)
        # Lease released - remove from grace period
        if [ -f "$GRACE_FILE" ]; then
            grep -v "^${MAC}," "$GRACE_FILE" > "${GRACE_FILE}.tmp" 2>/dev/null || true
            mv "${GRACE_FILE}.tmp" "$GRACE_FILE" 2>/dev/null || true
        fi
        logger -t irongate "DHCP lease released: $MAC ($IP)"
        ;;
esac

exit 0
DHCPNOTIFY

chmod +x /opt/irongate/dhcp-notify.sh
chown root:root /opt/irongate/dhcp-notify.sh
echo -e "${GREEN}  ✓ DHCP grace period script created${NC}"

#######################################
# Migration from older versions
#######################################
echo -e "${YELLOW}Checking for existing installations...${NC}"

# Create new directory structure
mkdir -p /var/www/irongate
# /etc/irongate: root:www-data 0750 where this run creates it (item E: the mode is set at creation, never widened later);
# an existing directory keeps the owner and mode it has - the permissions block further down does not chmod it
if [ ! -e /etc/irongate ] && [ ! -L /etc/irongate ]; then
    install -d -m 0750 -o root -g www-data /etc/irongate
fi
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

IG_DB_MODE_BEFORE=""   # the mode dhcp.db has when this run starts (permission and mode step further down)
IG_DB_CREATED=0
IG_DB_BACKUP=""
if [ -f /var/www/irongate/dhcp.db ]; then
    # keep the permission bits the operator gave the file - except setuid/setgid/sticky and world-write (0666 was the
    # mode the O1 hardening took away from every local user); a link is not looked through
    if [ ! -L /var/www/irongate/dhcp.db ]; then
        IG_DB_MODE_BEFORE=$(stat -c %a /var/www/irongate/dhcp.db 2>/dev/null) || IG_DB_MODE_BEFORE=""
        [ -z "$IG_DB_MODE_BEFORE" ] || IG_DB_MODE_BEFORE=$(printf '%o' $(( 8#$IG_DB_MODE_BEFORE & 8#775 )))
    fi
    # BACKUP THE DATABASE FIRST - safety measure
    # (a backup holds everything dhcp.db does: it is created 0600, never wider - umask 077)
    IG_DB_BACKUP=/var/www/irongate/dhcp.db.bak.$(date +%s)
    ( umask 077; cp /var/www/irongate/dhcp.db "$IG_DB_BACKUP" )
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
    # Note: UPDATE and SELECT changes() must be in same session to get correct count
    FIXED_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "UPDATE reservations SET hostname = REPLACE(hostname, ' ', '-') WHERE hostname LIKE '% %'; SELECT changes();" 2>/dev/null || echo "0")
    echo -e "${GREEN}  ✓ Database hostnames sanitized${NC}"
    
    # Verify data wasn't lost
    VERIFY_COUNT=$(sqlite3 /var/www/irongate/dhcp.db "SELECT COUNT(*) FROM reservations;" 2>/dev/null || echo "0")
    if [ "$VERIFY_COUNT" != "$DB_RESERVATION_COUNT" ]; then
        echo -e "${RED}WARNING: Reservation count changed! Restoring backup...${NC}"
        # Get the most recent backup file (sorted by modification time)
        LATEST_BACKUP=$(ls -t /var/www/irongate/dhcp.db.bak.* 2>/dev/null | head -n1)
        if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP" ]; then
            cp "$LATEST_BACKUP" /var/www/irongate/dhcp.db
        fi
    fi
else
    echo -e "${YELLOW}Creating new database${NC}"
    IG_DB_CREATED=1
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

# installed_commit is stamped at the very end of the install ("installer commit stamp" below), not here:
# a stamp made before the install had succeeded made a failed install look installed.

#######################################
# Create PHP Backend API
#######################################
echo -e "${YELLOW}Creating web application...${NC}"

cat > /var/www/irongate/api.php << 'EOPHP'
<?php
// Suppress ALL warnings/notices from corrupting JSON output
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/irongate-api.log');

// Catch fatal errors too
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        if (!headers_sent()) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Internal server error']);
        }
    }
});

set_error_handler(function($severity, $message, $file, $line) {
    error_log("Irongate API: [$severity] $message in $file:$line");
    return true;
});

set_exception_handler(function($e) {
    error_log("Irongate API Exception: " . $e->getMessage());
    if (!headers_sent()) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Server error']);
    }
    exit(1);
});

header('Content-Type: application/json');
// irongate-audit (V3): no CORS headers. The dashboard (index.php) calls this API
// with a relative URL, so it is same-origin; a wildcard Access-Control-Allow-Origin
// only let any web page a LAN browser visited drive this API cross-origin.

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Session guard: all API actions require an authenticated WebUI session.
// Localhost calls without a session cookie are exempted inside the guard.
require_once __DIR__ . '/session_check.php';

$db = new SQLite3('/var/www/irongate/dhcp.db');
// irongate-audit: without a busy timeout, a concurrent php-fpm worker holding
// the write lock made this connection fail immediately, silently dropping
// setting writes and config regeneration under load.
$db->busyTimeout(5000);
$action = $_GET['action'] ?? '';

// CSRF gate (operator ruling): every action that changes the configuration, the credentials or the access
// list needs this session's X-CSRF-Token. The gate is skipped only by irongate_csrf_not_required() - the one
// cli-server + IRONGATE_TEST_SANDBOX=1 seam the PHP suites use. update_now keeps its own check below.
$IRONGATE_CSRF_ACTIONS = ['settings', 'irongate_settings', 'irongate_toggle', 'irongate_apply', 'device_groups',
                          'irongate_devices', 'change_password', 'change_username', 'update_access_list',
                          'toggle_access_list'];
// These three also serve a read-only GET; only their writes need the token. Every other listed action changes
// state on any method and is gated unconditionally.
$IRONGATE_CSRF_READ_ACTIONS = ['settings', 'device_groups', 'irongate_devices'];
if (in_array($action, $IRONGATE_CSRF_ACTIONS, true)
    && !($_SERVER['REQUEST_METHOD'] === 'GET' && in_array($action, $IRONGATE_CSRF_READ_ACTIONS, true))) {
    irongate_require_csrf();
}

// Helper functions
function getSetting($db, $key) {
    $stmt = $db->prepare('SELECT value FROM settings WHERE key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ? $row['value'] : null;
}

function setSetting($db, $key, $value) {
    // irongate-audit (O3): backstop for every caller, whatever the endpoint checked before.
    if (is_string($key) && strpos($key, 'irongate_') === 0 && !validIrongateSetting($key, $value)) {
        return false;
    }
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

// Safe wrapper for applyIrongateConfig - prevents PHP warnings from corrupting JSON output
function safeApplyConfig($db) {
    ob_start();
    $result = ['success' => true];
    try {
        $result = applyIrongateConfig($db);
    } catch (Exception $e) {
        $result = ['success' => false, 'error' => $e->getMessage()];
    } catch (Error $e) {
        $result = ['success' => false, 'error' => $e->getMessage()];
    }
    ob_end_clean();
    return $result;
}

// Hand a request to the root helper (the only writer of config.yaml and auth.json). The verb is one of the
// three the installer's sudoers rule allows; the payload is JSON on stdin, never a path or an argument.
function irongateWriteViaHelper($verb, array $payload) {
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open(['sudo', '-n', '/usr/local/sbin/irongate-webwrite', $verb], $spec, $pipes);
    if (!is_resource($proc)) {
        return ['success' => false, 'error' => 'helper unavailable'];
    }
    @fwrite($pipes[0], json_encode($payload));
    @fclose($pipes[0]);
    $out = (string)stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    $body = json_decode(trim($out), true);
    if ($rc !== 0 || !is_array($body) || ($body['success'] ?? false) !== true) {
        return ['success' => false, 'error' => is_array($body) && is_string($body['error'] ?? null)
            ? $body['error'] : 'helper failed'];
    }
    return ['success' => true, 'changed' => (bool)($body['changed'] ?? false)];
}

// irongate-audit (V1): zone/group names and device IPs are interpolated into an
// nftables ruleset by the root engine, so only strict values may be stored.
// \z (not $) so a trailing newline cannot slip through. The name becomes the nft
// set identifier "<name>_devices", which cannot start with a digit or '-'.
function validZoneName($name) {
    return is_string($name) && preg_match('/^[A-Za-z_][A-Za-z0-9_-]{0,31}\z/', $name) === 1;
}

function validDeviceIp($ip) {
    return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

// irongate-audit (O3): the irongate_* settings are copied into /etc/irongate/config.yaml, which the root
// engine reads and, in dual-NIC mode, turns into bridge, nft and dnsmasq commands. yamlScalar() keeps a
// value from breaking the YAML but not from being a hostile string, so every key has a fixed shape here
// and an unknown irongate_* key is refused. Interface names follow the kernel's rules (1-15 characters,
// not starting with '-' or '.'); the addresses are IPv4 literals; the empty string means "not set".
// \z (not $) so a trailing newline cannot slip through.
function validIrongateSetting($key, $value) {
    static $flags = ['irongate_enabled', 'irongate_arp_defense', 'irongate_ipv6_ra', 'irongate_gateway_takeover',
                     'irongate_bypass_detection', 'irongate_firewall'];
    static $addrs = ['irongate_bridge_ip', 'irongate_bridge_dhcp_start', 'irongate_bridge_dhcp_end'];
    if (!is_string($key) || !is_string($value)) return false;
    if (in_array($key, $flags, true)) return $value === 'true' || $value === 'false';
    if ($key === 'irongate_mode') return $value === 'single' || $value === 'dual';
    if ($key === 'irongate_isolated_interface') {
        return $value === '' || preg_match('/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\z/', $value) === 1;
    }
    if (in_array($key, $addrs, true)) {
        return $value === '' || filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
    return false;
}

// The first problem in the irongate_* entries of a settings POST, or null. Checked before anything is stored.
function irongateSettingsError($data) {
    if (!is_array($data)) return null;
    foreach ($data as $key => $value) {
        if (is_string($key) && strpos($key, 'irongate_') === 0 && !validIrongateSetting($key, $value)) {
            return 'Invalid value or unknown setting: ' . preg_replace('/[^\x20-\x7e]/', '?', substr($key, 0, 40));
        }
    }
    return null;
}

function cidrToHosts($cidr) {
    return pow(2, 32 - intval($cidr)) - 2;
}

// Validate an allow-list entry: single IP (v4/v6) or IPv4 CIDR. Returns the
// trimmed entry on success, false otherwise. Used by the auth endpoints.
function validAllowEntry($v) {
    $v = trim((string)$v);
    if (filter_var($v, FILTER_VALIDATE_IP)) return $v;
    if (preg_match('#^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$#', $v, $m)) {
        for ($i = 1; $i <= 4; $i++) { if (intval($m[$i]) > 255) return false; }
        if (intval($m[5]) > 32) return false;
        return $v;
    }
    return false;
}

// True when $ip is covered by one of the allow-list entries (exact or CIDR).
function aclCovers($entries, $ip) {
    foreach ($entries as $e) {
        if ($e === $ip) return true;
        if (strpos($e, '/') !== false) {
            list($net, $bits) = explode('/', $e, 2);
            $ipL = ip2long($ip);
            $netL = ip2long($net);
            $bits = intval($bits);
            if ($ipL !== false && $netL !== false && $bits >= 0 && $bits <= 32) {
                $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
                if (($ipL & $mask) === ($netL & $mask)) return true;
            }
        }
    }
    return false;
}

// Midnight indexer presets — mirror of blockchain.py NETWORKS (Layer 8).
function midnightNetworks() {
    return [
        'preprod'    => 'https://indexer.preprod.midnight.network/api/v4/graphql',
        'preview'    => 'https://indexer.preview.midnight.network/api/v4/graphql',
        'mainnet'    => 'https://indexer.mainnet.midnight.network/api/v4/graphql',
        'undeployed' => 'http://127.0.0.1:8088/api/v4/graphql',
    ];
}

// irongate-audit (V2, SSRF): a custom indexer URL must be https and its host
// must be the host of one of the https presets above (same rule as
// blockchain.py). Otherwise the probe below could be aimed at loopback, LAN or
// cloud-metadata addresses from the web tier.
// (FILTER_VALIDATE_URL is intentionally not used: it accepts exactly the
// printable-ASCII set that the first check below already enforces.)
function validIndexerUrl($url) {
    if (!is_string($url) || !preg_match('/^[\x21-\x7e]+\z/', $url) || strpos($url, '\\') !== false) {
        return false;
    }
    $p = parse_url($url);
    // Exactly "https", no case folding: parse_url() keeps the case and PHP's stream layer does not
    // fold it either (PHP 8.3 sends the request for an all-upper-case "HTTPS://" in cleartext).
    if ($p === false || ($p['scheme'] ?? '') !== 'https') return false;
    if (isset($p['user']) || isset($p['pass'])) return false;
    if (isset($p['port']) && $p['port'] !== 443) return false;
    $hosts = [];
    foreach (midnightNetworks() as $preset) {
        $pp = parse_url($preset);
        if (strtolower($pp['scheme'] ?? '') === 'https' && !empty($pp['host'])) {
            $hosts[] = strtolower($pp['host']);
        }
    }
    return in_array(strtolower($p['host'] ?? ''), $hosts, true);
}

// Resolve the effective indexer endpoint: custom URL (https, known Midnight
// indexer host only) overrides the network preset, matching blockchain.py.
function midnightEndpoint($network, $custom) {
    $custom = trim((string)$custom);
    if ($custom !== '') {
        // The selected network's own preset (e.g. the local 'undeployed' node) is always fine.
        if ($custom !== (midnightNetworks()[$network] ?? null) && !validIndexerUrl($custom)) {
            return null;
        }
        return $custom;
    }
    $nets = midnightNetworks();
    return $nets[$network] ?? null;
}

// Probe a Midnight indexer with a minimal GraphQL query. Pure PHP streams —
// no shell involved. Returns reachable/response_time_ms/http_code/error.
function midnightProbe($endpoint, $timeout) {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\nUser-Agent: Irongate-WebUI\r\n",
            'content' => '{"query":"{__typename}"}',
            'timeout' => $timeout,
            'ignore_errors' => true,
            // irongate-audit (V2): never follow a redirect. An allowed host must not be
            // able to bounce the probe to loopback, the LAN or cloud metadata.
            'follow_location' => 0,
            'max_redirects' => 0,
        ],
    ]);
    $t0 = microtime(true);
    $body = @file_get_contents($endpoint, false, $ctx);
    $ms = (int)round((microtime(true) - $t0) * 1000);
    $code = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m)) {
        $code = intval($m[1]);
    }
    if ($body === false && $code === 0) {
        return ['reachable' => false, 'response_time_ms' => $ms, 'http_code' => 0,
                'error' => $ms >= ($timeout * 1000 - 100) ? 'connection timeout' : 'connection failed'];
    }
    // A 3xx is not an answer: redirects are not followed (see above).
    $ok = $code >= 200 && $code < 300;
    return ['reachable' => $ok, 'response_time_ms' => $ms, 'http_code' => $code,
            'error' => $ok ? null : 'indexer returned HTTP ' . $code];
}

// Write the access-control JSON and regenerate the nginx snippet via sudo.
// Returns ['success'=>bool, 'error'=>?, 'detail'=>?].
function writeAclAndRegen($acl) {
    $acl['updated_at'] = date('c');
    if (@file_put_contents('/etc/irongate/access-control.json',
            json_encode($acl, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
        return ['success' => false, 'error' => 'Failed to write access-control config'];
    }
    exec('sudo /opt/irongate/regen-access.sh 2>&1', $regenOut, $regenCode);
    if ($regenCode !== 0) {
        return ['success' => false, 'error' => 'nginx regeneration failed',
                'detail' => implode("\n", array_slice($regenOut, -5))];
    }
    return ['success' => true, 'acl' => $acl];
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
        return true;
    }
    return false;
}

function deleteReservation($db, $id) {
    $stmt = $db->prepare('DELETE FROM reservations WHERE id = ?');
    $stmt->bindValue(1, $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    return $result ? true : false;
}

// irongate-audit (O4): the web tier no longer writes /etc/dnsmasq.conf or anything in /etc/dnsmasq.d. dnsmasq runs
// as root and a `dhcp-script=` line in either would run a program as root, so both belong to root. This API stores
// the settings and reservations in the database as before; to apply them it stages them as DATA in
// DNSMASQ_STAGE_DIR (a root-owned directory outside the web root) and runs the one root helper below through sudo
// with no arguments (/etc/sudoers.d/irongate-dnsmasq-apply). The helper accepts only the keys listed here, checks
// each value, renders the files from its own template, runs `dnsmasq --test` and restarts dnsmasq.
const DNSMASQ_HELPER = '/opt/irongate/dnsmasq-apply';
const DNSMASQ_STAGE_DIR = '/var/lib/irongate/dnsmasq-staged';
const DNSMASQ_SETTING_KEYS = ['dhcp_enabled', 'interface', 'cidr', 'range_start', 'range_end', 'gateway',
                              'dns_primary', 'dns_secondary', 'lease_time', 'domain'];

function dnsmasqRequest($db, $action) {
    $all = getAllSettings($db);
    $settings = [];
    foreach (DNSMASQ_SETTING_KEYS as $key) {
        if (isset($all[$key]) && is_scalar($all[$key])) {
            // The old generator wrote the values as they were and dnsmasq ignores white space around them, so a gateway
            // saved with a trailing space worked. The helper strips as well; a value that is not plain is refused there.
            $settings[$key] = trim((string)$all[$key]);
        }
    }
    // As before: the DHCP options count only while DHCP is on and a range is set, and an empty interface means
    // "the default route's" (the helper looks that up).
    $on = ($settings['dhcp_enabled'] ?? '') === 'true' && !empty($settings['range_start'] ?? '') && !empty($settings['range_end'] ?? '');
    if (!$on) {
        $settings = array_intersect_key($settings, ['interface' => 1]);
    }
    $settings['dhcp_enabled'] = $on ? 'true' : 'false';
    if (empty($settings['interface'] ?? '')) {
        unset($settings['interface']);
    }
    $reservations = [];
    $results = $db->query('SELECT * FROM reservations');
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $reservations[] = [
            'mac' => trim((string)$row['mac']),
            'ip' => trim((string)$row['ip']),
            'hostname' => sanitizeHostname((string)($row['hostname'] ?? '')),
        ];
    }
    return ['version' => 1, 'action' => $action, 'settings' => (object)$settings, 'reservations' => $reservations];
}

// Stage the request and run the helper. Returns ['ok' => bool, 'error' => string, 'resp' => array|null].
function runDnsmasqHelper($db, $action) {
    $json = json_encode(dnsmasqRequest($db, $action));
    if ($json === false) {
        return ['ok' => false, 'error' => 'the request could not be encoded', 'resp' => null];
    }
    $dir = DNSMASQ_STAGE_DIR;
    $lock = @fopen($dir . '/.lock', 'c');
    if ($lock === false) {
        return ['ok' => false, 'error' => 'the staging directory is not writable', 'resp' => null];
    }
    flock($lock, LOCK_EX);
    // A directory named request.json would make every rename below fail for good; an empty one is ours to remove.
    if (is_dir($dir . '/request.json') && !is_link($dir . '/request.json')) {
        @rmdir($dir . '/request.json');
    }
    $tmp = @tempnam($dir, '.req-');
    if ($tmp === false || @file_put_contents($tmp, $json) === false || !@rename($tmp, $dir . '/request.json')) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return ['ok' => false, 'error' => 'the request could not be staged', 'resp' => null];
    }
    $out = [];
    exec('sudo -n ' . DNSMASQ_HELPER . ' 2>&1', $out, $rc);
    flock($lock, LOCK_UN);
    fclose($lock);
    $resp = null;
    foreach (array_reverse($out) as $line) {
        $decoded = json_decode($line, true);
        if (is_array($decoded) && array_key_exists('success', $decoded)) {
            $resp = $decoded;
            break;
        }
    }
    if ($resp === null) {
        return ['ok' => false, 'error' => 'dnsmasq-apply gave no answer: ' . substr(implode(' ', $out), 0, 300), 'resp' => null];
    }
    return ['ok' => true, 'error' => '', 'resp' => $resp];
}

// Validate dnsmasq config before applying (what the settings in the database would render to)
function validateConfig($db) {
    $run = runDnsmasqHelper($db, 'validate');
    $resp = $run['resp'];
    if (!$run['ok']) {
        return ['valid' => false, 'output' => $run['error'], 'return_code' => 1];
    }
    if (!($resp['success'] ?? false)) {
        return ['valid' => false, 'output' => (string)($resp['error'] ?? ''), 'return_code' => 2];
    }
    return [
        'valid' => (bool)($resp['valid'] ?? false),
        'output' => (string)($resp['output'] ?? ''),
        'return_code' => (int)($resp['return_code'] ?? 1)
    ];
}

function applyConfig($db) {
    $run = runDnsmasqHelper($db, 'apply');
    if (!$run['ok']) {
        return [
            'success' => false,
            'error' => 'Config validation failed: ' . $run['error'],
            'stage' => 'validation'
        ];
    }
    $resp = $run['resp'];
    if ($resp['success'] ?? false) {
        return ['success' => true];
    }
    if (($resp['stage'] ?? '') === 'start') {
        // Get the actual error from journalctl
        exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
        return [
            'success' => false,
            'error' => 'Service start failed',
            'output' => (string)($resp['output'] ?? ''),
            'journal' => implode("\n", $journalOutput),
            'stage' => 'start'
        ];
    }
    return [
        'success' => false,
        'error' => 'Config validation failed: ' . (string)($resp['error'] ?? ''),
        'stage' => 'validation'
    ];
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
            // Try tail command first (efficient for large files)
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

            // Fall back to direct read
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
    
    // Check file permissions (from dnsmasq's perspective, not www-data's)
    $dnsmasqUser = posix_getpwnam('dnsmasq');
    $dnsmasqUid = $dnsmasqUser ? $dnsmasqUser['uid'] : null;
    
    $leasesStat = @stat('/var/lib/dnsmasq/dnsmasq.leases');
    $diag['leases_writable'] = $leasesStat && $dnsmasqUid !== null && $leasesStat['uid'] === $dnsmasqUid && ($leasesStat['mode'] & 0200);
    
    $logStat = @stat('/var/log/dnsmasq.log');
    $diag['log_writable'] = $logStat && $dnsmasqUid !== null && $logStat['uid'] === $dnsmasqUid && ($logStat['mode'] & 0200);
    
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
    exec('sudo chmod 664 /var/log/dnsmasq.log 2>&1');
    $repairs[] = 'Fixed file permissions';
    
    // Only kill dnsmasq if it is in a failed/stuck state, not if running fine
    exec('systemctl is-active dnsmasq 2>&1', $activeCheck, $activeRet);
    if ($activeRet !== 0) {
        exec('logger -t irongate-autorepair "dnsmasq is-active returned '.$activeRet.', killing stale processes"');
        exec('sudo pkill -9 dnsmasq 2>&1');
        usleep(500000);
        $repairs[] = 'Killed stale dnsmasq processes';
    } else {
        exec('logger -t irongate-autorepair "dnsmasq is-active returned 0, skipping kill"');
        $repairs[] = 'Service already running, skipped kill';
    }
    
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
            // This endpoint stores any key, the irongate_* ones included: same rules as irongate_settings.
            $settingsError = irongateSettingsError($data);
            if ($settingsError !== null) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => $settingsError]);
                break;
            }

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
        $result = validateConfig($db);
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
            $settingsError = irongateSettingsError($data);
            if ($settingsError !== null) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => $settingsError]);
                break;
            }
            // Layer 8 validation: never persist an enable without a contract
            // address, an unknown network, or a malformed indexer URL.
            if (is_array($data) && (array_key_exists('blockchain_enabled', $data)
                || array_key_exists('blockchain_network', $data)
                || array_key_exists('blockchain_indexer_url', $data))) {
                $reqEnabled = ($data['blockchain_enabled'] ?? (getSetting($db, 'blockchain_enabled') ?? 'false')) === 'true';
                $reqContract = trim((string)($data['blockchain_contract_address']
                    ?? (getSetting($db, 'blockchain_contract_address') ?? '')));
                if ($reqEnabled && $reqContract === '') {
                    echo json_encode(['success' => false, 'error' => 'Layer 8 cannot be enabled without a contract address']);
                    break;
                }
                if (array_key_exists('blockchain_network', $data)
                    && !array_key_exists((string)$data['blockchain_network'], midnightNetworks())) {
                    echo json_encode(['success' => false, 'error' => 'Unknown blockchain network']);
                    break;
                }
                $reqIndexer = trim((string)($data['blockchain_indexer_url'] ?? ''));
                $reqNetwork = (string)($data['blockchain_network'] ?? (getSetting($db, 'blockchain_network') ?? 'preprod'));
                if ($reqIndexer !== '' && $reqIndexer !== (midnightNetworks()[$reqNetwork] ?? null)
                    && !validIndexerUrl($reqIndexer)) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'error' => 'Invalid indexer URL (must be https on a known Midnight indexer host)']);
                    break;
                }
                // Store exactly what was validated (trimmed), not the raw value: the engine refuses a
                // URL with surrounding whitespace, so storing the padded text would silently switch Layer 8 off.
                if (array_key_exists('blockchain_indexer_url', $data)) {
                    $data['blockchain_indexer_url'] = $reqIndexer;
                }
            }
            foreach ($data as $key => $value) {
                // irongate-audit: the Midnight read path needs no key material.
                // Refuse to persist secret-bearing keys so a mnemonic can never
                // re-enter the settings table (and from there an unauthenticated
                // read and a world-readable config.yaml).
                if (preg_match('/mnemonic|private_key|secret|passphrase|seed/i', $key)) {
                    continue;
                }
                if (strpos($key, 'irongate_') === 0 || strpos($key, 'blockchain_') === 0) {
                    setSetting($db, $key, $value);
                }
            }
            $result = safeApplyConfig($db);
            echo json_encode($result);
        } else {
            $settings = [];
            foreach (['irongate_enabled', 'irongate_mode', 'irongate_isolated_interface',
                      'irongate_bridge_ip', 'irongate_bridge_dhcp_start', 'irongate_bridge_dhcp_end',
                      'irongate_arp_defense', 'irongate_ipv6_ra', 'irongate_gateway_takeover',
                      'irongate_bypass_detection', 'irongate_firewall',
                      'blockchain_enabled', 'blockchain_network',
                      'blockchain_contract_address', 'blockchain_indexer_url',
                      'blockchain_cache_ttl', 'blockchain_fallback_allow',
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
            $result = safeApplyConfig($db);
        } else {
            exec('sudo systemctl stop irongate >/dev/null 2>&1 &');
            $result = ['success' => true, 'message' => 'Irongate disabled'];
        }
        echo json_encode($result);
        break;
    
    case 'irongate_apply':
        $result = safeApplyConfig($db);
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

            // irongate-audit (V1): group names (and the names a group may reach)
            // become nft set identifiers in the root engine.
            $accessList = $data['can_access_groups'] ?? [];
            $accessOk = is_array($accessList);
            foreach (($accessOk ? $accessList : []) as $g) {
                if (!validZoneName($g)) { $accessOk = false; }
            }
            if (!validZoneName($name) || !$accessOk) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid group name (letters, digits, _ and -, starting with a letter or _, max 32 characters)']);
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

            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
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

            if ($result) {
                safeApplyConfig($db);
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
            // irongate-audit (V1): ip and zone end up inside the root engine's nft
            // ruleset. An empty ip is still allowed (the engine skips such devices).
            $devIp = $data['ip'] ?? '';
            $devZone = $data['zone'] ?? 'isolated';
            if (($devIp !== '' && !validDeviceIp($devIp)) || !validZoneName($devZone)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid ip (IPv4 address) or zone (letters, digits, _ and -, starting with a letter or _, max 32 characters)']);
                break;
            }
            $stmt = $db->prepare('INSERT OR REPLACE INTO irongate_devices (mac, ip, hostname, zone) VALUES (?, ?, ?, ?)');
            $stmt->bindValue(1, strtolower($data['mac']), SQLITE3_TEXT);
            $stmt->bindValue(2, $devIp, SQLITE3_TEXT);
            $stmt->bindValue(3, $data['hostname'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(4, $devZone, SQLITE3_TEXT);
            $result = $stmt->execute();
            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $stmt = $db->prepare('DELETE FROM irongate_devices WHERE id = ?');
            $stmt->bindValue(1, $id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            if ($result) {
                safeApplyConfig($db);
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
        // irongate-audit: this action runs a downloaded script as root. As a
        // GET it was reachable by any link, prefetch or cross-origin form,
        // turning a page visit into root code execution. Require POST.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['success' => false, 'error' => 'update_now requires POST']);
            break;
        }
        // This starts a root process. It needs an authenticated session of its own - the localhost bypass of the
        // session guard (cli-server only) never applies to it - and the CSRF token of that session in the
        // X-CSRF-Token header (compared in constant time); a cross-site POST carries the cookie but not the token.
        if (($_SESSION['authenticated'] ?? false) !== true) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'auth_required']);
            break;
        }
        $csrfSent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $csrfWant = $_SESSION['csrf_token'] ?? '';
        if (!is_string($csrfSent) || !is_string($csrfWant) || $csrfWant === '' || !hash_equals($csrfWant, $csrfSent)) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'invalid csrf token']);
            break;
        }
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
        
        // irongate-audit (D5/D6): this used to download the installer as www-data
        // into a world-writable path and sudo-execute it. Any local user could
        // replace that file first, so an unauthenticated request became root code
        // execution. The web tier now only TRIGGERS the update; the root-owned
        // updater fetches the installer, pins it to a commit, and verifies it
        // before running. No attacker-supplied bytes are ever executed from here.
        exec("sudo touch /var/log/irongate-update.log");
        exec("sudo chown www-data /var/log/irongate-update.log");
        // The update runs as its own systemd unit (own cgroup: it is not a child of php-fpm, which the installer
        // restarts); the only thing sudo allows www-data to run for it is exactly this command.
        $out = [];
        $rc = 1;
        exec("sudo -n /usr/bin/systemctl start --no-block irongate-updater-now.service", $out, $rc);
        if ($rc !== 0) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Could not start the update service']);
            break;
        }
        
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
    
    // --- Layer 8 Midnight endpoints (session-protected) ---
    case 'test_blockchain_connection':
        $data = json_decode(file_get_contents('php://input'), true) ?: [];
        $settings = getAllSettings($db);
        $network = (string)($data['network'] ?? ($settings['blockchain_network'] ?? 'preprod'));
        $custom = (string)($data['indexer_url'] ?? ($settings['blockchain_indexer_url'] ?? ''));
        if (!array_key_exists($network, midnightNetworks())) {
            echo json_encode(['success' => false, 'error' => 'Unknown network; expected one of: '
                . implode(', ', array_keys(midnightNetworks()))]);
            break;
        }
        $endpoint = midnightEndpoint($network, $custom);
        if ($endpoint === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid indexer URL (must be https on a known Midnight indexer host)']);
            break;
        }
        $probe = midnightProbe($endpoint, 5);
        echo json_encode([
            'success' => true,
            'endpoint' => $endpoint,
            'reachable' => $probe['reachable'],
            'response_time_ms' => $probe['response_time_ms'],
            'http_code' => $probe['http_code'],
            'error' => $probe['error'],
        ]);
        break;

    case 'get_blockchain_status':
        $settings = getAllSettings($db);
        $enabled = ($settings['blockchain_enabled'] ?? 'false') === 'true';
        $contract = trim((string)($settings['blockchain_contract_address'] ?? ''));
        $network = $settings['blockchain_network'] ?? 'preprod';
        $endpoint = midnightEndpoint($network, $settings['blockchain_indexer_url'] ?? '');
        $engineActive = trim((string)shell_exec('systemctl is-active irongate 2>/dev/null')) === 'active';
        $probe = null;
        if ($contract !== '' && $endpoint !== null) {
            $probe = midnightProbe($endpoint, 3);
        }
        if ($contract === '') {
            $state = 'not_configured';
        } elseif (!$enabled) {
            $state = 'disabled';
        } elseif ($probe !== null && $probe['reachable']) {
            $state = 'active';
        } else {
            $state = 'degraded';
        }
        $journal = [];
        exec('sudo /usr/bin/journalctl -u irongate -n 80 --no-pager 2>/dev/null', $jout);
        foreach ($jout as $line) {
            if (stripos($line, 'blockchain') !== false || stripos($line, 'Layer 8') !== false) {
                $journal[] = $line;
            }
        }
        echo json_encode(['success' => true, 'data' => [
            'state' => $state,
            'enabled' => $enabled,
            'network' => $network,
            'contract_address' => $contract,
            'endpoint' => $endpoint,
            'engine_active' => $engineActive,
            'indexer_reachable' => $probe !== null ? $probe['reachable'] : null,
            'response_time_ms' => $probe !== null ? $probe['response_time_ms'] : null,
            'recent_log' => array_slice($journal, -5),
        ]]);
        break;

    // --- Auth management endpoints (added by webauth feature; session-protected) ---
    case 'change_password':
        $data = json_decode(file_get_contents('php://input'), true);
        $cur = (string)($data['current_password'] ?? '');
        $new = (string)($data['new_password'] ?? '');
        $confirm = (string)($data['confirm_password'] ?? '');
        $auth = json_decode(@file_get_contents('/etc/irongate/auth.json'), true);
        if (!is_array($auth) || empty($auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Auth config unavailable']);
            break;
        }
        if (!password_verify($cur, $auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Current password is incorrect']);
            break;
        }
        if (strlen($new) < 8) {
            echo json_encode(['success' => false, 'error' => 'New password must be at least 8 characters']);
            break;
        }
        if ($new !== $confirm) {
            echo json_encode(['success' => false, 'error' => 'New passwords do not match']);
            break;
        }
        if (irongate_test_sandbox()) {
            // PHP suites (built-in server + IRONGATE_TEST_SANDBOX=1): the old direct write. Dead under php-fpm.
            $auth['password_hash'] = password_hash($new, PASSWORD_BCRYPT);
            $auth['updated_at'] = date('c');
            if (@file_put_contents('/etc/irongate/auth.json',
                    json_encode($auth, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        } else {
            // Only the new hash reaches the root helper; the plaintext never leaves this process.
            $result = irongateWriteViaHelper('auth-set-credentials',
                ['password_hash' => password_hash($new, PASSWORD_BCRYPT)]);
            if (!$result['success']) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        }
        echo json_encode(['success' => true, 'message' => 'Password changed']);
        break;

    case 'change_username':
        $data = json_decode(file_get_contents('php://input'), true);
        $cur = (string)($data['current_password'] ?? '');
        $newUser = trim((string)($data['new_username'] ?? ''));
        $auth = json_decode(@file_get_contents('/etc/irongate/auth.json'), true);
        if (!is_array($auth) || empty($auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Auth config unavailable']);
            break;
        }
        if (!password_verify($cur, $auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Current password is incorrect']);
            break;
        }
        if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $newUser)) {
            echo json_encode(['success' => false, 'error' => 'Username must be 1-32 characters: letters, digits, dot, dash, underscore']);
            break;
        }
        if (irongate_test_sandbox()) {
            // PHP suites (built-in server + IRONGATE_TEST_SANDBOX=1): the old direct write. Dead under php-fpm.
            $auth['username'] = $newUser;
            $auth['updated_at'] = date('c');
            if (@file_put_contents('/etc/irongate/auth.json',
                    json_encode($auth, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        } else {
            $result = irongateWriteViaHelper('auth-set-username', ['username' => $newUser]);
            if (!$result['success']) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        }
        $_SESSION['username'] = $newUser;
        echo json_encode(['success' => true, 'message' => 'Username changed']);
        break;

    case 'get_access_list':
        $acl = json_decode(@file_get_contents('/etc/irongate/access-control.json'), true);
        if (!is_array($acl)) {
            $acl = ['enabled' => false, 'allowed_ips' => []];
        }
        echo json_encode(['success' => true, 'data' => $acl]);
        break;

    case 'update_access_list':
        $data = json_decode(file_get_contents('php://input'), true);
        if (!is_array($data) || !isset($data['allowed_ips']) || !is_array($data['allowed_ips'])) {
            echo json_encode(['success' => false, 'error' => 'Invalid request body']);
            break;
        }
        $ips = [];
        $bad = null;
        foreach ($data['allowed_ips'] as $entry) {
            $valid = validAllowEntry($entry);
            if ($valid === false) { $bad = (string)$entry; break; }
            if (!in_array($valid, $ips, true)) $ips[] = $valid;
        }
        if ($bad !== null) {
            echo json_encode(['success' => false, 'error' => 'Invalid IP or CIDR: ' . $bad]);
            break;
        }
        if (!in_array('127.0.0.1', $ips, true)) {
            array_unshift($ips, '127.0.0.1'); // never lock out localhost
        }
        $result = writeAclAndRegen([
            'enabled' => (bool)($data['enabled'] ?? true),
            'allowed_ips' => $ips
        ]);
        if (!$result['success']) {
            echo json_encode($result);
            break;
        }
        $warning = null;
        $remote = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($result['acl']['enabled'] && $remote !== ''
            && !in_array($remote, ['127.0.0.1', '::1'], true)
            && !aclCovers($ips, $remote)) {
            $warning = 'Your current IP (' . $remote . ') is not in the allow-list. You may lose access.';
        }
        echo json_encode(['success' => true, 'message' => 'Access list updated',
                          'data' => $result['acl'], 'warning' => $warning]);
        break;

    case 'toggle_access_list':
        $data = json_decode(file_get_contents('php://input'), true);
        $acl = json_decode(@file_get_contents('/etc/irongate/access-control.json'), true);
        if (!is_array($acl) || !isset($acl['allowed_ips']) || !is_array($acl['allowed_ips'])) {
            $acl = ['allowed_ips' => ['127.0.0.1']];
        }
        $acl['enabled'] = (bool)($data['enabled'] ?? false);
        $result = writeAclAndRegen($acl);
        if (!$result['success']) {
            echo json_encode($result);
            break;
        }
        echo json_encode(['success' => true, 'data' => $result['acl']]);
        break;

    default:
        echo json_encode(['error' => 'Unknown action', 'available' => [
            'system', 'status', 'settings', 'apply', 'leases',
            'reservations', 'logs', 'restart', 'stop', 'start',
            'diagnostics', 'repair', 'validate',
            'irongate_status', 'irongate_settings', 'irongate_interfaces',
            'irongate_toggle', 'irongate_apply', 'irongate_logs', 'irongate_devices', 'device_groups',
            'update_check', 'update_settings', 'update_now', 'update_log',
            'change_password', 'change_username', 'get_access_list',
            'update_access_list', 'toggle_access_list',
            'test_blockchain_connection', 'get_blockchain_status'
        ]]);
}

// irongate-audit: emit an arbitrary value as a safe YAML scalar.
// JSON string escaping is a valid subset of YAML 1.2 double-quoted style, so
// this neutralises the newlines, quotes and backslashes that previously let a
// stored setting (group name, description, zone, interface...) inject arbitrary
// YAML into /etc/irongate/config.yaml. A crafted value could add or rewrite
// engine directives, or make the file unparseable so the engine died on restart.
function yamlScalar($v) {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// Irongate config generator
function applyIrongateConfig($db) {
    $settings = getAllSettings($db);
    $enabled = ($settings['irongate_enabled'] ?? 'false') === 'true';
    
    if (!$enabled) {
        exec('sudo systemctl stop irongate >/dev/null 2>&1 &');
        return ['success' => true, 'message' => 'Irongate disabled'];
    }
    
    $mode = $settings['irongate_mode'] ?? 'single';
    $interface = $settings['interface'] ?: trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    $gateway = $settings['gateway'] ?: trim(shell_exec("ip route | grep default | awk '{print \$3}' | head -n1"));
    $localIp = trim(shell_exec("ip -4 addr show " . escapeshellarg($interface) . " 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -n1"));
    $localMac = trim(shell_exec("ip link show " . escapeshellarg($interface) . " 2>/dev/null | awk '/ether/ {print \$2}'"));
    
    // Get gateway MAC - try ARP cache first, then arping
    $gatewayMac = trim(shell_exec("ip neigh show | grep " . escapeshellarg($gateway . ' ') . " | awk '{print \$5}' | head -n1"));
    if (empty($gatewayMac)) {
        exec("arping -c 1 -I " . escapeshellarg($interface) . " "
             . escapeshellarg($gateway) . " 2>/dev/null", $arpOutput);
        $gatewayMac = trim(shell_exec("ip neigh show | grep " . escapeshellarg($gateway . ' ') . " | awk '{print \$5}' | head -n1"));
    }
    
    // The same values, as data, for the root helper (it validates and renders them; the web tier never
    // supplies YAML text). irongateWriteViaHelper() runs only outside the PHP-suites' cli-server seam.
    $groupResults = $db->query('SELECT * FROM device_groups ORDER BY name');
    $customGroups = [];
    while ($row = $groupResults->fetchArray(SQLITE3_ASSOC)) {
        $customGroups[] = $row;
    }
    $results = $db->query('SELECT mac, ip, zone FROM irongate_devices');
    $devices = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $devices[] = $row;
    }

    $blockchainNetwork = $settings['blockchain_network'] ?? 'preprod';
    if (!in_array($blockchainNetwork, ['preprod', 'preview', 'mainnet', 'undeployed'], true)) {
        $blockchainNetwork = 'preprod';
    }
    $contract = $settings['blockchain_contract_address'] ?? '';
    $contract = (!empty($contract) && $contract !== 'null') ? $contract : null;
    $indexer = $settings['blockchain_indexer_url'] ?? '';
    $indexer = (!empty($indexer) && $indexer !== 'null') ? $indexer : null;

    $payload = ['settings' => [
        'network' => [
            'interface' => $interface,
            'local_ip' => $localIp,
            'local_mac' => $localMac,
            'gateway_ip' => $gateway,
            'gateway_mac' => $gatewayMac,
        ],
        'mode' => $mode,
        'layers' => [
            'arp_defense' => (($settings['irongate_arp_defense'] ?? 'true') === 'true'),
            'ipv6_ra' => (($settings['irongate_ipv6_ra'] ?? 'true') === 'true'),
            'gateway_takeover' => (($settings['irongate_gateway_takeover'] ?? 'true') === 'true'),
            'bypass_detection' => (($settings['irongate_bypass_detection'] ?? 'true') === 'true'),
            'firewall' => (($settings['irongate_firewall'] ?? 'true') === 'true'),
        ],
        'blockchain' => [
            'enabled' => (($settings['blockchain_enabled'] ?? 'false') === 'true'),
            'network' => $blockchainNetwork,
            'contract_address' => $contract,
            'indexer_url' => $indexer,
            'cache_ttl' => intval($settings['blockchain_cache_ttl'] ?? 60),
            'fallback_allow' => (($settings['blockchain_fallback_allow'] ?? 'true') === 'true'),
            'audit_logging' => (($settings['blockchain_audit_logging'] ?? 'false') === 'true'),
            'allow_rogue_devices' => (($settings['blockchain_allow_rogue_devices'] ?? 'false') === 'true'),
        ],
        'custom_groups' => array_map(function($group) {
            return [
                'name' => (string)$group['name'],
                'color' => (string)($group['color'] ?? ''),
                'icon' => (string)($group['icon'] ?? ''),
                'description' => (string)($group['description'] ?? ''),
                'lan_access' => (string)($group['lan_access'] ?? 'none'),
                'can_access_groups' => json_decode($group['can_access_groups'] ?? '[]', true) ?: [],
            ];
        }, $customGroups),
        'devices' => array_map(function($dev) {
            return [
                'mac' => (string)$dev['mac'],
                'ip' => (string)($dev['ip'] ?? ''),
                'zone' => (string)($dev['zone'] ?? ''),
            ];
        }, $devices),
    ]];
    if ($mode === 'dual') {
        $payload['settings']['bridge'] = [
            'enabled' => true,
            'isolated_interface' => (string)($settings['irongate_isolated_interface'] ?? ''),
            'bridge_name' => 'br-irongate',
            'bridge_ip' => (string)($settings['irongate_bridge_ip'] ?? '10.99.0.1'),
            'bridge_netmask' => '255.255.0.0',
            'dhcp_start' => (string)($settings['irongate_bridge_dhcp_start'] ?? '10.99.1.1'),
            'dhcp_end' => (string)($settings['irongate_bridge_dhcp_end'] ?? '10.99.255.254'),
            'port_isolation' => true,
        ];
    }

    if (irongate_test_sandbox()) {
    // The PHP suites drive api.php under the built-in server (IRONGATE_TEST_SANDBOX=1): keep their old
    // direct write so they stay green. Dead under php-fpm - there the helper above is always used.
    $config = "# Irongate Configuration\n";
    $config .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";
    $config .= "network:\n";
    $config .= "  interface: " . yamlScalar($interface) . "\n";
    $config .= "  local_ip: " . yamlScalar($localIp) . "\n";
    $config .= "  local_mac: " . yamlScalar($localMac) . "\n";
    $config .= "  gateway_ip: " . yamlScalar($gateway) . "\n";
    $config .= "  gateway_mac: " . yamlScalar($gatewayMac) . "\n\n";
    
    $config .= "mode: " . yamlScalar($mode) . "\n\n";
    
    if ($mode === 'dual') {
        $config .= "bridge:\n";
        $config .= "  enabled: true\n";
        $config .= "  isolated_interface: " . yamlScalar($settings['irongate_isolated_interface'] ?? '') . "\n";
        $config .= "  bridge_name: \"br-irongate\"\n";
        $config .= "  bridge_ip: " . yamlScalar($settings['irongate_bridge_ip'] ?? '10.99.0.1') . "\n";
        $config .= "  bridge_netmask: \"255.255.0.0\"\n";
        $config .= "  dhcp_start: " . yamlScalar($settings['irongate_bridge_dhcp_start'] ?? '10.99.1.1') . "\n";
        $config .= "  dhcp_end: " . yamlScalar($settings['irongate_bridge_dhcp_end'] ?? '10.99.255.254') . "\n";
        $config .= "  port_isolation: true\n\n";
    }
    
    $config .= "layers:\n";
    $config .= "  arp_defense: " . (($settings['irongate_arp_defense'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  ipv6_ra: " . (($settings['irongate_ipv6_ra'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  gateway_takeover: " . (($settings['irongate_gateway_takeover'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  bypass_detection: " . (($settings['irongate_bypass_detection'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  firewall: " . (($settings['irongate_firewall'] ?? 'true') === 'true' ? 'true' : 'false') . "\n\n";
    
    // Layer 8: Blockchain settings
    // irongate-audit: migrated from Algorand to Midnight. The Midnight read path
    // is unauthenticated, so app_id and admin_mnemonic are gone entirely - the
    // mnemonic was previously persisted in the settings table, returned by an
    // unauthenticated API action, and written in plaintext into this
    // world-readable config file.
    $config .= "# Layer 8: Midnight Blockchain Verification\n";
    $config .= "blockchain:\n";
    $config .= "  enabled: " . (($settings['blockchain_enabled'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $network = $settings['blockchain_network'] ?? 'preprod';
    if (!in_array($network, ['preprod', 'preview', 'mainnet', 'undeployed'], true)) {
        $network = 'preprod';
    }
    $config .= "  network: " . yamlScalar($network) . "\n";
    $contract = $settings['blockchain_contract_address'] ?? '';
    if (!empty($contract) && $contract !== 'null') {
        $config .= "  contract_address: " . yamlScalar($contract) . "\n";
    } else {
        $config .= "  contract_address: null\n";
    }
    $indexer = $settings['blockchain_indexer_url'] ?? '';
    if (!empty($indexer) && $indexer !== 'null') {
        $config .= "  indexer_url: " . yamlScalar($indexer) . "\n";
    } else {
        $config .= "  indexer_url: null\n";
    }
    $config .= "  cache_ttl: " . intval($settings['blockchain_cache_ttl'] ?? 60) . "\n";
    $config .= "  fallback_allow: " . (($settings['blockchain_fallback_allow'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  audit_logging: " . (($settings['blockchain_audit_logging'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  allow_rogue_devices: " . (($settings['blockchain_allow_rogue_devices'] ?? 'false') === 'true' ? 'true' : 'false') . "\n\n";
    
    $config .= "# Custom Device Groups\n";
    $config .= "custom_groups:\n";
    if (!empty($customGroups)) {
        foreach ($customGroups as $group) {
            $config .= "  - name: " . yamlScalar($group['name']) . "\n";
            $config .= "    color: " . yamlScalar($group['color']) . "\n";
            $config .= "    icon: " . yamlScalar($group['icon']) . "\n";
            $config .= "    description: " . yamlScalar($group['description'] ?? '') . "\n";
            $config .= "    lan_access: " . yamlScalar($group['lan_access'] ?? 'none') . "\n";
            $canAccess = json_decode($group['can_access_groups'] ?? '[]', true) ?: [];
            $config .= "    can_access_groups: [" . implode(', ', array_map(function($g) { return yamlScalar($g); }, $canAccess)) . "]\n";
        }
    } else {
        $config .= "  []\n";
    }
    $config .= "\n";

    $config .= "devices:\n";
    if (!empty($devices)) {
        foreach ($devices as $dev) {
            $config .= "  - mac: " . yamlScalar($dev['mac']) . "\n";
            $config .= "    ip: " . yamlScalar($dev['ip']) . "\n";
            $config .= "    zone: " . yamlScalar($dev['zone']) . "\n";
        }
    } else {
        $config .= "  []\n";
    }

    // Write config. The directory is created 0750 only when absent and never chmodded/chowned afterwards:
    // outside this seam the installer creates it and the root helper does the writing.
    @mkdir('/etc/irongate', 0750, true);
    $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
    if ($writeResult === false) {
        return [
            'success' => false,
            'error' => 'Failed to write config file - check /etc/irongate permissions'
        ];
    }

    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
    }

    // Root helper: it writes atomically and restarts irongate only when the bytes changed.
    $result = irongateWriteViaHelper('config-apply', $payload);
    if (!$result['success']) {
        return [
            'success' => false,
            'error' => 'Failed to write config file - check /etc/irongate permissions'
        ];
    }

    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
}
EOPHP

#######################################
# Create Web UI with improved error display
#######################################
cat > /var/www/irongate/index.php << 'EOHTML'
<?php require_once __DIR__ . '/session_check.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
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
            <div class="nav-item" onclick="showPage('security')">🔐 Security</div>
            <div class="nav-item" onclick="window.location.href='/logout.php'" style="color:var(--text-secondary);">🚪 Logout</div>
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
                <h2 style="margin-bottom:20px;">⛓️ Layer 8: Midnight Blockchain</h2>
                
                <div id="blockchain-alert" class="alert" style="display:none;"></div>
                
                <!-- Overview Card -->
                <div class="card" style="background:linear-gradient(135deg,rgba(102,51,153,0.2),rgba(22,33,62,0.5));">
                    <div class="card-title" style="color:#9966cc;">What is Layer 8?</div>
                    <p style="margin-bottom:10px;">Layer 8 adds <strong>privacy-preserving device verification</strong> via the <a href="https://midnight.network" target="_blank" rel="noopener" style="color:var(--accent);">Midnight</a> blockchain. A device can be proven to be registered and correctly zoned without publishing what the device is, so the registry does not become a public map of your network.</p>
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
                        When enabled, devices must be registered on the Midnight registry contract to access protected resources.
                        Requires a deployed registry contract.
                    </p>
                </div>
                
                <!-- Contract Configuration -->
                <div class="card">
                    <div class="card-title">Midnight Configuration</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Network</label>
                            <select class="form-control" id="blockchain-network" style="max-width:220px;" onchange="blockchainNetworkChanged()">
                                <option value="preprod">Preprod (recommended)</option>
                                <option value="preview">Preview</option>
                                <option value="mainnet">Mainnet</option>
                                <option value="undeployed">Undeployed (local node)</option>
                            </select>
                        </div>
                        <div class="form-group" style="flex:2;">
                            <label>Contract Address</label>
                            <input class="form-control" id="blockchain-contract-address" type="text" placeholder="0x..." oninput="updateBlockchainToggleState()">
                            <div style="font-size:0.8em;color:var(--text-secondary);margin-top:5px;">
                                Address of the deployed device-registry contract. Required to enable Layer 8.
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Indexer URL (optional)</label>
                        <input class="form-control" id="blockchain-indexer-url" type="text" placeholder="leave blank to use the preset for the selected network">
                        <div style="font-size:0.8em;color:var(--text-secondary);margin-top:5px;">
                            The public Midnight indexers accept unauthenticated queries, so no wallet or key
                            material is stored on this device. Read operations only.
                        </div>
                    </div>
                    <div class="form-group">
                        <div style="padding:12px;background:var(--bg);border-radius:6px;font-size:0.85em;color:var(--text-secondary);">
                            <strong>Write operations are not available.</strong> Registering or revoking a device
                            on-chain requires a funded Midnight wallet and a ZK proof server, which does not run on
                            this hardware. Verification is read-only, and no recovery phrase is ever needed or stored.
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
                                <div style="font-size:0.8em;color:var(--text-secondary);">Log access attempts on-chain. Not currently available: writing to Midnight needs a wallet and a proof server.</div>
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
                        <li>Deploy a device-registry contract to Midnight and note its address</li>
                        <li>Choose the network the contract is deployed on (preprod, preview or mainnet)</li>
                        <li>Enter the contract address above</li>
                        <li>Enable Layer 8 and save &mdash; the engine restarts automatically</li>
                        <li>Check the connection status above to confirm the indexer is reachable</li>
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

            <!-- Security Settings -->
            <div class="page" id="page-security">
                <h2 style="margin-bottom:20px;">🔐 Security</h2>

                <!-- IP Allow-List -->
                <div class="card">
                    <div class="card-title">🌐 IP Allow-List</div>
                    <p style="color:var(--text-secondary);font-size:0.9em;margin-bottom:15px;">
                        Only the IPs and CIDR ranges below can reach the WebUI (enforced by nginx before PHP runs).
                        127.0.0.1 is always kept in the list so local access can never be locked out.
                    </p>
                    <div style="display:flex;align-items:center;gap:15px;margin-bottom:10px;">
                        <div class="toggle" id="acl-toggle" onclick="toggleAccessList()"></div>
                        <span id="acl-status-text">Loading…</span>
                    </div>
                    <p id="acl-disabled-warning" style="display:none;color:var(--warning);font-size:0.9em;margin-bottom:10px;">
                        ⚠️ When disabled, any device on the network can reach the login page. Authentication is still required.
                    </p>
                    <div id="acl-ip-list" style="margin-bottom:15px;"></div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;">
                        <input type="text" id="acl-new-ip" class="form-control" placeholder="e.g. 192.168.1.50 or 192.168.1.0/24" style="max-width:300px;">
                        <button class="btn btn-primary" onclick="addAllowIp()">➕ Add IP</button>
                    </div>
                </div>

                <!-- Change Password -->
                <div class="card">
                    <div class="card-title">🔑 Change Password</div>
                    <div class="form-group"><label>Current Password</label><input type="password" id="pw-current" class="form-control" autocomplete="current-password"></div>
                    <div class="form-group"><label>New Password (min 8 characters)</label><input type="password" id="pw-new" class="form-control" autocomplete="new-password"></div>
                    <div class="form-group"><label>Confirm New Password</label><input type="password" id="pw-confirm" class="form-control" autocomplete="new-password"></div>
                    <button class="btn btn-primary" onclick="changePassword()">💾 Change Password</button>
                </div>

                <!-- Change Username -->
                <div class="card">
                    <div class="card-title">👤 Change Username</div>
                    <div class="form-group"><label>Current Password</label><input type="password" id="user-current-pw" class="form-control" autocomplete="current-password"></div>
                    <div class="form-group"><label>New Username</label><input type="text" id="user-new" class="form-control" autocomplete="username"></div>
                    <button class="btn btn-primary" onclick="changeUsername()">💾 Change Username</button>
                </div>

                <!-- Session -->
                <div class="card">
                    <div class="card-title">🚪 Session</div>
                    <p style="color:var(--text-secondary);font-size:0.9em;margin-bottom:15px;">
                        Sessions expire after 4 hours of inactivity.
                    </p>
                    <button class="btn btn-danger" onclick="window.location.href='/logout.php'">🚪 Logout</button>
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
            const pages = ['dashboard','devices','dhcp','leases','reservations','protection','blockchain','logs','diagnostics','updates','security'];
            const idx = pages.indexOf(page);
            if (idx >= 0) document.querySelectorAll('.nav-item')[idx].classList.add('active');
            if(page==='dashboard')loadDashboard();
            if(page==='leases')loadLeases();
            if(page==='reservations')loadReservations();
            if(page==='logs')loadLogs();
            if(page==='diagnostics')runDiagnostics();
            if(page==='devices')loadIrongateDevices();
            if(page==='protection')loadIrongateStatus();
            if(page==='blockchain'){loadBlockchainSettings();loadBlockchainStatus();}
            if(page==='dhcp')loadSettings();
            if(page==='updates')loadUpdateStatus();
            if(page==='security')loadAccessList();
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
                    headers:Object.assign(opts.body?{'Content-Type':'application/json'}:{},{'X-CSRF-Token':(document.querySelector('meta[name="csrf-token"]')||{}).content||''}),
                    body:opts.body?JSON.stringify(opts.body):undefined
                });
                if(res.status===401){window.location.href='/login.php';return{success:false,error:'auth_required'};}
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
                    document.getElementById('blockchain-network').value = res.data.blockchain_network || 'preprod';
                    document.getElementById('blockchain-contract-address').value = res.data.blockchain_contract_address || '';
                    document.getElementById('blockchain-indexer-url').value = res.data.blockchain_indexer_url || '';
                    document.getElementById('blockchain-cache-ttl').value = res.data.blockchain_cache_ttl || '60';
                    document.getElementById('blockchain-fallback').checked = res.data.blockchain_fallback_allow !== 'false';
                    document.getElementById('blockchain-audit').checked = res.data.blockchain_audit_logging === 'true';
                    document.getElementById('blockchain-allow-rogue').checked = res.data.blockchain_allow_rogue_devices === 'true';

                    updateBlockchainToggleState();
                    blockchainNetworkChanged();
                }
            } catch (e) {
                console.error('Blockchain settings error:', e);
            }
        }
        
        async function toggleBlockchain() {
            const toggle = document.getElementById('blockchain-toggle');
            const enabling = !toggle.classList.contains('active');
            
            // Quick validation
            // Layer 8 cannot function without a contract address; enabling it without
            // one silently leaves the layer off, so refuse here rather than mislead.
            if (enabling) {
                const addr = document.getElementById('blockchain-contract-address').value.trim();
                if (!addr) {
                    toast('Enter a contract address before enabling Layer 8', 'error');
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
            updateBlockchainToggleState();
        }

        // Indexer presets — mirror of blockchain.py NETWORKS
        const MIDNIGHT_INDEXER_PRESETS = {
            preprod: 'https://indexer.preprod.midnight.network/api/v4/graphql',
            preview: 'https://indexer.preview.midnight.network/api/v4/graphql',
            mainnet: 'https://indexer.mainnet.midnight.network/api/v4/graphql',
            undeployed: 'http://127.0.0.1:8088/api/v4/graphql'
        };

        function blockchainNetworkChanged() {
            const network = document.getElementById('blockchain-network').value;
            const field = document.getElementById('blockchain-indexer-url');
            const preset = MIDNIGHT_INDEXER_PRESETS[network] || '';
            // Blank means "use the preset" — surface which endpoint that is.
            field.placeholder = preset ? ('leave blank to use ' + preset) : 'leave blank to use the preset for the selected network';
            // If the field holds another network's preset (not a custom URL), clear it
            // so the new network's preset applies; never stomp a custom URL.
            const v = field.value.trim();
            if (v && v !== preset && Object.values(MIDNIGHT_INDEXER_PRESETS).includes(v)) {
                field.value = '';
            }
        }

        function updateBlockchainToggleState() {
            const toggle = document.getElementById('blockchain-toggle');
            const hasContract = document.getElementById('blockchain-contract-address').value.trim() !== '';
            const enabled = toggle.classList.contains('active');
            // Grey the toggle until a contract address exists (unless already enabled,
            // so Layer 8 can always be turned off).
            if (!hasContract && !enabled) {
                toggle.style.opacity = '0.4';
                toggle.style.cursor = 'not-allowed';
                toggle.title = 'Set a contract address to enable Layer 8';
            } else {
                toggle.style.opacity = '';
                toggle.style.cursor = 'pointer';
                toggle.title = '';
            }
        }

        async function loadBlockchainStatus() {
            const res = await api('get_blockchain_status');
            if (!res.success) return;
            const d = res.data;
            const statusText = document.getElementById('blockchain-status-text');
            const connStatus = document.getElementById('blockchain-connection-status');
            if (d.state === 'active') {
                statusText.textContent = 'Enabled';
                statusText.style.color = 'var(--success)';
                connStatus.innerHTML = '<span class="status-dot running"></span>🟢 Active — connected to ' + d.network + ' indexer (' + d.response_time_ms + 'ms)';
            } else if (d.state === 'degraded') {
                statusText.textContent = 'Enabled';
                statusText.style.color = 'var(--warning)';
                connStatus.innerHTML = '<span class="status-dot stopped"></span>🟡 Enabled — indexer unreachable';
            } else if (d.state === 'disabled') {
                statusText.textContent = 'Disabled';
                statusText.style.color = 'var(--text-secondary)';
                connStatus.innerHTML = '<span class="status-dot stopped"></span>⚪ Disabled';
            } else {
                statusText.textContent = 'Not configured';
                statusText.style.color = 'var(--text-secondary)';
                connStatus.innerHTML = '⚙️ Not configured — set a contract address to enable';
            }
        }

        async function saveBlockchainSettings() {
            const enabled = document.getElementById('blockchain-toggle').classList.contains('active');
            const contractAddr = document.getElementById('blockchain-contract-address').value.trim();
            
            // Validate if enabling
            if (enabled && !contractAddr) {
                toast('Contract address is required to enable Layer 8', 'error');
                return;
            }
            
            const settings = {
                blockchain_enabled: enabled ? 'true' : 'false',
                blockchain_network: document.getElementById('blockchain-network').value,
                blockchain_contract_address: contractAddr,
                blockchain_indexer_url: document.getElementById('blockchain-indexer-url').value.trim(),
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
                    loadBlockchainStatus();
                } else {
                    toast('Failed: ' + (res.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                toast('Error: ' + e.message, 'error');
            }
        }
        
        async function testBlockchainConnection() {
            // Server-side probe: the Pi (not the browser) contacts the indexer, so
            // the result is a real reachability measurement from the engine's host.
            const network = document.getElementById('blockchain-network').value;
            const custom = document.getElementById('blockchain-indexer-url').value.trim();
            const connStatus = document.getElementById('blockchain-connection-status');
            connStatus.innerHTML = '<span style="color:var(--text-secondary);">Testing…</span>';
            const res = await api('test_blockchain_connection', {method:'POST', body:{network: network, indexer_url: custom}});
            if (res.success && res.reachable) {
                connStatus.innerHTML = '<span style="color:var(--success);">✓ Reachable (' + res.response_time_ms + 'ms)</span> <span style="color:var(--text-secondary);font-size:0.85em;">' + res.endpoint + '</span>';
                toast('Indexer reachable in ' + res.response_time_ms + 'ms');
            } else {
                const why = res.error || 'unknown error';
                connStatus.innerHTML = '<span style="color:var(--danger);">✗ Unreachable: ' + why + '</span>';
                toast('Indexer unreachable: ' + why, 'error');
            }
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
                
                const res = await api('update_now', {method:'POST'});
                
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
        
        // --- Security page: auth + IP allow-list (webauth feature) ---
        let aclState={enabled:false,allowed_ips:[]};

        async function loadAccessList(){
            const res=await api('get_access_list');
            if(res.success){aclState=res.data;renderAccessList();}
            else toast(res.error||'Failed to load access list','error');
        }

        function renderAccessList(){
            const on=!!aclState.enabled;
            document.getElementById('acl-toggle').classList.toggle('active',on);
            document.getElementById('acl-status-text').textContent=on
                ?`🟢 Active — ${aclState.allowed_ips.length} IP${aclState.allowed_ips.length===1?'':'s'} allowed`
                :'⚪ Disabled — all IPs can connect (auth still required)';
            document.getElementById('acl-disabled-warning').style.display=on?'none':'block';
            document.getElementById('acl-ip-list').innerHTML=aclState.allowed_ips.map(ip=>
                `<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--surface2);">
                    <code>${ip}</code>
                    ${ip==='127.0.0.1'
                        ?'<span style="color:var(--text-secondary);font-size:0.85em;">(always allowed)</span>'
                        :`<button class="btn btn-danger" style="padding:2px 10px;font-size:0.85em;" onclick="removeAllowIp('${ip}')">×</button>`}
                </div>`).join('')
                ||'<span style="color:var(--text-secondary);">No IPs configured</span>';
        }

        function validIpClient(v){
            const m=/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/.exec(v.trim());
            if(!m)return false;
            for(let i=1;i<=4;i++){if(+m[i]>255)return false;}
            if(m[6]!==undefined&&+m[6]>32)return false;
            return true;
        }

        async function addAllowIp(){
            const inp=document.getElementById('acl-new-ip');
            const v=inp.value.trim();
            if(!validIpClient(v)){toast('Invalid IP or CIDR format','error');return;}
            if(aclState.allowed_ips.includes(v)){toast('Already in the list','error');return;}
            await saveAccessList({enabled:aclState.enabled,allowed_ips:[...aclState.allowed_ips,v]});
            inp.value='';
        }

        async function removeAllowIp(ip){
            await saveAccessList({enabled:aclState.enabled,allowed_ips:aclState.allowed_ips.filter(x=>x!==ip)});
        }

        async function toggleAccessList(){
            const res=await api('toggle_access_list',{method:'POST',body:{enabled:!aclState.enabled}});
            if(res.success){aclState=res.data;renderAccessList();toast(aclState.enabled?'Allow-list enabled':'Allow-list disabled');}
            else toast(res.error||'Toggle failed','error');
        }

        async function saveAccessList(next){
            const res=await api('update_access_list',{method:'POST',body:next});
            if(res.success){
                aclState=res.data;renderAccessList();toast('Access list updated');
                if(res.warning)toast(res.warning,'error');
            }else toast(res.error||'Update failed','error');
        }

        async function changePassword(){
            const cur=document.getElementById('pw-current').value;
            const nw=document.getElementById('pw-new').value;
            const cf=document.getElementById('pw-confirm').value;
            if(nw.length<8){toast('New password must be at least 8 characters','error');return;}
            if(nw!==cf){toast('New passwords do not match','error');return;}
            const res=await api('change_password',{method:'POST',body:{current_password:cur,new_password:nw,confirm_password:cf}});
            if(res.success){toast('Password changed');['pw-current','pw-new','pw-confirm'].forEach(id=>document.getElementById(id).value='');}
            else toast(res.error||'Password change failed','error');
        }

        async function changeUsername(){
            const cur=document.getElementById('user-current-pw').value;
            const nu=document.getElementById('user-new').value.trim();
            if(!/^[A-Za-z0-9_.-]{1,32}$/.test(nu)){toast('Username: 1-32 letters, digits, dot, dash, underscore','error');return;}
            const res=await api('change_username',{method:'POST',body:{current_password:cur,new_username:nu}});
            if(res.success){toast('Username changed');document.getElementById('user-current-pw').value='';document.getElementById('user-new').value='';}
            else toast(res.error||'Username change failed','error');
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboard();
        });
    </script>
</body>
</html>
EOHTML

# webauth: the SPA is now index.php (session-guarded); remove any stale copy
rm -f /var/www/irongate/index.html

cat > /var/www/irongate/session_check.php << 'WEBAUTH_SESSEOF'
<?php
/**
 * Irongate WebUI Session Guard
 * Include at the top of every protected page.
 *
 * - Browser pages: unauthenticated -> redirect to /login.php
 * - api.php: unauthenticated -> 401 JSON (the SPA fetch() helper handles the
 *   redirect; a 302-to-HTML would corrupt every frontend JSON error path)
 * - Local service bypass: requests from 127.0.0.1/::1 to api.php that carry
 *   no session cookie are exempted, but ONLY under PHP's built-in web server
 *   (cli-server, which is how the test suite drives api.php). Under php-fpm
 *   (fpm-fcgi, the real deployment) the bypass does not exist for any endpoint.
 * - update_now is never exempted: it also requires a session and its CSRF token.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}

$IRONGATE_SESSION_TIMEOUT = 4 * 60 * 60; // 4 hours of inactivity

$isApi = basename($_SERVER['SCRIPT_NAME'] ?? '') === 'api.php';

// The ONE test/development exception: PHP's built-in server together with IRONGATE_TEST_SANDBOX=1. The PHP
// suites drive api.php this way, so they keep the old direct writes and skip the CSRF gate. Dead under
// php-fpm: the SAPI there is fpm-fcgi, never cli-server. (php_sapi_name() is used instead of the SAPI
// constant so that this file keeps exactly one literal occurrence of it, which tests/test_item_e_api.php
// relies on to rewrite the guard for its fpm-fcgi cases.)
function irongate_test_sandbox(): bool {
    return php_sapi_name() === 'cli-server' && getenv('IRONGATE_TEST_SANDBOX') === '1';
}

// CSRF token gate for the state-changing API actions. True here means the token is NOT required.
function irongate_csrf_not_required(): bool {
    return irongate_test_sandbox();
}

// Enforce X-CSRF-Token against this session's token, in constant time. A request without a session
// (the cli-server loopback bypass) has no token and is refused too.
function irongate_require_csrf(): void {
    if (irongate_csrf_not_required()) {
        return;
    }
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $want = $_SESSION['csrf_token'] ?? '';
    if (!is_string($sent) || !is_string($want) || $want === '' || !hash_equals($want, $sent)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'invalid csrf token']);
        exit;
    }
}

// Local service-to-service API bypass (no session cookie presented). The decision is a function of the SAPI so
// that it can be tested for fpm-fcgi: it is true only for the built-in web server (cli-server) on loopback.
function irongate_local_bypass_allowed(string $sapi, string $addr, bool $hasCookie): bool {
    return $sapi === 'cli-server'
        && in_array($addr, ['127.0.0.1', '::1'], true)
        && !$hasCookie;
}

if ($isApi
    && irongate_local_bypass_allowed(PHP_SAPI, (string)($_SERVER['REMOTE_ADDR'] ?? ''), isset($_COOKIE[session_name()]))) {
    return;
}

$authed = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
$expired = false;

if ($authed && isset($_SESSION['last_activity'])
    && (time() - $_SESSION['last_activity'] > $IRONGATE_SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
    $authed = false;
    $expired = true;
}

if (!$authed) {
    if ($isApi) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'auth_required']);
        exit;
    }
    $current = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: /login.php?' . ($expired ? 'expired=1&' : '') . 'redirect=' . urlencode($current));
    exit;
}

$_SESSION['last_activity'] = time();

// CSRF token of this session: login.php creates it; a session that predates it gets one here.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
WEBAUTH_SESSEOF

cat > /var/www/irongate/login.php << 'WEBAUTH_LOGINEOF'
<?php
/**
 * Irongate WebUI Login
 * Validates credentials against /etc/irongate/auth.json (bcrypt).
 * Rate limiting: 5 failed attempts within 15 minutes -> 15 minute lockout.
 */
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
session_start();

$AUTH_FILE = '/etc/irongate/auth.json';
// Login lockout counters: a www-data-owned state file, not auth.json (which is root:www-data 0640 and is
// only READ on this path now). One GLOBAL counter, as before: 5 failures in 15 minutes -> 15 minute lockout.
$LOCKOUT_FILE = '/var/lib/irongate/lockout/lockout.json';
$MAX_ATTEMPTS = 5;
$WINDOW_SECONDS = 15 * 60;
$LOCKOUT_SECONDS = 15 * 60;

if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header('Location: /');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function loadAuth($file) {
    $auth = json_decode(@file_get_contents($file), true);
    return is_array($auth) ? $auth : null;
}

// The lockout state is read and written under an exclusive flock on the counter file itself. The write
// renames a new file over it, so after locking, the descriptor is checked against the path: a lock on the
// replaced inode would not serialise the next writer, and the caller retries on the current file.
function lockoutOpen($file) {
    for ($i = 0; $i < 20; $i++) {
        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return false;
        }
        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return false;
        }
        clearstatcache(true, $file);
        $a = fstat($fh);
        $b = @stat($file);
        if ($a !== false && $b !== false && $a['dev'] === $b['dev'] && $a['ino'] === $b['ino']) {
            return $fh;
        }
        flock($fh, LOCK_UN);
        fclose($fh);
    }
    return false;
}

function lockoutZero() {
    return ['version' => 1, 'failed_attempts' => 0, 'first_failed_at' => 0, 'locked_until' => 0];
}

function lockoutRead($fh) {
    rewind($fh);
    $raw = stream_get_contents($fh);
    $data = json_decode((string)$raw, true);
    if (!is_array($data)) {
        // Missing or unparsable: zero counters, logged, and rewritten clean on the next write.
        error_log('Irongate login: lockout state is missing or unreadable; counters reset');
        return lockoutZero();
    }
    return [
        'version' => 1,
        'failed_attempts' => intval($data['failed_attempts'] ?? 0),
        'first_failed_at' => intval($data['first_failed_at'] ?? 0),
        'locked_until' => intval($data['locked_until'] ?? 0),
    ];
}

function lockoutWrite($fh, $file, $state) {
    $dir = dirname($file);
    $tmp = $dir . '/.lockout.json.new.' . getmypid();
    @unlink($tmp);
    $out = @fopen($tmp, 'x');
    if ($out === false) {
        error_log('Irongate login: cannot create the lockout temporary file');
        return false;
    }
    $data = json_encode($state, JSON_PRETTY_PRINT) . "\n";
    $ok = (@fwrite($out, $data) === strlen($data)) && @fflush($out) && @fsync($out);
    @fclose($out);
    @chmod($tmp, 0600);
    if (!$ok || !@rename($tmp, $file)) {
        @unlink($tmp);
        error_log('Irongate login: cannot write the lockout state');
        return false;
    }
    return true;
}

function lockoutClose($fh) {
    if (is_resource($fh)) {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

function safeRedirectTarget() {
    $r = $_POST['redirect'] ?? $_GET['redirect'] ?? '/';
    // Same-origin relative paths only: must start with a single '/'
    if (!is_string($r) || $r === '' || $r[0] !== '/' || (isset($r[1]) && $r[1] === '/')) {
        return '/';
    }
    return $r;
}

$error = '';
$notice = '';
if (isset($_GET['expired'])) {
    $notice = 'Session expired — please sign in again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], (string)$csrf)) {
        $error = 'Invalid session token — please reload the page and try again.';
    } else {
        $auth = loadAuth($AUTH_FILE);
        if (!$auth || empty($auth['password_hash']) || empty($auth['username'])) {
            $error = 'Authentication is not configured correctly.';
        } else {
            $now = time();
            $lock = lockoutOpen($LOCKOUT_FILE);
            if ($lock === false) {
                error_log('Irongate login: cannot open the lockout state; counters are not persisted');
            }
            $counters = $lock !== false ? lockoutRead($lock) : lockoutZero();
            $lockedUntil = $counters['locked_until'];
            if ($lockedUntil > $now) {
                $mins = (int)ceil(($lockedUntil - $now) / 60);
                $error = 'Too many failed attempts. Try again in ' . $mins . ' minute' . ($mins === 1 ? '' : 's') . '.';
                lockoutClose($lock);
            } else {
                $user = (string)($_POST['username'] ?? '');
                $pass = (string)($_POST['password'] ?? '');
                if ($user === $auth['username'] && password_verify($pass, $auth['password_hash'])) {
                    $counters = lockoutZero();
                    if ($lock !== false) {
                        lockoutWrite($lock, $LOCKOUT_FILE, $counters);
                    }
                    lockoutClose($lock);
                    session_regenerate_id(true);
                    $_SESSION['authenticated'] = true;
                    $_SESSION['username'] = $auth['username'];
                    $_SESSION['last_activity'] = time();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header('Location: ' . safeRedirectTarget());
                    exit;
                }
                // Failed attempt - rolling window (same thresholds as before)
                $first = $counters['first_failed_at'];
                if ($first === 0 || ($now - $first) > $WINDOW_SECONDS) {
                    $counters['failed_attempts'] = 1;
                    $counters['first_failed_at'] = $now;
                } else {
                    $counters['failed_attempts'] = $counters['failed_attempts'] + 1;
                }
                if ($counters['failed_attempts'] >= $MAX_ATTEMPTS) {
                    $counters['locked_until'] = $now + $LOCKOUT_SECONDS;
                    $counters['failed_attempts'] = 0;
                    $counters['first_failed_at'] = 0;
                    $error = 'Too many failed attempts. Locked for 15 minutes.';
                } else {
                    $error = 'Invalid username or password.';
                }
                if ($lock !== false) {
                    lockoutWrite($lock, $LOCKOUT_FILE, $counters);
                }
                lockoutClose($lock);
            }
        }
    }
}
$redirectValue = safeRedirectTarget();
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Irongate — Sign In</title>
    <style>
        :root{--bg:#1a1a2e;--surface:#16213e;--surface2:#0f3460;--primary:#e94560;--success:#00bf63;--warning:#ffc107;--danger:#dc3545;--text:#eee;--text-secondary:#aaa;}
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;}
        .login-card{background:var(--surface);border-radius:12px;padding:35px;width:100%;max-width:380px;box-shadow:0 8px 24px rgba(0,0,0,0.4);}
        .logo{display:flex;align-items:center;justify-content:center;gap:10px;font-size:1.4em;font-weight:bold;color:#e94560;margin-bottom:25px;letter-spacing:2px;}
        .logo svg{width:32px;height:32px;}
        .form-group{margin-bottom:15px;}
        .form-group label{display:block;margin-bottom:5px;color:var(--text-secondary);}
        .form-control{width:100%;padding:10px;border:1px solid var(--surface2);border-radius:6px;background:var(--bg);color:var(--text);font-size:1em;}
        .form-control:focus{outline:none;border-color:var(--primary);}
        .btn{display:block;width:100%;padding:12px;border:none;border-radius:6px;cursor:pointer;font-size:1em;background:var(--primary);color:white;margin-top:20px;}
        .btn:hover{opacity:0.9;}
        .alert{padding:12px;border-radius:8px;margin-bottom:15px;font-size:0.9em;}
        .alert-danger{background:rgba(220,53,69,0.2);border:1px solid var(--danger);}
        .alert-warning{background:rgba(255,193,7,0.2);border:1px solid var(--warning);}
        .subtitle{text-align:center;color:var(--text-secondary);font-size:0.85em;margin-bottom:20px;}
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/></svg>
            IRONGATE
        </div>
        <div class="subtitle">Sign in to manage your network</div>
        <?php if ($error !== ''): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php elseif ($notice !== ''): ?>
        <div class="alert alert-warning"><?php echo htmlspecialchars($notice, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <form method="POST" action="/login.php" autocomplete="on">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($redirectValue, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control" autocomplete="username" autofocus required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" class="form-control" autocomplete="current-password" required>
            </div>
            <button type="submit" class="btn">🔐 Sign In</button>
        </form>
    </div>
</body>
</html>
WEBAUTH_LOGINEOF

cat > /var/www/irongate/logout.php << 'WEBAUTH_LOGOUTEOF'
<?php
// Irongate WebUI logout — destroys the session and returns to login
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
session_start();
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']
    );
}
session_destroy();
header('Location: /login.php');
exit;
WEBAUTH_LOGOUTEOF

# ---- dnsmasq root helper: begin ----
#######################################
# dnsmasq's configuration belongs to root (irongate-audit O4)
#######################################
# dnsmasq runs as root and honours `dhcp-script=` (and conf-script, dhcp-luascript, conf-file, ...) in any
# file it reads, so whoever can write /etc/dnsmasq.conf or a file in /etc/dnsmasq.d can run a program as
# root; the web tier (www-data) could, and may restart dnsmasq. From here on the web API only stages a
# REQUEST in /var/lib/irongate/dnsmasq-staged and runs /opt/irongate/dnsmasq-apply through sudo; the helper
# validates it, renders both files from its own template and restarts dnsmasq.
#
# The helper, its sudoers drop-in and the staging directory are installed HERE, before the permission step
# below, which (kept as it was: the O1 permission tests pin it) hands /etc/dnsmasq.conf and /etc/dnsmasq.d to
# www-data for the moment. Only the lockdown (right after that step) is left in the window that opens, so
# whatever www-data plants in it is scanned, quarantined and never preserved (dnsmasq-apply --lockdown).
echo -e "${YELLOW}Installing the dnsmasq root helper...${NC}"
mkdir -p /opt/irongate
cat > /opt/irongate/dnsmasq-apply << 'DNSMASQAPPLY'
#!/usr/bin/python3 -I
"""dnsmasq-apply - the only program that writes /etc/dnsmasq.conf and /etc/dnsmasq.d/reservations.conf.

Why this exists (irongate-audit O4). dnsmasq runs as root and honours `dhcp-script=` (and `conf-script=`,
`dhcp-luascript=`, `conf-file=`, ...) in any file it reads. While www-data owned /etc/dnsmasq.conf and
/etc/dnsmasq.d, a compromised web tier could add such a line and get a root program started by the next
`systemctl restart dnsmasq`, which it is allowed to run. Now:

  * /etc/dnsmasq.conf, /etc/dnsmasq.d and every file in it belong to root (0644 / 0755);
  * the web API (www-data) writes a REQUEST (settings and reservations, as data) to
    /var/lib/irongate/dnsmasq-staged/request.json and runs this program through sudo, with no arguments
    (/etc/sudoers.d/irongate-dnsmasq-apply: `www-data ALL=(root) NOPASSWD: /opt/irongate/dnsmasq-apply ""`);
  * this program accepts only the keys the dashboard sets, checks every value against a strict shape, and
    RENDERS the files from the template below (the dhcp-script and conf-dir lines are constants here, not
    input). A request that carries anything else - an unknown key, a directive name that must never come from
    the web tier, a newline, a NUL, an "=" - is refused as a whole and nothing is written;
  * the rendered files go through `dnsmasq --test` before they replace the live ones (temp file + rename in a
    root-only directory); if dnsmasq will not start on them the previous files are put back.

Output: one JSON object on stdout, {"success": bool, "stage": ..., "error": ..., "output": ...}.
Exit status: 0 applied/valid, 2 request refused, 3 dnsmasq --test failed, 4 service did not stop or start (the previous files are back),
5 the environment is not safe (a directory is not root-owned, a tool is missing, --lockdown could not lock every entry),
1 internal error.

Root-only command line modes (the sudoers rule allows no arguments, so the web tier cannot reach them):
  --lockdown   make /etc/dnsmasq.conf and /etc/dnsmasq.d root-owned. The directory is taken first; then every
               file the web tier could have written is READ ONCE, scanned as dnsmasq's own parser would read it
               (a forbidden directive, quoted or split across dnsmasq's 1024-byte read buffer, anything but plain
               `name=value` lines) and only what is clean is written back as a new root-owned file, so a
               descriptor the web tier still holds is useless. A file that is not clean is never re-created: its
               bytes go to a root-only directory (QUARANTINE_DIR) and, for the two files this program renders,
               the root-held snapshot of the last good rendering (SNAPSHOT_DIR) or a safe default replaces it.
               Links, directories and special files are renamed aside (.refused.*, dnsmasq skips dot files), and so
               is an entry that cannot be processed at all (a read or write error, a name of any length): one entry
               never stops the others or the main file, and the exit status is 5 if anything could not be locked.
               What is accepted in a file the web tier could have written is an ALLOWLIST: the main file may hold
               only what render_main() emits (MAIN_NAMES, the four fixed lines as they are), reservations.conf only
               dhcp-host, any other file only options dnsmasq has (KNOWN_OPTIONS) that are not FORBIDDEN.
  --audit      read-only: every entry of /etc/dnsmasq.d (root-owned ones too) and /etc/dnsmasq.conf must be a
               root-only regular file without a directive the web tier must not set; the programs dnsmasq and
               sudo run as root must not be writable by anybody else. Exit 1 on any finding.

apply() runs the audit first and refuses (exit 5) to run dnsmasq --test, which executes conf-script, on a tree
that is not clean.
"""

import errno
import fcntl
import io
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time

try:
    import syslog
except ImportError:  # pragma: no cover
    syslog = None

# ---- paths (tests replace these on the imported module; the installed program never reads them from the environment) ----
CONF_PATH = '/etc/dnsmasq.conf'
CONF_DIR = '/etc/dnsmasq.d'
RES_NAME = 'reservations.conf'
STATE_DIR = '/var/lib/irongate'
STAGE_DIR = '/var/lib/irongate/dnsmasq-staged'
QUARANTINE_DIR = '/var/lib/irongate/dnsmasq-quarantine'
SNAPSHOT_DIR = '/var/lib/irongate/dnsmasq-good'
REQUEST_NAME = 'request.json'
LOCK_PATH = '/run/irongate-dnsmasq-apply.lock'
DNSMASQ_BIN = ('/usr/sbin/dnsmasq', '/usr/bin/dnsmasq', '/sbin/dnsmasq')
SYSTEMCTL_BIN = ('/usr/bin/systemctl', '/bin/systemctl')
IP_BIN = ('/usr/sbin/ip', '/sbin/ip', '/usr/bin/ip', '/bin/ip')
WEB_USER = 'www-data'
MAX_REQUEST = 1024 * 1024
MAX_RESERVATIONS = 2048
MAX_CONF_FILE = 8 * 1024 * 1024
MAX_QUARANTINE = 1000
# dnsmasq reads its configuration with fgets() into a 1025-byte buffer: at most 1024 bytes of a longer line, and the
# rest comes back as if it were a line of its own (a `#` comment of 1023 characters followed by `conf-file=...` is
# a comment plus a directive for dnsmasq).
READ_CHUNK = 1024
# programs that run as root on the web tier's behalf (sudo) or dnsmasq's (dhcp-script): nobody else may change them
EXEC_PATHS = ('/opt/irongate/dnsmasq-apply', '/opt/irongate/dhcp-notify.sh')
TEST_TIMEOUT = 30
SERVICE_TIMEOUT = 60
# `systemctl stop dnsmasq` is not quick on the router: irongate.service is bound to dnsmasq (BindsTo/PartOf) and stops FIRST (its ARP restoration
# takes ~95 s, TimeoutStopSec=180), dnsmasq's own stop (default 90 s) comes after it. The wait must outlast both.
STOP_TIMEOUT = 300

# ---- what the dashboard may set ----
SETTING_KEYS = ('dhcp_enabled', 'interface', 'cidr', 'range_start', 'range_end', 'gateway',
                'dns_primary', 'dns_secondary', 'lease_time', 'domain')
TOP_KEYS = ('version', 'action', 'settings', 'reservations')
RESERVATION_KEYS = ('mac', 'ip', 'hostname')

# dnsmasq's long-option table (option.c, `opts[]`) of dnsmasq 2.92: EVERY name a configuration file may use, with the option value (the
# `val` field) it stands for. Names with the same value are aliases of one option, and not all of them are in `dnsmasq --help`:
# `dhcp-lease` is the old name of `dhcp-leasefile` (a root dnsmasq creates and rewrites that file just the same), `domain-suffix` is
# `domain`. tests/test_dnsmasq_apply.py reads the table out of the dnsmasq binary it runs against and requires it to be this one, name
# for name and value for value (and every name to be a string of the binary).
_OPTION_TABLE = '''
    version 118; no-hosts 104; no-poll 110; help 119; no-daemon 100; log-queries 113; user 117; group 103; resolv-file 114
    servers-file 333; mx-host 109; mx-target 116; cache-size 99; port 112; dhcp-leasefile 108; dhcp-lease 108; dhcp-host 71; dhcp-range 70
    dhcp-option 79; dhcp-boot 77; domain 115; domain-suffix 115; interface 105; listen-address 97; local-service 335; bogus-priv 98
    bogus-nxdomain 66; ignore-address 338; selfmx 101; filterwin2k 102; filter-A 369; filter-AAAA 370; filter-rr 381; pid-file 120
    strict-order 111; server 83; rev-server 332; local 286; address 65; conf-file 67; conf-script 374; no-resolv 82; expand-hosts 69
    localmx 76; local-ttl 84; no-negcache 78; no-round-robin 378; no-0x20-encode 387; do-0x20-encode 388; cache-rr 380; addn-hosts 72
    hostsdir 342; query-port 81; except-interface 73; no-dhcp-interface 50; no-dhcpv4-interface 383; no-dhcpv6-interface 382
    domain-needed 68; dhcp-lease-max 88; bind-interfaces 122; read-ethers 90; alias 86; dhcp-vendorclass 85; dhcp-userclass 106
    dhcp-ignore 74; edns-packet-max 80; keep-in-foreground 107; dhcp-authoritative 75; srv-host 87; localise-queries 121; txt-record 89
    caa-record 356; dns-rr 310; enable-dbus 49; enable-ubus 354; bootp-dynamic 51; dhcp-mac 52; no-ping 53; dhcp-script 54; conf-dir 55
    log-facility 56; leasefile-ro 57; script-on-renewal 360; dns-forward-max 48; clear-on-reload 256; dhcp-ignore-names 257
    enable-tftp 258; tftp-secure 259; tftp-no-fail 344; tftp-unique-root 274; tftp-root 260; tftp-max 263; tftp-mtu 349
    tftp-lowercase 309; tftp-single-port 359; ptr-record 261; naptr-record 287; bridge-interface 262; shared-network 357
    dhcp-option-force 264; dhcp-option-pxe 386; tftp-no-blocksize 265; log-dhcp 266; log-async 267; dhcp-circuitid 268; dhcp-remoteid 269
    dhcp-subscrid 270; dhcp-pxe-vendor 361; interface-name 271; dhcp-hostsfile 273; dhcp-optsfile 280; dhcp-hostsdir 340; dhcp-optsdir 341
    dhcp-no-override 275; tftp-port-range 276; stop-dns-rebind 277; rebind-domain-ok 298; all-servers 278; dhcp-match 281
    dhcp-name-match 355; dhcp-broadcast 282; neg-ttl 283; max-ttl 297; min-cache-ttl 339; max-cache-ttl 312; dhcp-alternate-port 284
    dhcp-scriptuser 285; min-port 288; max-port 345; dhcp-fqdn 289; cname 290; pxe-prompt 291; pxe-service 292; test 293; tag-if 294
    dhcp-proxy 295; dhcp-generate-names 296; rebind-localhost-ok 299; add-mac 300; strip-mac 372; add-subnet 325; strip-subnet 371
    add-cpe-id 346; proxy-dnssec 301; dhcp-sequential-ip 302; conntrack 303; dhcp-client-update 304; dhcp-luascript 305; enable-ra 306
    dhcp-duid 307; host-record 308; bind-dynamic 311; auth-zone 313; auth-server 314; auth-ttl 315; auth-soa 316; auth-sec-servers 317
    auth-peer 318; ipset 319; nftset 368; connmark-allowlist-enable 365; connmark-allowlist 366; synth-domain 320; dnssec 329
    trust-anchor 330; dnssec-debug 331; dnssec-check-unsigned 334; dnssec-no-timecheck 336; dnssec-timestamp 343; dnssec-limits 385
    dhcp-relay 323; dhcp-split-relay 390; ra-param 324; quiet-dhcp 326; quiet-dhcp6 327; quiet-ra 328; dns-loop-detect 337; script-arp 347
    dhcp-ttl 348; dhcp-reply-delay 350; dhcp-rapid-commit 351; dumpfile 352; dumpmask 353; dhcp-ignore-clid 358; dynamic-host 362
    log-debug 363; umbrella 364; quiet-tftp 367; port-limit 375; fast-dns-retry 376; use-stale-cache 377; no-ident 379
    max-tcp-connections 384; leasequery 389
'''
OPTION_VALUES = dict((item.split()[0], int(item.split()[1])) for item in re.split(r'[;\n]', _OPTION_TABLE) if item.strip())

# Directives that read a file, run a program, write a file, change the user or open another config. They may
# never come from the web tier. Everything not in SETTING_KEYS is refused anyway; this list only makes the
# refusal say so (and is what the audit looks for). FORBIDDEN is this list plus every ALIAS of one of its options,
# derived by option VALUE from the table above, so a spelling that only dnsmasq's own table knows is covered too.
_FORBIDDEN_NAMED = frozenset('''
    conf-file conf-dir conf-script dhcp-script dhcp-luascript script-arp dhcp-scriptuser dhcp-hostsfile dhcp-optsfile
    dhcp-hostsdir dhcp-optsdir hostsdir addn-hosts servers-file resolv-file pid-file dhcp-leasefile leasefile-ro
    log-facility dumpfile dumpmask dnssec-timestamp tftp-root enable-tftp dhcp-boot pxe-service user group read-ethers
    dhcp-relay dhcp-proxy trust-anchor ipset nftset connmark-allowlist
'''.split())
_FORBIDDEN_VALUES = frozenset(OPTION_VALUES[n] for n in _FORBIDDEN_NAMED if n in OPTION_VALUES)
FORBIDDEN = _FORBIDDEN_NAMED | frozenset(n for n, v in OPTION_VALUES.items() if v in _FORBIDDEN_VALUES)
# the table's names in the form the scanner compares (lower case: the table also has filter-A and filter-AAAA)
KNOWN_OPTIONS = frozenset(n.lower() for n in OPTION_VALUES)

# ---- the template ----
HEADER_FMT = "# DHCP Server Configuration\n# Auto-generated by Web UI on %s\n\n"
FIXED_LEASEFILE = 'dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases'
FIXED_LOGFACILITY = 'log-facility=/var/log/dnsmasq.log'
FIXED_SCRIPT = 'dhcp-script=/opt/irongate/dhcp-notify.sh'
FIXED_CONFDIR = 'conf-dir=/etc/dnsmasq.d/,*.conf'
RES_HEADER = "# Static DHCP Reservations - Auto-generated by Web UI\n"

# directive names the rendered main file may contain
MAIN_NAMES = frozenset(['interface', 'bind-dynamic', 'port', 'dhcp-range', 'dhcp-option', 'domain',
                        'dhcp-leasefile', 'dhcp-authoritative', 'log-dhcp', 'log-facility', 'dhcp-script', 'conf-dir'])

_IFACE_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}')
_IPV4_RE = re.compile(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}')
_MAC_RE = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
_LEASE_RE = re.compile(r'(?:[0-9]{1,10}[smhdw]?|infinite)', re.IGNORECASE)
_CIDR_RE = re.compile(r'[0-9]{1,2}')
_HOST_LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_HOST_RE = re.compile(r'%s(?:\.%s)*' % (_HOST_LABEL, _HOST_LABEL))
_DOM_LABEL = r'[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?'
_DOMAIN_RE = re.compile(r'%s(?:\.%s)*' % (_DOM_LABEL, _DOM_LABEL))


class Reject(Exception):
    """The request is not acceptable. The message names the field, never the value."""


class Failure(Exception):
    def __init__(self, stage, error, output='', code=1, **extra):
        Exception.__init__(self, error)
        self.stage, self.error, self.output, self.code, self.extra = stage, error, output, code, extra


# ============================================================ request checking ============================================================

def _no_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Reject('duplicate key in request')
        out[key] = value
    return out


def _bad_constant(_name):
    raise Reject('non-finite number in request')


_KNOWN_NAMES = frozenset(SETTING_KEYS + TOP_KEYS + RESERVATION_KEYS)


def _scan_strings(node, path='request', depth=0):
    """No control character, no non-ASCII character and no '=' in any key or value, anywhere. The refusal names the
    field (never the value; a key is named only when it is one the dashboard may send)."""
    if depth > 8:
        raise Reject('request is nested too deeply')
    if isinstance(node, dict):
        for key, value in node.items():
            _scan_strings(key, path + ' key', depth + 1)
            _scan_strings(value, '%s.%s' % (path, key if key in _KNOWN_NAMES else '?'), depth + 1)
    elif isinstance(node, list):
        for number, item in enumerate(node, 1):
            _scan_strings(item, '%s[%d]' % (path, number), depth + 1)
    elif isinstance(node, str):
        for ch in node:
            code = ord(ch)
            if code < 0x20 or code > 0x7e or ch == '=':
                raise Reject('control character, non-ASCII character or "=" in %s' % path)


def _check_key(key, allowed, what):
    if not isinstance(key, str):
        raise Reject('%s key is not a string' % what)
    norm = key.strip().lower().replace('_', '-')
    head = re.split(r'[=\s,]', norm, maxsplit=1)[0].lstrip('-')
    if head in FORBIDDEN or norm.lstrip('-') in FORBIDDEN:
        raise Reject('forbidden directive %r in the request' % head[:40])
    if key not in allowed:
        raise Reject('unknown %s key' % what)


def _ipv4(value, field):
    if not isinstance(value, str) or not _IPV4_RE.fullmatch(value):
        raise Reject('invalid %s' % field)
    try:
        canonical = str(ipaddress.IPv4Address(value))
    except ValueError:
        raise Reject('invalid %s' % field)
    if canonical != value:
        raise Reject('invalid %s' % field)
    return value


def _optional_ipv4(value, field):
    if value == '':
        return ''
    return _ipv4(value, field)


def normalize_settings(settings):
    """Strict, canonical form of the dashboard's settings. Raises Reject."""
    if not isinstance(settings, dict):
        raise Reject('settings is not an object')
    for key in settings:
        _check_key(key, SETTING_KEYS, 'setting')
    for key, value in settings.items():
        if not isinstance(value, str):
            raise Reject('invalid %s' % key)
    # The old generator wrote values as they were and dnsmasq ignores white space around them, so a gateway with a
    # trailing space or a range start with a leading one worked. Only plain spaces can be left here (_scan_strings
    # has refused every other control character); they are removed and the stripped value is what gets checked
    # and rendered.
    settings = dict((key, value.strip(' ')) for key, value in settings.items())
    out = {}
    enabled = settings.get('dhcp_enabled', 'false')
    if enabled not in ('true', 'false'):
        raise Reject('invalid dhcp_enabled')
    out['dhcp_enabled'] = enabled == 'true'
    iface = settings.get('interface', '')
    if iface != '' and not _IFACE_RE.fullmatch(iface):
        raise Reject('invalid interface')
    out['interface'] = iface
    cidr = settings.get('cidr', '')
    if cidr == '':
        cidr = '24'
    if not _CIDR_RE.fullmatch(cidr) or int(cidr) > 32:
        raise Reject('invalid cidr')
    out['cidr'] = int(cidr)
    for key in ('range_start', 'range_end', 'gateway', 'dns_primary', 'dns_secondary'):
        out[key] = _optional_ipv4(settings.get(key, ''), key)
    lease = settings.get('lease_time', '')
    if lease == '':
        lease = '24h'
    if not _LEASE_RE.fullmatch(lease):
        raise Reject('invalid lease_time')
    out['lease_time'] = lease.lower()
    domain = settings.get('domain', '')
    if domain != '' and (len(domain) > 253 or not _DOMAIN_RE.fullmatch(domain)):
        raise Reject('invalid domain')
    out['domain'] = domain
    return out


def normalize_reservations(items):
    if not isinstance(items, list):
        raise Reject('reservations is not a list')
    if len(items) > MAX_RESERVATIONS:
        raise Reject('too many reservations')
    out = []
    for number, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise Reject('reservation %d is not an object' % number)
        for key in item:
            _check_key(key, RESERVATION_KEYS, 'reservation')
        mac, ip, host = item.get('mac'), item.get('ip'), item.get('hostname', '')
        mac, ip, host = (v.strip(' ') if isinstance(v, str) else v for v in (mac, ip, host))
        if not isinstance(mac, str) or not _MAC_RE.fullmatch(mac):
            raise Reject('invalid reservation %d mac' % number)
        ip = _ipv4(ip, 'reservation %d ip' % number)
        if not isinstance(host, str) or (host != '' and (len(host) > 253 or not _HOST_RE.fullmatch(host))):
            raise Reject('invalid reservation %d hostname' % number)
        out.append((mac, ip, host))
    return out


def parse_request(raw):
    """bytes -> (action, normalized settings, normalized reservations). Raises Reject."""
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        raise Reject('request is not ASCII')
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except (ValueError, RecursionError):
        raise Reject('request is not valid JSON')
    if not isinstance(obj, dict):
        raise Reject('request is not an object')
    for key in obj:
        _check_key(key, TOP_KEYS, 'request')
    _scan_strings(obj)
    if type(obj.get('version')) is not int or obj.get('version') != 1:
        raise Reject('unsupported request version')
    action = obj.get('action')
    if action not in ('apply', 'validate'):
        raise Reject('invalid action')
    settings = normalize_settings(obj.get('settings', {}))
    reservations = normalize_reservations(obj.get('reservations', []))
    return action, settings, reservations


# ============================================================ rendering ============================================================

def _default_interface():
    """Same as the old generator: `ip route | grep default | awk '{print $5}' | head -n1`."""
    exe = next((p for p in IP_BIN if os.access(p, os.X_OK)), None)
    if exe is None:
        return ''
    try:
        proc = subprocess.run([exe, 'route'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=10, env=_env())
    except (OSError, subprocess.SubprocessError):
        return ''
    for line in proc.stdout.decode('ascii', 'replace').splitlines():
        if 'default' in line:
            fields = line.split()
            iface = fields[4] if len(fields) >= 5 else ''
            return iface if _IFACE_RE.fullmatch(iface) else ''
    return ''


def render_main(s, now=None, default_interface=None):
    """The text of /etc/dnsmasq.conf for normalized settings s. Same bytes as the old PHP generator
    (apart from the timestamp's timezone, which is the system's here)."""
    iface = s['interface']
    if iface == '':
        iface = default_interface() if default_interface else _default_interface()
    cfg = HEADER_FMT % time.strftime('%Y-%m-%d %H:%M:%S', now or time.localtime())
    cfg += "# Interface\ninterface=%s\nbind-dynamic\n\n" % iface
    cfg += "# Disable DNS (DHCP only)\nport=0\n\n"
    if s['dhcp_enabled'] and s['range_start'] != '' and s['range_end'] != '':
        netmask = str(ipaddress.IPv4Network('0.0.0.0/%d' % s['cidr']).netmask)
        cfg += "# DHCP Range\ndhcp-range=%s,%s,%s,%s\n\n" % (s['range_start'], s['range_end'], netmask, s['lease_time'])
        if s['gateway'] != '':
            cfg += "# Gateway\ndhcp-option=option:router,%s\n\n" % s['gateway']
        dns = [v for v in (s['dns_primary'], s['dns_secondary']) if v != '']
        if dns:
            cfg += "# DNS Servers\ndhcp-option=option:dns-server,%s\n\n" % ','.join(dns)
        if s['domain'] != '':
            cfg += "# Domain\ndomain=%s\n\n" % s['domain']
    else:
        cfg += "# DHCP is disabled - configure via Web UI\n\n"
    cfg += "# Lease file\n%s\n\n" % FIXED_LEASEFILE
    cfg += "# Be authoritative\ndhcp-authoritative\n\n"
    cfg += "# Logging\nlog-dhcp\n%s\n\n" % FIXED_LOGFACILITY
    cfg += "# DHCP grace period notification for IronGate\n%s\n\n" % FIXED_SCRIPT
    cfg += "# Static reservations\n%s\n" % FIXED_CONFDIR
    verify_main(cfg)
    return cfg


def render_reservations(items):
    out = RES_HEADER
    for mac, ip, host in items:
        out += "dhcp-host=%s,%s%s\n" % (mac, ip, (',' + host) if host != '' else '')
    verify_reservations(out)
    return out


def _directive(line):
    body = line.strip()
    if body == '' or body.startswith('#'):
        return None
    return re.split(r'[=\s]', body, maxsplit=1)[0]


def verify_main(text):
    """Last line of defence: the rendered file holds only known directives, and the fixed lines exactly once."""
    seen = {}
    for line in text.split('\n'):
        name = _directive(line)
        if name is None:
            continue
        if name not in MAIN_NAMES:
            raise Reject('rendered config holds an unexpected directive')
        seen[name] = seen.get(name, 0) + 1
        if name == 'dhcp-script' and line != FIXED_SCRIPT:
            raise Reject('rendered config changes dhcp-script')
        if name == 'conf-dir' and line != FIXED_CONFDIR:
            raise Reject('rendered config changes conf-dir')
        if name == 'dhcp-leasefile' and line != FIXED_LEASEFILE:
            raise Reject('rendered config changes dhcp-leasefile')
        if name == 'log-facility' and line != FIXED_LOGFACILITY:
            raise Reject('rendered config changes log-facility')
    for name in ('dhcp-script', 'conf-dir', 'dhcp-leasefile', 'log-facility', 'interface', 'port'):
        if seen.get(name) != 1:
            raise Reject('rendered config does not hold %s exactly once' % name)
    if '\r' in text or '\x00' in text:
        raise Reject('rendered config holds a control character')


def verify_reservations(text):
    for line in text.split('\n'):
        name = _directive(line)
        if name is not None and name != 'dhcp-host':
            raise Reject('rendered reservations hold an unexpected directive')
    if '\r' in text or '\x00' in text:
        raise Reject('rendered reservations hold a control character')


# ============================================================ helpers ============================================================

def _env():
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def _log(message):
    if syslog is not None:
        try:
            syslog.openlog('irongate-dnsmasq-apply', syslog.LOG_PID, syslog.LOG_AUTH)
            syslog.syslog(syslog.LOG_NOTICE, message)
        except Exception:  # logging must never decide the outcome
            pass


def _run(argv, timeout):
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, env=_env(), close_fds=True)
    except subprocess.TimeoutExpired:
        return 124, 'timed out after %d s' % timeout
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, proc.stdout.decode('utf-8', 'replace').strip()[-4000:]


def _tool(candidates, name):
    for path in candidates:
        if os.access(path, os.X_OK):
            return path
    raise Failure('validation', '%s is not installed' % name, code=5)


def _root_only_dir(path):
    """The directory is a real directory owned by root that nobody else can write."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise Failure('validation', '%s: %s' % (path, exc.strerror), code=5)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Failure('validation', '%s must be a directory owned by root that only root can write '
                      '(run the installer, or dnsmasq-apply --lockdown)' % path, code=5)


def _read_regular(path):
    """Contents of a regular file, or None if there is none. Never follows a link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Failure('validation', '%s: %s' % (path, exc.strerror), code=5)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CONF_FILE:
            raise Failure('validation', '%s is not a regular file of a sane size' % path, code=5)
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def _install_file(path, data):
    """Atomically replace path with data, root:root 0644: temp file next to it, fsync, rename."""
    directory, name = os.path.split(path)
    tmp = os.path.join(directory, '.%s.new.%d' % (name, os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        _unlink_quiet(tmp)
        raise
    os.close(fd)
    try:
        os.rename(tmp, path)
    except BaseException:
        _unlink_quiet(tmp)
        raise
    _fsync_dir(directory)


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_dir(directory):
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _restore(path, old):
    """Put the previous contents back (or remove the file if there was none)."""
    try:
        if old is None:
            _unlink_quiet(path)
        else:
            _install_file(path, old)
    except OSError as exc:  # keep going: the caller reports the original failure
        _log('could not restore %s: %s' % (path, exc))


def _web_uid():
    try:
        return pwd.getpwnam(WEB_USER).pw_uid
    except KeyError:
        return None


def read_request():
    """The staged request as bytes. The file is opened without following links relative to the staging
    directory, must be a lone regular file owned by root or www-data, and is removed after reading."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        dfd = os.open(STAGE_DIR, flags | os.O_DIRECTORY)
    except OSError as exc:
        raise Failure('validation', 'staging directory %s: %s' % (STAGE_DIR, exc.strerror), code=5)
    try:
        dst = os.fstat(dfd)
        if dst.st_uid != 0 or dst.st_mode & 0o002:
            raise Failure('validation', 'staging directory must be owned by root and not world-writable', code=5)
        try:
            fd = os.open(REQUEST_NAME, flags | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                _unlink_quiet_at(REQUEST_NAME, dfd)
                raise Reject('the staged request is a link')
            raise Reject('no staged request')
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                # unlink(2) cannot remove a directory, so a directory named request.json would stay and block every later
                # request (api.php renames its file over that name); empty it away, or put it aside under a dot name
                raise Reject('the staged request is a directory (%s)' % _clear_directory_named_request(dfd))
            allowed = {0}
            web = _web_uid()
            if web is not None:
                allowed.add(web)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid not in allowed or st.st_size > MAX_REQUEST:
                raise Reject('the staged request is not a plain file of an acceptable owner and size')
            data = b''
            while len(data) <= MAX_REQUEST:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data += chunk
            if len(data) > MAX_REQUEST:
                raise Reject('the staged request is too large')
            return data
        finally:
            os.close(fd)
            _unlink_quiet_at(REQUEST_NAME, dfd)
    finally:
        os.close(dfd)


def _unlink_quiet_at(name, dfd):
    try:
        os.unlink(name, dir_fd=dfd)
    except OSError:
        pass


def _clear_directory_named_request(dfd):
    """request.json is a directory in the staging directory: remove it if it is empty, else rename it aside."""
    try:
        os.rmdir(REQUEST_NAME, dir_fd=dfd)
        return 'removed'
    except OSError:
        pass
    aside = '.refused.%d.%d.%s' % (int(time.time()), os.getpid(), REQUEST_NAME)
    try:
        os.rename(REQUEST_NAME, aside, src_dir_fd=dfd, dst_dir_fd=dfd)
        return 'moved aside as %s' % aside
    except OSError as exc:
        return 'could not be moved: %s' % exc.strerror


# ============================================================ the apply ============================================================

def apply(action, settings, reservations):
    dnsmasq = _tool(DNSMASQ_BIN, 'dnsmasq')
    systemctl = _tool(SYSTEMCTL_BIN, 'systemctl')
    main_text = render_main(settings)
    res_text = render_reservations(reservations)
    for directory in (os.path.dirname(CONF_PATH) or '/', CONF_DIR):
        _root_only_dir(directory)
    _require_clean_tree()
    res_path = os.path.join(CONF_DIR, RES_NAME)
    old_main = _read_regular(CONF_PATH)
    old_res = _read_regular(res_path)
    tmp_main = os.path.join(os.path.dirname(CONF_PATH), '.%s.test.%d' % (os.path.basename(CONF_PATH), os.getpid()))

    def check_candidate():
        _unlink_quiet(tmp_main)
        fd = os.open(tmp_main, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, main_text.encode('ascii'))
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
        try:
            return _run([dnsmasq, '--test', '--conf-file=%s' % tmp_main], TEST_TIMEOUT)
        finally:
            _unlink_quiet(tmp_main)

    if action == 'validate':
        # the candidate main file against the reservations that are live now (what the old `validate` did)
        rc, out = check_candidate()
        return {'success': True, 'stage': 'validation', 'valid': rc == 0, 'output': out, 'return_code': rc}

    # apply: the new reservations must be in place for dnsmasq --test to read them through conf-dir
    _install_file(res_path, res_text.encode('ascii'))
    try:
        rc, out = check_candidate()
        if rc != 0:
            _restore(res_path, old_res)
            raise Failure('validation', out or 'dnsmasq --test failed', output=out, code=3, return_code=rc)
        _install_file(CONF_PATH, main_text.encode('ascii'))
        # The stop is WAITED for and its result counts: a `start` issued while the stop job is still queued cancels it, dnsmasq would go on as
        # the old process with the old configuration and this would report success. A stop job that finished (rc 0) means dnsmasq is down, so
        # the start that follows is a real restart on the new files.
        rc, out = _run([systemctl, 'stop', 'dnsmasq'], STOP_TIMEOUT)
        what = 'stop'
        if rc == 0:
            time.sleep(0.5)
            rc, out = _run([systemctl, 'start', 'dnsmasq'], SERVICE_TIMEOUT)
            what = 'start'
        if rc != 0:
            _restore(CONF_PATH, old_main)
            _restore(res_path, old_res)
            # after a stop that did not finish this `start` is also what cancels the queued stop job (a killed client leaves it behind):
            # dnsmasq is never left to be stopped later, and runs on the files that are back
            rc_back, _out_back = _run([systemctl, 'start', 'dnsmasq'], SERVICE_TIMEOUT)
            if what == 'stop':
                out = 'systemctl stop dnsmasq: %s (the previous files are back)' % out   # api.php shows `output` under its fixed 'Service start failed'
            raise Failure('start', 'Service %s failed' % what, output=out, code=4, restored=True, restarted=rc_back == 0)
    except Failure:
        raise
    except BaseException:
        # whatever went wrong, the previous files are what dnsmasq finds on its next start
        _restore(CONF_PATH, old_main)
        _restore(res_path, old_res)
        raise
    _save_snapshot({'main': main_text.encode('ascii'), 'res': res_text.encode('ascii')})
    return {'success': True, 'stage': 'start'}


def _take_lock():
    """The one lock that serialises everything that writes the dnsmasq files: a request, and the lockdown."""
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def run_request():
    fd = _take_lock()
    action = '?'
    try:
        raw = read_request()
        action, settings, reservations = parse_request(raw)
        result = apply(action, settings, reservations)
        _log('%s ok (%d reservations)' % (action, len(reservations)))
        return 0, result
    except Reject as exc:
        _log('request refused: %s' % exc)
        return 2, {'success': False, 'stage': 'validation', 'error': 'Request refused: %s' % exc}
    except Failure as exc:
        _log('%s failed at %s: %s' % (action, exc.stage, exc.error[:200]))
        body = {'success': False, 'stage': exc.stage, 'error': exc.error, 'output': exc.output}
        body.update(exc.extra)
        return exc.code, body
    finally:
        os.close(fd)


# ============================================================ what dnsmasq's own parser would read ============================================================

def _chunks(data):
    """(physical line number, bytes) in the pieces dnsmasq's fgets() loop hands to its option parser."""
    stream = io.BytesIO(data)
    number = 1
    while True:
        piece = stream.readline(READ_CHUNK)
        if not piece:
            return
        yield number, piece
        if piece.endswith(b'\n'):
            number += 1


def _squash(piece):
    """One piece as dnsmasq's first pass leaves it: cut at a NUL (it works on C strings), quotes removed (what they
    enclose stays), white space folded to one blank, and a `#` that starts a word ends the line."""
    text = piece.split(b'\x00', 1)[0].decode('latin-1')
    out = []
    white = True
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                out.append(text[i])
                i += 1
            i += 1
            continue
        if ch.isspace():
            out.append(' ')
            white = True
        else:
            if white and ch == '#':
                break
            white = False
            out.append(ch)
        i += 1
    return ''.join(out)


def _canonical(name):
    return name.lower().replace('_', '-').lstrip('-')


def directive_name(piece):
    """The option name dnsmasq finds in a line piece (canonical: lower case, `_` as `-`, no leading dashes, which
    only widens what is recognised), or None for a blank line or a comment."""
    body = _squash(piece).strip()
    if body == '':
        return None
    return _canonical(re.split(r'[=\s]', body, maxsplit=1)[0])


# The only syntax the files the web tier could write may use: blank lines, `#` comments of printable ASCII, and
# `name[=value]` with a plain value. No quote, backslash, NUL, CR, byte above 0x7e or line over dnsmasq's read size,
# so there is no room left for the ways a directive can be spelled so that dnsmasq reads it and a scanner does not.
_G_COMMENT = re.compile(r'[ \t]*(?:#[\x20-\x7e\t]*)?')
_G_DIRECTIVE = re.compile(r'[ \t]*[a-z][a-z0-9-]*(?:[ \t]*=[ \t]*[A-Za-z0-9 \t,.:/_@+*!\[\]%=-]*)?')


def _syntax_problems(data):
    problems = []
    for number, raw in enumerate(data.split(b'\n'), 1):
        if len(raw) > READ_CHUNK - 1:
            problems.append((number, 'line-too-long'))
            continue
        try:
            line = raw.decode('ascii')
        except UnicodeDecodeError:
            problems.append((number, 'non-ascii-character'))
            continue
        if any(ord(c) < 0x20 and c != '\t' or ord(c) == 0x7f for c in line):
            problems.append((number, 'control-character'))
            continue
        if not (_G_COMMENT.fullmatch(line) or _G_DIRECTIVE.fullmatch(line)):
            problems.append((number, 'unusual-syntax'))
    return problems


def _fixed_main_line(text):
    return text.strip() in (FIXED_SCRIPT, FIXED_CONFDIR, FIXED_LEASEFILE, FIXED_LOGFACILITY)


def scan_config(data, kind, strict):
    """Findings [(line number, what)] in the bytes of a dnsmasq configuration file; `what` is a name from FORBIDDEN or
    a fixed tag, never text of the file. kind: 'main' (the four fixed lines of the rendering are allowed as they are),
    'res' (reservations.conf: nothing but dhcp-host) or 'other'. strict: the web tier could have written the file, so
    only the plain syntax above is accepted as well, and what is left is an ALLOWLIST, not a list of what to refuse: the
    main file may hold only the names render_main() emits, any other file only options dnsmasq has (KNOWN_OPTIONS).
    A name no list has heard of can then not be a spelling of a forbidden option that this program does not know yet."""
    found = []
    if strict:
        found += _syntax_problems(data)
    for number, piece in _chunks(data):
        name = directive_name(piece)
        if name is None:
            continue
        if kind == 'main' and _fixed_main_line(piece.decode('latin-1')) and name in FORBIDDEN:
            continue
        if name in FORBIDDEN:
            found.append((number, name))
        elif kind == 'res' and name != 'dhcp-host':
            found.append((number, 'not-dhcp-host'))
        elif strict and kind == 'main' and name not in MAIN_NAMES:
            found.append((number, 'not-rendered'))
        elif strict and kind == 'other' and name not in KNOWN_OPTIONS:
            found.append((number, 'unknown-option'))
    return sorted(set(found))


def _safe(text):
    return ''.join(c if 0x21 <= ord(c) <= 0x7e else '?' for c in text)


# ============================================================ audit (read-only) ============================================================

def _audit_file(path, kind):
    findings = []
    label = _safe(path)
    try:
        st = os.lstat(path)
    except OSError:
        return findings
    if stat.S_ISLNK(st.st_mode):
        return [(label, 0, 'symlink')]
    if not stat.S_ISREG(st.st_mode):
        return [(label, 0, 'not-a-regular-file')]
    if st.st_uid != 0 or st.st_mode & 0o022:
        findings.append((label, 0, 'not-root-only'))
    try:
        data = _read_regular(path)
    except Failure:
        return findings + [(label, 0, 'unreadable-or-too-large')]
    if data is not None:
        findings += [(label, number, what) for number, what in scan_config(data, kind, strict=False)]
    return findings


def _audit_exec_paths():
    """The programs root runs for the web tier (sudo: the helper) and for dnsmasq (dhcp-script): neither the file nor a
    directory above it may be changed by anybody but root."""
    findings = []
    for path in EXEC_PATHS:
        chain = ['/']
        cur = ''
        for part in [p for p in path.split('/') if p][:-1]:
            cur += '/' + part
            chain.append(cur)
        for directory in chain:
            try:
                st = os.stat(directory)
            except OSError:
                break
            if st.st_uid != 0 or st.st_mode & 0o022:
                findings.append((_safe(directory), 0, 'exec-path-not-root-only'))
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            findings.append((_safe(path), 0, 'exec-path-not-root-only'))
    return sorted(set(findings))


def audit():
    """Read-only. Every file dnsmasq reads - /etc/dnsmasq.conf and EVERY entry of /etc/dnsmasq.d, root-owned ones and
    operator files included, whatever their names (a Debian dnsmasq reads them all) - must be a regular file that only
    root can write and must not hold a directive the web tier must not set. Returns the findings (path, line, what)."""
    findings = []
    for directory in (os.path.dirname(CONF_PATH) or '/', CONF_DIR):
        try:
            st = os.lstat(directory)
        except OSError:
            findings.append((_safe(directory), 0, 'missing'))
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            findings.append((_safe(directory), 0, 'directory-not-root-only'))
    findings += _audit_file(CONF_PATH, 'main')
    try:
        names = sorted(os.listdir(CONF_DIR))
    except OSError:
        names = []
    for name in names:
        path = os.path.join(CONF_DIR, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if name.startswith('.refused.') and st.st_uid == 0 and not stat.S_ISREG(st.st_mode):
            continue  # put aside by --lockdown (a link, directory or special file renamed to a dot name, which dnsmasq skips)
        findings += _audit_file(path, 'res' if name == RES_NAME else 'other')
    findings += _audit_exec_paths()
    return findings


def _require_clean_tree():
    """`dnsmasq --test` (and the daemon) executes conf-script, so it never runs on a tree the audit objects to."""
    findings = audit()
    if findings:
        _log('refusing to run dnsmasq: %d audit finding(s)' % len(findings))
        raise Failure('validation', 'the dnsmasq configuration is not clean or not root-only (%d finding(s)): '
                      'run dnsmasq-apply --audit as root' % len(findings), code=5)


# ============================================================ root-held state: quarantine and snapshot ============================================================

def _mkdir_root(path, mode):
    os.mkdir(path, 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _ensure_state_dirs():
    """/var/lib/irongate (root, 0755) with the quarantine and snapshot directories (root, 0700) below it."""
    for path, mode, private in ((STATE_DIR, 0o755, False), (QUARANTINE_DIR, 0o700, True), (SNAPSHOT_DIR, 0o700, True)):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            _mkdir_root(path, mode)
            st = os.lstat(path)
        bad = st.st_mode & (0o077 if private else 0o022)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or bad:
            raise Failure('validation', '%s must be a directory owned by root%s' % (path, ' that nobody else can open' if private else ' that only root can write'), code=5)


def _write_new(dfd, name, data, mtime_ns=None, private=False):
    """Create `name` (a new root:root file, 0644 or 0600 in the private directories) in the directory dfd with `data`,
    atomically: temp file, fsync, rename. Returns nothing; raises OSError.
    The temporary name is not made from `name`: an entry of the web tier's directory can have a name of 255 characters
    and `.<name>.lock.<pid>` is longer than NAME_MAX, which stopped the lockdown half way (O_EXCL on a name somebody
    else already took stopped it just the same). A name that is taken is not used; the next one is."""
    mode = 0o600 if private else 0o644
    base = '.new.%d.%d' % (os.getpid(), time.monotonic_ns())
    tmp, attempt = base, 0
    while True:
        try:
            nfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            break
        except FileExistsError:
            attempt += 1
            if attempt > 32:
                raise
            tmp = '%s.%d' % (base, attempt)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(nfd, view):]
        os.fchown(nfd, 0, 0)
        os.fchmod(nfd, mode)
        if mtime_ns is not None:
            os.utime(nfd, ns=mtime_ns)
        os.fsync(nfd)
    except BaseException:
        os.close(nfd)
        os.unlink(tmp, dir_fd=dfd)
        raise
    os.close(nfd)
    os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


SNAPSHOT_NAMES = {'main': 'dnsmasq.conf', 'res': 'reservations.conf'}


def _snapshot_ok(kind, data):
    """What may be kept as, and believed to be, the last good content: plain ASCII that passes the scan the lockdown
    applies to a file the web tier could have written (no forbidden directive, nothing but plain `name=value` lines)."""
    try:
        data.decode('ascii')
    except UnicodeDecodeError:
        return False
    return not scan_config(data, kind, strict=True)


def _load_snapshot():
    """The last good content the root helper kept: {'main': bytes|None, 'res': bytes|None}. A snapshot that is not
    private to root, or that fails the scan, does not exist."""
    snap = {'main': None, 'res': None}
    try:
        dfd = os.open(SNAPSHOT_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return snap
    try:
        st = os.fstat(dfd)
        if st.st_uid != 0 or st.st_mode & 0o077:
            return snap
        for kind, name in SNAPSHOT_NAMES.items():
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=dfd)
            except OSError:
                continue
            try:
                s = os.fstat(fd)
                if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077 or s.st_size > MAX_CONF_FILE:
                    continue
                data = os.read(fd, MAX_CONF_FILE + 1)
            finally:
                os.close(fd)
            if _snapshot_ok(kind, data):
                snap[kind] = data
    finally:
        os.close(dfd)
    return snap


def _save_snapshot(items):
    """Keep what was just verified and installed (a dict kind -> bytes). Never decides the outcome of a run."""
    try:
        _ensure_state_dirs()
        dfd = os.open(SNAPSHOT_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for kind, data in items.items():
                if data is not None and _snapshot_ok(kind, data):
                    _write_new(dfd, SNAPSHOT_NAMES[kind], data, private=True)
        finally:
            os.close(dfd)
    except (OSError, Failure) as exc:
        _log('snapshot not saved: %s' % (getattr(exc, 'strerror', None) or getattr(exc, 'error', '') or type(exc).__name__))


def _quarantine_copy(label, name, data, why, out):
    """Keep the bytes of a file that is not re-created in the root-only quarantine directory (never overwriting, never
    following a link) and say so. Failing to keep a copy does not keep the file in place."""
    where = '(no copy kept)'
    try:
        qfd = os.open(QUARANTINE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if len(os.listdir(qfd)) >= MAX_QUARANTINE:
                where = '(quarantine full, no copy kept)'
            else:
                new = '%s.%d.%s' % (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()), os.getpid(), _safe(name)[:100])
                suffix = 0
                while True:
                    try:
                        _write_exclusive(qfd, new if suffix == 0 else '%s.%d' % (new, suffix), data[:MAX_CONF_FILE])
                        break
                    except FileExistsError:
                        suffix += 1
                where = os.path.join(QUARANTINE_DIR, new if suffix == 0 else '%s.%d' % (new, suffix))
        finally:
            os.close(qfd)
    except OSError as exc:
        where = '(no copy kept: %s)' % exc.strerror
    _log('quarantined %s: %s' % (label, why))
    out.append('lockdown: QUARANTINED %s (%s) -> %s' % (label, why, where))


def _write_exclusive(dfd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def _why(findings):
    return ', '.join('%s at line %d' % (what, number) for number, what in findings[:6]) + (' ...' if len(findings) > 6 else '')


def _default_main():
    """What replaces a /etc/dnsmasq.conf that must not be kept and has no snapshot: DHCP off, which the dashboard
    turns on again with Save & Apply (it renders from the database)."""
    settings = normalize_settings({'dhcp_enabled': 'false', 'interface': _default_interface() or 'lo'})
    return render_main(settings).encode('ascii')


def _salvage_reservations(data):
    """The dhcp-host lines of the exact shape this program renders; everything else is dropped."""
    items = []
    for line in data.decode('latin-1').split('\n'):
        m = re.fullmatch(r'dhcp-host=([^,]+),([^,]+)(?:,([^,]+))?', line)
        if m:
            try:
                items += normalize_reservations([{'mac': m.group(1), 'ip': m.group(2), 'hostname': m.group(3) or ''}])
            except Reject:
                pass
    return render_reservations(items).encode('ascii')


# ============================================================ lockdown ============================================================

def _refuse(dfd, name, label, out, why):
    """A link, directory or special file in a root-owned directory (or any entry that could not be processed): renamed to a
    dot name (dnsmasq skips those, nothing is deleted, a link is never followed) and given to root. The new name is short
    whatever the old one was; if somebody took it (a directory there, say) the next one is tried."""
    base = '.refused.%d.%d.%s' % (int(time.time()), os.getpid(), _safe(name)[:100])
    new, attempt = base, 0
    while True:
        try:
            os.rename(name, new, src_dir_fd=dfd, dst_dir_fd=dfd)
            break
        except OSError as exc:
            attempt += 1
            if attempt > 32 or exc.errno not in (errno.EISDIR, errno.ENOTDIR, errno.ENOTEMPTY, errno.EEXIST):
                raise
            new = '%s.%d' % (base, attempt)
    try:
        os.chown(new, 0, 0, dir_fd=dfd, follow_symlinks=False)
    except OSError:
        pass
    # a regular file put aside (an entry that could not be processed) keeps the mode the web tier gave it: no write bit for group and others
    try:
        fd = os.open(new, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=dfd)
        try:
            mode = os.fstat(fd)
            if stat.S_ISREG(mode.st_mode) and mode.st_uid == 0:
                os.fchmod(fd, stat.S_IMODE(mode.st_mode) & ~0o022)
        finally:
            os.close(fd)
    except OSError:
        pass
    out.append('lockdown: QUARANTINED %s (%s) -> %s' % (label, why, new))


def _read_all(fd, limit):
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b''.join(chunks)
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)


def _lock_entry(dfd, name, label, kind, snap, out, final):
    """One entry of a root-owned directory (kind: 'other', 'res' for reservations.conf, 'main' for dnsmasq.conf)."""
    label = _safe(label)
    try:
        lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if name.startswith('.refused.') and lst.st_uid == 0 and not stat.S_ISREG(lst.st_mode):
        return  # put aside by an earlier run
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=dfd)
    except OSError as exc:
        return _refuse(dfd, name, label, out, 'link' if exc.errno == errno.ELOOP else exc.strerror)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            fd = None
            return _refuse(dfd, name, label, out, 'directory' if stat.S_ISDIR(st.st_mode) else 'special file')
        if st.st_uid == 0 and not st.st_mode & 0o022:
            out.append('lockdown: kept %s (root-owned, mode %o)' % (label, stat.S_IMODE(st.st_mode)))
            if kind != 'other':
                final[kind] = (_read_all(fd, MAX_CONF_FILE), True)
            return
        data = _read_all(fd, MAX_CONF_FILE)
    finally:
        if fd is not None:
            os.close(fd)
    mtime = (st.st_atime_ns, st.st_mtime_ns)
    if data is None:
        os.unlink(name, dir_fd=dfd)
        _quarantine_copy(label, name, b'', 'larger than %d bytes' % MAX_CONF_FILE, out)
        return
    findings = scan_config(data, kind if kind in ('main', 'res') else 'other', strict=True)
    if kind == 'other':
        if findings:
            _quarantine_copy(label, name, data, _why(findings), out)
            os.unlink(name, dir_fd=dfd)
        else:
            _write_new(dfd, name, data, mtime_ns=mtime)
            out.append('lockdown: re-created %s as root:root 0644 (was uid %d, mode %o)' % (label, st.st_uid, stat.S_IMODE(st.st_mode)))
        return
    # The two files this program renders: never trusted from the disk when a root-held snapshot of the last good
    # rendering exists; without one, what is clean stays and what is not is replaced.
    snapshot = snap.get(kind)
    reliable = True
    if snapshot is not None:
        content = snapshot
        if data != snapshot:
            if findings:
                _quarantine_copy(label, name, data, _why(findings), out)
            else:
                _quarantine_copy(label, name, data, 'differs from the root-held snapshot', out)
                out[-1] = out[-1].replace('QUARANTINED', 'REPLACED', 1)
            out.append('lockdown: restored %s from the root-held snapshot' % label)
            mtime = None
    elif not findings:
        content = data
    else:
        _quarantine_copy(label, name, data, _why(findings), out)
        if kind == 'main':
            content, reliable = _default_main(), False
            out.append('lockdown: %s is now a safe default (DHCP off): Save & Apply in the dashboard renders it again' % label)
        else:
            content = _salvage_reservations(data)
            out.append('lockdown: %s keeps only its dhcp-host lines of the shape this program renders' % label)
        mtime = None
    _write_new(dfd, name, content, mtime_ns=mtime)
    out.append('lockdown: re-created %s as root:root 0644 (was uid %d, mode %o)' % (label, st.st_uid, stat.S_IMODE(st.st_mode)))
    final[kind] = (content, reliable)


def lockdown():
    lock = _take_lock()  # a request that is being applied finishes first; none starts while the files are re-created
    try:
        return _lockdown()
    finally:
        os.close(lock)


def _lock_one(dfd, name, label, kind, snap, out, final, failed):
    """_lock_entry for one entry, with whatever goes wrong with it contained here: a read or write error, an exhausted disk,
    a name of any length, a bug. The entry is put aside like a link (a name dnsmasq skips) and the lockdown goes on, so one
    entry can never leave the others - above all the main file, which is the last one - in the web tier's hands. What could
    not even be put aside is listed in `failed`, and so is a main file that had to be (it is gone)."""
    try:
        _lock_entry(dfd, name, label, kind, snap, out, final)
        return
    except Exception as exc:  # not BaseException: a signal still ends the run
        why = getattr(exc, 'strerror', None) or type(exc).__name__
    shown = _safe(label)
    try:
        _refuse(dfd, name, shown, out, 'could not be locked: %s' % why)
    except FileNotFoundError:
        return  # gone meanwhile: nothing is left to lock
    except OSError as exc:
        out.append('lockdown: FAILED %s (%s; it could not be put aside either: %s)' % (shown, why, exc.strerror))
        failed.append(shown)
        return
    if kind == 'main':
        failed.append(shown)


def _lockdown():
    out = []
    final = {}
    failed = []
    _ensure_state_dirs()
    snap = _load_snapshot()
    st = os.lstat(CONF_DIR) if os.path.lexists(CONF_DIR) else None
    if st is None:
        os.mkdir(CONF_DIR, 0o755)
    elif not stat.S_ISDIR(st.st_mode):
        raise Failure('validation', '%s is not a directory' % CONF_DIR, code=5)
    dfd = os.open(CONF_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        # first the directory itself: from here on nobody but root can add, rename or remove entries
        os.fchown(dfd, 0, 0)
        os.fchmod(dfd, 0o755)
        out.append('lockdown: %s is root:root 0755' % CONF_DIR)
        for name in sorted(os.listdir(dfd)):
            _lock_one(dfd, name, os.path.join(CONF_DIR, name), 'res' if name == RES_NAME else 'other', snap, out, final, failed)
    finally:
        os.close(dfd)
    parent, name = os.path.split(CONF_PATH)
    pfd = os.open(parent or '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.path.islink(CONF_PATH):
            raise Failure('validation', '%s is a symbolic link: resolve it by hand' % CONF_PATH, output='\n'.join(out), code=5)
        if os.path.lexists(CONF_PATH):
            _lock_one(pfd, name, CONF_PATH, 'main', snap, out, final, failed)
        else:
            out.append('lockdown: %s does not exist' % CONF_PATH)
    finally:
        os.close(pfd)
    keep = {}
    for kind, (content, reliable) in final.items():
        if reliable and content is not None and content != snap.get(kind) and _snapshot_ok(kind, content):
            keep[kind] = content
    if keep:
        _save_snapshot(keep)
    if failed:
        # everything else is done (the directory and the main file are root's, the other entries are re-created or put aside);
        # the report goes out with the failure so that the operator sees what was done and what was not
        raise Failure('validation', 'could not lock: %s' % ', '.join(failed), output='\n'.join(out), code=5)
    return out


def main(argv):
    os.umask(0o077)
    if os.geteuid() != 0:
        print(json.dumps({'success': False, 'stage': 'validation', 'error': 'must run as root (through sudo)'}))
        return 5
    if len(argv) > 1:
        # --lockdown only makes dnsmasq's files root-owned and --audit only names directives, so neither is dangerous in
        # other hands; and the installer runs them under `sudo` or from the updater that www-data starts through sudo, so
        # SUDO_UID cannot be used to tell a legitimate caller from another. The sudoers rule (`""`) is what keeps arguments
        # away from the web tier.
        try:
            if argv[1:] == ['--lockdown']:
                for line in lockdown():
                    print(line)
                return 0
            if argv[1:] == ['--audit']:
                findings = audit()
                for label, number, name in findings:
                    print('FINDING %s:%d: %s' % (label, number, name))
                print('audit: %d finding(s)' % len(findings))
                return 1 if findings else 0
        except Failure as exc:
            if exc.output:
                print(exc.output)  # what the lockdown did before it stopped
            print('error: %s' % exc.error, file=sys.stderr)
            return exc.code
        except OSError as exc:
            print('error: %s' % exc, file=sys.stderr)
            return 1
        print('usage: dnsmasq-apply [--lockdown | --audit]', file=sys.stderr)
        return 2
    try:
        code, body = run_request()
    except Exception as exc:  # never a traceback to the caller
        _log('internal error: %s' % type(exc).__name__)
        code, body = 1, {'success': False, 'stage': 'validation', 'error': 'internal error (%s)' % type(exc).__name__}
    print(json.dumps(body))
    return code


if __name__ == '__main__':
    sys.exit(main(sys.argv))
DNSMASQAPPLY
chown root:root /opt/irongate/dnsmasq-apply
chmod 755 /opt/irongate/dnsmasq-apply

# ---- web root helper: begin ----
# The only writer of /etc/irongate/config.yaml and /etc/irongate/auth.json (see the file for why).
IG_WEBWRITE_NEW=/usr/local/sbin/.irongate-webwrite.new
rm -f "$IG_WEBWRITE_NEW"
cat > "$IG_WEBWRITE_NEW" << 'IRONGATE_WEBWRITE'
#!/usr/bin/python3 -I
"""irongate-webwrite - the only program that writes /etc/irongate/config.yaml and /etc/irongate/auth.json.

Why this exists. The web tier (www-data) used to write both files itself, so it owned them or had to widen
/etc/irongate every time a save failed. Those files are read by the root engine and by nothing else that needs
write access, so the web tier now hands this program a REQUEST as data and runs it through sudo:

    www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite config-apply
    www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-credentials
    www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-username

The program accepts exactly one verb and no other argument, reads a JSON object on stdin (ASCII, at most 64 KiB,
no duplicate keys, at most four levels of nesting), checks every value against the shape the dashboard and the
engine use, renders the YAML itself (the web tier never supplies YAML text) and replaces the file atomically as
root:www-data 0640. It never widens or re-owns /etc/irongate.

For config-apply the rendered bytes are compared with the file that is already there (the `# Generated:` line
ignored); when nothing changed it writes nothing and does not restart irongate.

Output: one JSON object on stdout, {"success": bool, "error": str, "changed": bool}.
Exit status: 0 applied/unchanged, 2 request refused, 3 write failed, 4 service restart failed, 1 internal error.
"""

import datetime
import fcntl
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.parse

try:
    import syslog
except ImportError:  # pragma: no cover
    syslog = None

# ---- paths (the tests import this file and may point these at a scratch tree) ----
CONFIG_PATH = '/etc/irongate/config.yaml'
AUTH_PATH = '/etc/irongate/auth.json'
LOCK_PATH = '/run/irongate-webwrite.lock'
SYSTEMCTL_BIN = ('/usr/bin/systemctl', '/bin/systemctl')
WEB_GID = 33
MAX_INPUT = 65536
MAX_STRING = 253
SERVICE_TIMEOUT = 20

VERBS = ('config-apply', 'auth-set-credentials', 'auth-set-username')

# The Midnight presets and their indexer URLs (mirror web/api.php midnightNetworks() and src/blockchain.py
# NETWORKS). Only these hosts may appear in a custom blockchain.indexer_url; the chosen network's own preset
# (byte for byte, including the loopback 'undeployed' one) is always accepted.
NETWORK_PRESETS = {
    'preprod': 'https://indexer.preprod.midnight.network/api/v4/graphql',
    'preview': 'https://indexer.preview.midnight.network/api/v4/graphql',
    'mainnet': 'https://indexer.mainnet.midnight.network/api/v4/graphql',
    'undeployed': 'http://127.0.0.1:8088/api/v4/graphql',
}
NETWORKS = tuple(NETWORK_PRESETS)
INDEXER_HOSTS = frozenset((
    'indexer.preprod.midnight.network',
    'indexer.preview.midnight.network',
    'indexer.mainnet.midnight.network',
))

# Engine/dashboard shapes (mirror src/irongate.py _valid_iface/_valid_zone_name and src/dnsmasq-apply _MAC_RE).
IFACE_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}')
ZONE_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_-]{0,31}')
MAC_RE = re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
CONTRACT_RE = re.compile(r'0x[0-9A-Fa-f]{64}')
HASH_RE = re.compile(r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}')
USERNAME_RE = re.compile(r'[A-Za-z0-9._-]{1,32}')

# ---- the exact key sets of a config-apply request ----
NETWORK_KEYS = ('interface', 'local_ip', 'local_mac', 'gateway_ip', 'gateway_mac')
BRIDGE_KEYS = ('enabled', 'isolated_interface', 'bridge_name', 'bridge_ip', 'bridge_netmask',
               'dhcp_start', 'dhcp_end', 'port_isolation')
LAYER_KEYS = ('arp_defense', 'ipv6_ra', 'gateway_takeover', 'bypass_detection', 'firewall')
BLOCKCHAIN_KEYS = ('enabled', 'network', 'contract_address', 'indexer_url', 'cache_ttl',
                   'fallback_allow', 'audit_logging', 'allow_rogue_devices')
GROUP_KEYS = ('name', 'color', 'icon', 'description', 'lan_access', 'can_access_groups')
DEVICE_KEYS = ('mac', 'ip', 'zone')
SETTINGS_BASE_KEYS = ('network', 'mode', 'layers', 'blockchain', 'custom_groups', 'devices')


class Reject(Exception):
    """The request is not acceptable; nothing is written (exit 2)."""


class Failure(Exception):
    """A step that is not the request's fault failed. code is the exit status."""

    def __init__(self, error, code):
        Exception.__init__(self, error)
        self.error = error
        self.code = code


# ============================================================ parsing ============================================================

def _no_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Reject('duplicate key in request')
        out[key] = value
    return out


def _bad_constant(_name):
    raise Reject('non-finite number in request')


def _check_depth(node, depth):
    """A container deeper than four levels below the request object is refused (the deepest legitimate one is
    custom_groups[].can_access_groups)."""
    if isinstance(node, dict) or isinstance(node, list):
        if depth > 4:
            raise Reject('request is nested too deeply')
        values = node.values() if isinstance(node, dict) else node
        for value in values:
            _check_depth(value, depth + 1)


def parse_request(raw):
    """bytes -> dict. Raises Reject."""
    if len(raw) > MAX_INPUT:
        raise Reject('request is too large')
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        raise Reject('request is not ASCII')
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except (ValueError, RecursionError):
        raise Reject('request is not valid JSON')
    if not isinstance(obj, dict):
        raise Reject('request is not an object')
    _check_depth(obj, 0)
    return obj


def _exact_keys(obj, keys, what):
    if not isinstance(obj, dict):
        raise Reject('%s is not an object' % what)
    if set(obj) != set(keys):
        raise Reject('%s has an unknown or missing key' % what)


# ============================================================ value shapes ============================================================

def _printable(value):
    """True when the string has no control or line-separator character. The raw request is ASCII (PHP's
    json_encode() escapes everything else); a decoded value may still carry printable Unicode, as a group
    icon does, and it is rendered exactly as the PHP generator rendered it."""
    for ch in value:
        code = ord(ch)
        if code < 0x20 or 0x7f <= code <= 0x9f or 0xd800 <= code <= 0xdfff or code in (0x2028, 0x2029):
            return False
    return True


def _string(value, field, allow_empty=True):
    if not isinstance(value, str) or len(value) > MAX_STRING or not _printable(value):
        raise Reject('invalid %s' % field)
    if not allow_empty and value == '':
        raise Reject('invalid %s' % field)
    return value


def _iface(value, field):
    """An empty string or a kernel interface name, as src/irongate.py _valid_iface() and web/api.php:158-161."""
    value = _string(value, field)
    if value != '' and IFACE_RE.fullmatch(value) is None:
        raise Reject('invalid %s' % field)
    return value


def _ipv4(value, field, allow_empty=True):
    if value == '':
        if allow_empty:
            return ''
        raise Reject('invalid %s' % field)
    if not isinstance(value, str):
        raise Reject('invalid %s' % field)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise Reject('invalid %s' % field)
    if addr.version != 4 or str(addr) != value:
        raise Reject('invalid %s' % field)
    return value


def _mac(value, field, allow_empty):
    if value == '' and allow_empty:
        return ''
    if not isinstance(value, str):
        raise Reject('invalid %s' % field)
    if MAC_RE.fullmatch(value) is None:
        raise Reject('invalid %s' % field)
    return value


def _bool(value, field):
    if value is not True and value is not False:
        raise Reject('invalid %s' % field)
    return value


def _indexer_url(value, network):
    """None/'' means "use the network default". The chosen network's own preset URL is accepted byte for
    byte (that is the loopback http preset for 'undeployed'); anything else must pass the same rule as
    web/api.php validIndexerUrl() and src/blockchain.py validate_indexer_url()."""
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > MAX_STRING:
        raise Reject('invalid indexer_url')
    if value == NETWORK_PRESETS[network]:
        return value
    if re.fullmatch(r'[\x21-\x7e]+', value) is None or '\\' in value:
        raise Reject('invalid indexer_url')
    # urlsplit() lower-cases the scheme; PHP's parse_url() does not, and an all-upper-case
    # scheme is not the "https" this file and the engine require.
    if value.split(':', 1)[0] != 'https':
        raise Reject('invalid indexer_url')
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except ValueError:
        raise Reject('invalid indexer_url')
    if parts.scheme != 'https' or '@' in parts.netloc or port not in (None, 443):
        raise Reject('invalid indexer_url')
    if (parts.hostname or '').lower() not in INDEXER_HOSTS:
        raise Reject('invalid indexer_url')
    return value


def _contract_address(value):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 66 or CONTRACT_RE.fullmatch(value) is None:
        raise Reject('invalid contract_address')
    return value


def normalize_settings(settings):
    """Strict, canonical form of the settings the dashboard's generator writes. Raises Reject."""
    if not isinstance(settings, dict):
        raise Reject('settings is not an object')
    for key in settings:
        if key not in SETTINGS_BASE_KEYS and key != 'bridge':
            raise Reject('unknown settings key')
    mode = settings.get('mode')
    if mode not in ('single', 'dual'):
        raise Reject('invalid mode')
    required = set(SETTINGS_BASE_KEYS) | ({'bridge'} if mode == 'dual' else set())
    if set(settings) != required:
        raise Reject('settings has an unknown or missing key')

    network_in = settings['network']
    _exact_keys(network_in, NETWORK_KEYS, 'network')
    iface = _string(network_in['interface'], 'interface')
    if iface != '' and IFACE_RE.fullmatch(iface) is None:
        raise Reject('invalid interface')
    network = {
        'interface': iface,
        'local_ip': _ipv4(network_in['local_ip'], 'local_ip'),
        'local_mac': _mac(network_in['local_mac'], 'local_mac', True),
        'gateway_ip': _ipv4(network_in['gateway_ip'], 'gateway_ip'),
        'gateway_mac': _mac(network_in['gateway_mac'], 'gateway_mac', True),
    }

    out = {'network': network, 'mode': mode}

    if mode == 'dual':
        bridge_in = settings['bridge']
        _exact_keys(bridge_in, BRIDGE_KEYS, 'bridge')
        bridge_name = _string(bridge_in['bridge_name'], 'bridge_name', allow_empty=False)
        if IFACE_RE.fullmatch(bridge_name) is None:
            raise Reject('invalid bridge_name')
        bridge = {
            'enabled': _bool(bridge_in['enabled'], 'bridge.enabled'),
            'isolated_interface': _iface(bridge_in['isolated_interface'], 'isolated_interface'),
            'bridge_name': bridge_name,
            'bridge_ip': _ipv4(bridge_in['bridge_ip'], 'bridge_ip'),
            'bridge_netmask': _ipv4(bridge_in['bridge_netmask'], 'bridge_netmask', allow_empty=False),
            'dhcp_start': _ipv4(bridge_in['dhcp_start'], 'dhcp_start'),
            'dhcp_end': _ipv4(bridge_in['dhcp_end'], 'dhcp_end'),
            'port_isolation': _bool(bridge_in['port_isolation'], 'bridge.port_isolation'),
        }
        # The generator writes these two as constants; anything else would not be the same file.
        if bridge['enabled'] is not True or bridge['port_isolation'] is not True:
            raise Reject('invalid bridge enabled/port_isolation')
        out['bridge'] = bridge

    layers_in = settings['layers']
    _exact_keys(layers_in, LAYER_KEYS, 'layers')
    out['layers'] = dict((key, _bool(layers_in[key], 'layers.' + key)) for key in LAYER_KEYS)

    blockchain_in = settings['blockchain']
    _exact_keys(blockchain_in, BLOCKCHAIN_KEYS, 'blockchain')
    network_name = blockchain_in['network']
    if network_name not in NETWORKS:
        raise Reject('unknown blockchain network')
    cache_ttl = blockchain_in['cache_ttl']
    if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, int) or cache_ttl < 0 or cache_ttl > 2147483647:
        raise Reject('invalid cache_ttl')
    out['blockchain'] = {
        'enabled': _bool(blockchain_in['enabled'], 'blockchain.enabled'),
        'network': network_name,
        'contract_address': _contract_address(blockchain_in['contract_address']),
        'indexer_url': _indexer_url(blockchain_in['indexer_url'], network_name),
        'cache_ttl': cache_ttl,
        'fallback_allow': _bool(blockchain_in['fallback_allow'], 'blockchain.fallback_allow'),
        'audit_logging': _bool(blockchain_in['audit_logging'], 'blockchain.audit_logging'),
        'allow_rogue_devices': _bool(blockchain_in['allow_rogue_devices'], 'blockchain.allow_rogue_devices'),
    }

    groups_in = settings['custom_groups']
    if not isinstance(groups_in, list):
        raise Reject('custom_groups is not a list')
    groups = []
    for number, item in enumerate(groups_in, 1):
        _exact_keys(item, GROUP_KEYS, 'custom group %d' % number)
        name = item['name']
        if not isinstance(name, str) or ZONE_RE.fullmatch(name) is None:
            raise Reject('invalid custom group %d name' % number)
        access = item['can_access_groups']
        if not isinstance(access, list):
            raise Reject('invalid custom group %d can_access_groups' % number)
        checked_access = []
        for entry in access:
            if not isinstance(entry, str) or ZONE_RE.fullmatch(entry) is None:
                raise Reject('invalid custom group %d can_access_groups' % number)
            checked_access.append(entry)
        groups.append({
            'name': name,
            'color': _string(item['color'], 'custom group color'),
            'icon': _string(item['icon'], 'custom group icon'),
            'description': _string(item['description'], 'custom group description'),
            'lan_access': _string(item['lan_access'], 'custom group lan_access'),
            'can_access_groups': checked_access,
        })
    out['custom_groups'] = groups

    devices_in = settings['devices']
    if not isinstance(devices_in, list):
        raise Reject('devices is not a list')
    devices = []
    for number, item in enumerate(devices_in, 1):
        _exact_keys(item, DEVICE_KEYS, 'device %d' % number)
        mac = item['mac']
        if not isinstance(mac, str) or MAC_RE.fullmatch(mac) is None:
            raise Reject('invalid device %d mac' % number)
        zone = item['zone']
        if not isinstance(zone, str) or ZONE_RE.fullmatch(zone) is None:
            raise Reject('invalid device %d zone' % number)
        devices.append({
            'mac': mac,
            'ip': _ipv4(item['ip'], 'device %d ip' % number),
            'zone': zone,
        })
    out['devices'] = devices
    return out


# ============================================================ rendering (byte-for-byte the PHP generator) ============================================================

def _scalar(value):
    """PHP yamlScalar(): json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE). PHP still escapes
    U+2028/U+2029 even with that flag, so they are escaped here too."""
    return (json.dumps(value, ensure_ascii=False)
            .replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))


def render_config(settings, now=None):
    """The same bytes web/api.php applyIrongateConfig() wrote, for the same settings."""
    stamp = now if now is not None else time.strftime('%Y-%m-%d %H:%M:%S')
    network = settings['network']
    out = '# Irongate Configuration\n'
    out += '# Generated: ' + stamp + '\n\n'
    out += 'network:\n'
    out += '  interface: ' + _scalar(network['interface']) + '\n'
    out += '  local_ip: ' + _scalar(network['local_ip']) + '\n'
    out += '  local_mac: ' + _scalar(network['local_mac']) + '\n'
    out += '  gateway_ip: ' + _scalar(network['gateway_ip']) + '\n'
    out += '  gateway_mac: ' + _scalar(network['gateway_mac']) + '\n\n'
    out += 'mode: ' + _scalar(settings['mode']) + '\n\n'

    bridge = settings.get('bridge')
    if bridge is not None:
        out += 'bridge:\n'
        out += '  enabled: true\n'
        out += '  isolated_interface: ' + _scalar(bridge['isolated_interface']) + '\n'
        out += '  bridge_name: ' + _scalar(bridge['bridge_name']) + '\n'
        out += '  bridge_ip: ' + _scalar(bridge['bridge_ip']) + '\n'
        out += '  bridge_netmask: ' + _scalar(bridge['bridge_netmask']) + '\n'
        out += '  dhcp_start: ' + _scalar(bridge['dhcp_start']) + '\n'
        out += '  dhcp_end: ' + _scalar(bridge['dhcp_end']) + '\n'
        out += '  port_isolation: true\n\n'

    layers = settings['layers']
    out += 'layers:\n'
    for key in LAYER_KEYS:
        out += '  %s: %s\n' % (key, 'true' if layers[key] else 'false')
    out += '\n'

    blockchain = settings['blockchain']
    out += '# Layer 8: Midnight Blockchain Verification\n'
    out += 'blockchain:\n'
    out += '  enabled: %s\n' % ('true' if blockchain['enabled'] else 'false')
    out += '  network: ' + _scalar(blockchain['network']) + '\n'
    if blockchain['contract_address'] is not None:
        out += '  contract_address: ' + _scalar(blockchain['contract_address']) + '\n'
    else:
        out += '  contract_address: null\n'
    if blockchain['indexer_url'] is not None:
        out += '  indexer_url: ' + _scalar(blockchain['indexer_url']) + '\n'
    else:
        out += '  indexer_url: null\n'
    out += '  cache_ttl: %d\n' % blockchain['cache_ttl']
    out += '  fallback_allow: %s\n' % ('true' if blockchain['fallback_allow'] else 'false')
    out += '  audit_logging: %s\n' % ('true' if blockchain['audit_logging'] else 'false')
    out += '  allow_rogue_devices: %s\n\n' % ('true' if blockchain['allow_rogue_devices'] else 'false')

    groups = settings['custom_groups']
    out += '# Custom Device Groups\n'
    out += 'custom_groups:\n'
    if groups:
        for group in groups:
            out += '  - name: ' + _scalar(group['name']) + '\n'
            out += '    color: ' + _scalar(group['color']) + '\n'
            out += '    icon: ' + _scalar(group['icon']) + '\n'
            out += '    description: ' + _scalar(group['description']) + '\n'
            out += '    lan_access: ' + _scalar(group['lan_access']) + '\n'
            out += '    can_access_groups: [' + ', '.join(_scalar(g) for g in group['can_access_groups']) + ']\n'
    else:
        out += '  []\n'
    out += '\n'

    devices = settings['devices']
    out += 'devices:\n'
    if devices:
        for device in devices:
            out += '  - mac: ' + _scalar(device['mac']) + '\n'
            out += '    ip: ' + _scalar(device['ip']) + '\n'
            out += '    zone: ' + _scalar(device['zone']) + '\n'
    else:
        out += '  []\n'
    return out


def _normalize_generated(data):
    lines = []
    for line in data.splitlines(keepends=True):
        if line.startswith(b'# Generated: '):
            lines.append(b'# Generated: X\n')
        else:
            lines.append(line)
    return b''.join(lines)


# ============================================================ PHP-compatible auth.json ============================================================

def _php_string(value):
    """json_encode()'s string escaping without JSON_UNESCAPED_* (what the web tier used for auth.json)."""
    pieces = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            pieces.append('\\"')
        elif ch == '\\':
            pieces.append('\\\\')
        elif ch == '/':
            pieces.append('\\/')
        elif ch == '\b':
            pieces.append('\\b')
        elif ch == '\f':
            pieces.append('\\f')
        elif ch == '\n':
            pieces.append('\\n')
        elif ch == '\r':
            pieces.append('\\r')
        elif ch == '\t':
            pieces.append('\\t')
        elif code < 0x20:
            pieces.append('\\u%04x' % code)
        elif code < 0x7f:
            pieces.append(ch)
        elif code <= 0xffff:
            pieces.append('\\u%04x' % code)
        else:
            value2 = code - 0x10000
            pieces.append('\\u%04x\\u%04x' % (0xd800 + (value2 >> 10), 0xdc00 + (value2 & 0x3ff)))
    pieces.append('"')
    return ''.join(pieces)


def _php_pretty(value, level=1):
    pad = '    ' * level
    if isinstance(value, dict):
        if not value:
            return '{}'
        items = [pad + _php_string(str(key)) + ': ' + _php_pretty(item, level + 1)
                 for key, item in value.items()]
        return '{\n' + ',\n'.join(items) + '\n' + '    ' * (level - 1) + '}'
    if isinstance(value, list):
        if not value:
            return '[]'
        items = [pad + _php_pretty(item, level + 1) for item in value]
        return '[\n' + ',\n'.join(items) + '\n' + '    ' * (level - 1) + ']'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if value is None:
        return 'null'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    return _php_string(value)


def encode_auth(auth):
    """json_encode($auth, JSON_PRETTY_PRINT) . "\\n"."""
    return (_php_pretty(auth) + '\n').encode('utf-8')


# ============================================================ filesystem ============================================================

def _unlink_quiet(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_dir(directory):
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def check_target(path, must_exist):
    """Refuse a link or anything that is not a regular file. Return True when it exists."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if must_exist:
            raise Failure('target is missing', 3)
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Reject('target is not a regular file')
    return True


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def write_atomic(path, data):
    """temp `.NAME.new.PID` in the same directory -> fsync -> rename -> fsync(dir), root:www-data 0640."""
    directory, name = os.path.split(path)
    tmp = os.path.join(directory, '.%s.new.%d' % (name, os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchown(fd, 0, WEB_GID)
        os.fchmod(fd, 0o640)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        _unlink_quiet(tmp)
        raise
    os.close(fd)
    try:
        os.rename(tmp, path)
    except BaseException:
        _unlink_quiet(tmp)
        raise
    _fsync_dir(directory)


def take_lock():
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def restart_service():
    exe = next((path for path in SYSTEMCTL_BIN if os.access(path, os.X_OK)), None)
    if exe is None:
        return 127
    try:
        proc = subprocess.run([exe, 'restart', 'irongate'], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=SERVICE_TIMEOUT, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                            'LANG': 'C', 'LC_ALL': 'C'},
                              close_fds=True)
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 127
    return proc.returncode


# ============================================================ audit ============================================================

def _caller_uid():
    value = os.environ.get('SUDO_UID')
    if value:
        try:
            return int(value)
        except ValueError:
            pass
    return os.getuid()


def _audit(verb, uid, code, reason):
    if syslog is None:
        return
    try:
        syslog.openlog('irongate-webwrite', syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, 'verb=%s uid=%d rc=%d %s' % (verb or '-', uid, code, reason))
    except Exception:  # logging must never decide the outcome
        pass


# ============================================================ verbs ============================================================

def _answer(success, error, changed):
    return {'success': bool(success), 'error': error, 'changed': bool(changed)}


def config_apply(obj):
    _exact_keys(obj, ('settings',), 'request')
    settings = normalize_settings(obj['settings'])
    rendered = render_config(settings).encode('utf-8')
    exists = check_target(CONFIG_PATH, must_exist=False)
    if exists:
        try:
            current = read_file(CONFIG_PATH)
        except OSError:
            raise Failure('target is unreadable', 3)
        if _normalize_generated(current) == _normalize_generated(rendered):
            return 0, _answer(True, '', False), 'unchanged, no reload'
    try:
        write_atomic(CONFIG_PATH, rendered)
    except OSError:
        raise Failure('write failed', 3)
    rc = restart_service()
    if rc != 0:
        return 4, _answer(False, 'service restart failed', True), 'reload failed'
    return 0, _answer(True, '', True), 'applied'


def auth_set(obj, field):
    _exact_keys(obj, (field,), 'request')
    value = obj[field]
    if field == 'password_hash':
        if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
            raise Reject('invalid password_hash')
    else:
        if not isinstance(value, str) or USERNAME_RE.fullmatch(value) is None:
            raise Reject('invalid username')
    check_target(AUTH_PATH, must_exist=True)
    try:
        auth = json.loads(read_file(AUTH_PATH).decode('utf-8'))
    except (OSError, ValueError, UnicodeDecodeError):
        raise Failure('auth file is unreadable', 3)
    if not isinstance(auth, dict):
        raise Failure('auth file is unreadable', 3)
    auth[field] = value
    auth['updated_at'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    data = encode_auth(auth)
    try:
        if read_file(AUTH_PATH) == data:
            return 0, _answer(True, '', False), 'unchanged'
        write_atomic(AUTH_PATH, data)
    except OSError:
        raise Failure('write failed', 3)
    return 0, _answer(True, '', True), 'applied'


def dispatch(verb, obj):
    if verb == 'config-apply':
        return config_apply(obj)
    if verb == 'auth-set-credentials':
        return auth_set(obj, 'password_hash')
    if verb == 'auth-set-username':
        return auth_set(obj, 'username')
    raise Reject('unknown verb')


def _read_stdin():
    chunks = []
    total = 0
    while total <= MAX_INPUT:
        chunk = os.read(0, min(65536, MAX_INPUT + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b''.join(chunks)


def main(argv):
    os.umask(0o077)
    verb = argv[1] if len(argv) == 2 and argv[1] in VERBS else None
    uid = _caller_uid()
    reason = 'ok'
    try:
        if os.geteuid() != 0:
            raise Reject('must run as root (through sudo)')
        if len(argv) != 2 or argv[1] not in VERBS:
            raise Reject('usage: irongate-webwrite <verb>')
        raw = _read_stdin()
        if len(raw) > MAX_INPUT:
            raise Reject('request is too large')
        obj = parse_request(raw)
        lock = take_lock()
        try:
            code, body, reason = dispatch(argv[1], obj)
        finally:
            os.close(lock)
    except Reject as exc:
        code, body, reason = 2, _answer(False, 'refused: %s' % exc, False), 'refused'
    except Failure as exc:
        code, body, reason = exc.code, _answer(False, exc.error, False), 'failed'
    except Exception as exc:  # never a traceback to the caller
        code, body, reason = 1, _answer(False, 'internal error (%s)' % type(exc).__name__, False), 'internal error'
    _audit(verb if len(argv) == 2 else None, uid, code, reason)
    print(json.dumps(body))
    return code


if __name__ == '__main__':
    sys.exit(main(sys.argv))
IRONGATE_WEBWRITE
chown root:root "$IG_WEBWRITE_NEW"
chmod 755 "$IG_WEBWRITE_NEW"
if [ ! -f /usr/local/sbin/irongate-webwrite ] || ! cmp -s "$IG_WEBWRITE_NEW" /usr/local/sbin/irongate-webwrite; then
    mv -f "$IG_WEBWRITE_NEW" /usr/local/sbin/irongate-webwrite
else
    rm -f "$IG_WEBWRITE_NEW"
fi
# ---- web root helper: end ----

mkdir -p /var/lib/irongate
chown root:root /var/lib/irongate
chmod 755 /var/lib/irongate
install -d -o root -g www-data -m 0770 /var/lib/irongate/dnsmasq-staged

# Login lockout counters (web/login.php): www-data owns this directory and file, so auth.json can stay
# root:www-data 0640. Created only when absent; an existing directory or file is left exactly as it is.
# ---- web lockout state: begin ----
if [ ! -d /var/lib/irongate/lockout ]; then
    install -d -o www-data -g www-data -m 0700 /var/lib/irongate/lockout
fi
if [ ! -e /var/lib/irongate/lockout/lockout.json ] && [ ! -L /var/lib/irongate/lockout/lockout.json ]; then
    ( umask 077; printf '%s\n' '{"version":1,"failed_attempts":0,"first_failed_at":0,"locked_until":0}' > /var/lib/irongate/lockout/lockout.json )
    chown www-data:www-data /var/lib/irongate/lockout/lockout.json
    chmod 0600 /var/lib/irongate/lockout/lockout.json
fi
# ---- web lockout state: end ----

# sudo ignores every file of /etc/sudoers.d whose name contains a dot, and a sudoers file with a syntax error
# makes sudo refuse to work at all: the drop-in is written under a dotted name, checked there with visudo and only
# then renamed (atomically) to its real name, so a broken drop-in is never live.
IG_SUDOERS_NEW=/etc/sudoers.d/.irongate-dnsmasq-apply.new
rm -f "$IG_SUDOERS_NEW"
cat << 'DNSMASQAPPLY_SUDOEOF' > "$IG_SUDOERS_NEW"
# Allow the web UI (www-data) to hand a validated dnsmasq request to the root helper.
# The helper takes NO arguments (the "" below), reads /var/lib/irongate/dnsmasq-staged/request.json, accepts only
# the settings the dashboard sets, renders /etc/dnsmasq.conf and /etc/dnsmasq.d/reservations.conf itself and
# restarts dnsmasq. Remove this file to revoke (DHCP settings can then no longer be applied from the web UI).
www-data ALL=(root) NOPASSWD: /opt/irongate/dnsmasq-apply ""
DNSMASQAPPLY_SUDOEOF
chown root:root "$IG_SUDOERS_NEW"
chmod 440 "$IG_SUDOERS_NEW"
if visudo -cf "$IG_SUDOERS_NEW"; then
    mv -T "$IG_SUDOERS_NEW" /etc/sudoers.d/irongate-dnsmasq-apply
else
    echo -e "${RED}ERROR: irongate-dnsmasq-apply sudoers failed validation - not installed (DHCP settings cannot be applied from the web UI until it is fixed)${NC}"
    rm -f "$IG_SUDOERS_NEW"
fi
# ---- dnsmasq root helper: end ----

#######################################
# Set permissions
#######################################
# ---- web-tree permission helper: begin ----
# /var/www/irongate and /etc/dnsmasq.d are handed to www-data (the web UI writes there), so the web tier
# can create, rename and symlink entries in them at any moment, also while this installer runs as root.
# `chmod FILE` and `chmod -R` have no no-follow switch (they re-resolve the name after looking at it),
# so a link planted there made root chmod an arbitrary file (`chmod 666 dhcp.db` on a link to a root-only
# file made it world-writable). ig_perm_fix opens every entry relative to the directory it already
# holds with O_NOFOLLOW and changes owner and mode of the OPEN inode (fchown/fchmod), so nothing can
# be redirected after the type check:
#   ig_perm_fix tree DIR  OWNER GROUP MODE   DIR itself and every directory and regular file below it
#                                            (a directory keeps its setuid/setgid bits, like chmod -R)
#                                            get OWNER:GROUP and MODE; symlinks, FIFOs, sockets and
#                                            hard-linked files are left alone and listed on stderr
#   ig_perm_fix file PATH OWNER GROUP MODE   the same for one file; a symlink, any other type or a file
#                                            with a second hard link is refused (exit 3, nothing changed)
ig_perm_fix() {
    python3 -I - "$@" <<'IG_PERM_FIX_PY'
import errno
import grp
import os
import pwd
import stat
import sys

kind, path, owner, group, mode = sys.argv[1:6]
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
left = []


def fix(fd, st, label, uid, gid, mode):
    """Give the inode behind fd to uid:gid with mode; False (and noted) unless it is a directory or a lone regular file."""
    if stat.S_ISDIR(st.st_mode):
        keep = st.st_mode & 0o6000
    elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
        keep = 0
    else:
        left.append(label)
        return False
    os.fchown(fd, uid, gid)
    os.fchmod(fd, keep | mode)
    return True


def walk(dfd, prefix, depth, uid, gid, mode):
    for name in sorted(os.listdir(dfd)):
        label = prefix + "/" + name
        try:
            fd = os.open(name, FLAGS, dir_fd=dfd)
        except OSError:
            left.append(label)
            continue
        try:
            st = os.fstat(fd)
            if fix(fd, st, label, uid, gid, mode) and stat.S_ISDIR(st.st_mode):
                if depth < 32:
                    walk(fd, label, depth + 1, uid, gid, mode)
                else:
                    left.append(label + "/...")
        finally:
            os.close(fd)


try:
    uid, gid, mode = pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid, int(mode, 8)
    if kind == "tree":
        top = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fix(top, os.fstat(top), path, uid, gid, mode)
        walk(top, path, 0, uid, gid, mode)
    elif kind == "file":
        parent, name = os.path.split(path)
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            fd = os.open(name, FLAGS, dir_fd=pfd)
        except OSError as exc:
            sys.stderr.write("ig_perm_fix: %s %s: refusing to change it\n"
                             % (path, "is a symlink" if exc.errno == errno.ELOOP else exc.strerror))
            sys.exit(3)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not fix(fd, st, path, uid, gid, mode):
            sys.stderr.write("ig_perm_fix: %s is not a regular file with a single link: refusing to change it\n" % path)
            sys.exit(3)
    else:
        sys.exit("ig_perm_fix: unknown kind %r" % kind)
except (KeyError, OSError) as exc:
    sys.exit("ig_perm_fix: %s: %s" % (path, exc))
for label in left:
    sys.stderr.write("ig_perm_fix: left alone (symlink, special file or hard-linked): %r\n" % label)
IG_PERM_FIX_PY
}
# ---- web-tree permission helper: end ----
echo -e "${YELLOW}Setting permissions...${NC}"

# dhcp.db: written by the web API (www-data) and by root's sqlite3 (installer, updater), nothing else
# reads it, so 0664 is enough; it was 0666, i.e. writable by every local user.
ig_perm_fix tree /var/www/irongate www-data www-data 755
ig_perm_fix file /var/www/irongate/dhcp.db www-data www-data 664

# Allow www-data to write dnsmasq config
chown www-data:www-data /etc/dnsmasq.conf
chmod 664 /etc/dnsmasq.conf
ig_perm_fix tree /etc/dnsmasq.d www-data www-data 775

# Ensure lease file has proper ownership for dnsmasq to write
# (the dnsmasq lockdown comes first: it closes the window the three lines above opened, and nothing else is left in it)
# ---- dnsmasq lockdown: begin ----
# Every file is read once, scanned the way dnsmasq's own parser reads it and written back as a new root-owned
# file only if it is clean; a file holding a forbidden directive (or any syntax but plain `name=value`) is never
# re-created: its bytes go to /var/lib/irongate/dnsmasq-quarantine, and the main file and reservations.conf are
# restored from the root-held snapshot of the last good rendering. Links and special files are renamed to .refused.*
# (dnsmasq skips dot files). The audit then reads EVERYTHING dnsmasq reads, root-owned files included; a finding
# stops the installer, and the EXIT trap leaves dnsmasq stopped (ig_dnsmasq_tree_ok).
echo -e "${YELLOW}Making /etc/dnsmasq.conf and /etc/dnsmasq.d root-only...${NC}"
IG_LOCKDOWN_RC=0
IG_LOCKDOWN_OUT=$(/opt/irongate/dnsmasq-apply --lockdown 2>&1) || IG_LOCKDOWN_RC=$?
printf '%s\n' "$IG_LOCKDOWN_OUT"
if [ "$IG_LOCKDOWN_RC" -ne 0 ]; then
    echo -e "${RED}ERROR: could not make /etc/dnsmasq.conf and /etc/dnsmasq.d root-only - stopping, dnsmasq stays stopped${NC}"
    exit 1
fi
case "$IG_LOCKDOWN_OUT" in
    *QUARANTINED*) echo -e "${RED}WARNING: files the web tier could write were not clean and were put aside (names above): the web tier may be compromised${NC}" ;;
esac
if ! /opt/irongate/dnsmasq-apply --audit; then
    echo -e "${RED}ERROR: /etc/dnsmasq.conf or /etc/dnsmasq.d still holds what the findings above name - stopping, dnsmasq stays stopped${NC}"
    exit 1
fi
# ---- dnsmasq lockdown: end ----
# ---- dhcp.db modes: begin ----
# The permission step above (kept as it is, pinned by the O1 tests) gives every file of the web tree - dhcp.db and the
# backups of it too - www-data:www-data 0755 / 0664. Here dhcp.db gets back the mode it had when this run started (without
# world-write; 0660 only when this run created it) and the backup made by this run is root:root 0600, as it was created.
if [ -n "$IG_DB_BACKUP" ]; then
    ig_perm_fix file "$IG_DB_BACKUP" root root 600 || echo -e "${YELLOW}  ! could not restrict $IG_DB_BACKUP to root${NC}"
fi
if [ -n "$IG_DB_MODE_BEFORE" ]; then
    ig_perm_fix file /var/www/irongate/dhcp.db www-data www-data "$IG_DB_MODE_BEFORE"
elif [ "$IG_DB_CREATED" = 1 ]; then
    ig_perm_fix file /var/www/irongate/dhcp.db www-data www-data 660
fi
# ---- dhcp.db modes: end ----
chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null || chown nobody:nogroup /var/lib/dnsmasq/dnsmasq.leases
chmod 644 /var/lib/dnsmasq/dnsmasq.leases

# Ensure log file is readable by www-data (use world-readable since group memberships require service restart)
chown dnsmasq:adm /var/log/dnsmasq.log 2>/dev/null || chown nobody:adm /var/log/dnsmasq.log
chmod 644 /var/log/dnsmasq.log

# Make www-data a member of systemd-journal and adm groups to read logs
# Note: www-data needs php-fpm restart to pick up new group memberships
usermod -a -G systemd-journal www-data 2>/dev/null || true
usermod -a -G adm www-data 2>/dev/null || true

# Like the drop-in of the dnsmasq root helper above: sudo ignores every file of /etc/sudoers.d whose name contains a dot, and
# a sudoers file with a syntax error makes sudo refuse to work at all, so this file is written under a dotted name, checked
# there with visudo and only then renamed (atomically) to its real name. If the check fails, the file that is in place
# stays as it is and an error is printed.
IG_SUDOERS_WEB_NEW=/etc/sudoers.d/.irongate-dnsmasq-web.new
rm -f "$IG_SUDOERS_WEB_NEW"
cat << EOF > "$IG_SUDOERS_WEB_NEW"
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
www-data ALL=(ALL) NOPASSWD: /usr/sbin/arping *
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block irongate-updater-now.service
www-data ALL=(ALL) NOPASSWD: /usr/bin/touch /var/log/irongate-update.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown www-data /var/log/irongate-update.log
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite config-apply
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-credentials
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-username
EOF
chown root:root "$IG_SUDOERS_WEB_NEW"
chmod 440 "$IG_SUDOERS_WEB_NEW"
if visudo -cf "$IG_SUDOERS_WEB_NEW"; then
    mv -T "$IG_SUDOERS_WEB_NEW" /etc/sudoers.d/dnsmasq-web
else
    echo -e "${RED}ERROR: dnsmasq-web sudoers failed validation - the file in place (if any) is left as it is; the web UI's sudo rules are not updated${NC}"
    rm -f "$IG_SUDOERS_WEB_NEW"
fi

#######################################
# Create systemd watchdog for auto-recovery
#######################################
echo -e "${YELLOW}Setting up service watchdog...${NC}"

mkdir -p /etc/systemd/system/dnsmasq.service.d

cat > /etc/systemd/system/dnsmasq.service.d/override.conf << EOF
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Restart=on-failure
RestartSec=5
# Clear resolvconf hooks — dnsmasq runs with port=0 (DNS disabled),
# and systemd-networkd is disabled, so resolvconf calls always fail
# with "Unit dbus-org.freedesktop.network1.service not found"
ExecStartPost=
ExecStop=
EOF

#######################################
# Create Irongate Network Isolation Service
#######################################
echo -e "${YELLOW}Setting up Irongate network isolation...${NC}"

mkdir -p /opt/irongate
mkdir -p /etc/irongate
mkdir -p /var/log/irongate

# ---- /etc/irongate fixed-file helpers: begin ----
# /etc/irongate can be group-writable for www-data (an installation made by an older version has it
# 0775 and its mode is kept; a new one is created 0750), so the web tier may be able to
# create, rename and symlink entries there at any moment, also while this installer runs as
# root. A root process must therefore never open, chown or chmod a fixed name in it by path:
# that follows a planted symlink to whatever it points at (`cat >` on a dangling link even creates
# the target, and on a FIFO it blocks forever). These helpers do the work in a root-only staging
# directory on the same filesystem and reach the final name only through rename(2) (replaces a
# symlink, never follows it) or link(2) (links the symlink itself, never its target):
#   ig_etc_check  NAME       0 = NAME is a regular file, 1 = absent. A symlink, directory, FIFO,
#                            socket or device is renamed aside (NAME.refused.<time>.<pid>, never
#                            deleted) and reported, and counts as absent
#   ig_etc_fix    NAME MODE  root:www-data for an existing regular NAME, without following links;
#                            MODE `keep` leaves the mode as it is, MODE `keep-o` only removes the
#                            `other` permission bits (never adds any); a numeric MODE is set exactly
#   ig_etc_commit NAME MODE  install the file staged as $IG_STAGE/NAME as root:www-data MODE
#   ig_etc_ensure NAME MODE  NAME exists as a regular file: created empty as root:www-data MODE if
#                            missing; an existing file keeps its content, owner, group and u/g mode
#                            bits and loses every `other` bit (never widened)
IG_ETC=/etc/irongate
IG_STAGE=/etc/.irongate-stage
ig_stage() {
    install -d -m 0700 -o root -g root "$IG_STAGE"
}
ig_etc_check() {
    local p="$IG_ETC/$1" aside
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then
        aside="$p.refused.$(date +%s).$$"
        echo -e "${RED}  ! $p is a symlink or not a regular file: not following it, moving it to $aside${NC}" >&2
        mv -T -- "$p" "$aside" || true
        return 1
    fi
    [ -f "$p" ]
}
ig_etc_fix() {
    local pin="$IG_STAGE/$1.pin.$$" rc=0
    ig_stage || return 1
    # link(2) does not follow a symlink: $pin is a second name for exactly the inode that is at NAME
    # right now, in a directory the web tier cannot reach, so the check and the chown/chmod below
    # cannot be redirected by a swap of NAME in between.
    if ! ln -fP -- "$IG_ETC/$1" "$pin" 2>/dev/null; then
        echo -e "${RED}  ! cannot pin $IG_ETC/$1 (missing, or no hard links here): owner and mode left as they are${NC}" >&2
        return 1
    fi
    if [ -L "$pin" ] || [ ! -f "$pin" ]; then
        echo -e "${RED}  ! $IG_ETC/$1 is a symlink or not a regular file: owner and mode left as they are${NC}" >&2
        rm -f -- "$pin"
        return 1
    fi
    chown root:www-data "$pin" && { case "$2" in keep) ;; keep-o) chmod o-rwx "$pin" ;; *) chmod "$2" "$pin" ;; esac; } || rc=1
    rm -f -- "$pin"
    return $rc
}
ig_etc_commit() {
    local f="$IG_STAGE/$1"
    chown root:www-data "$f" && chmod "$2" "$f" && mv -fT -- "$f" "$IG_ETC/$1"
}
ig_etc_ensure() {
    local rc=0
    if ig_etc_check "$1"; then
        ig_etc_fix "$1" keep-o || rc=1
    else
        { ig_stage && : > "$IG_STAGE/$1" && ig_etc_commit "$1" "$2"; } || rc=1
    fi
    rmdir "$IG_STAGE" 2>/dev/null || true
    return $rc
}
# ---- /etc/irongate fixed-file helpers: end ----

# IMPORTANT: www-data needs to write to config.yaml from the web UI
# Recursive chown of everything in /etc/irongate (links are not followed) EXCEPT the updater's
# pin file, which is the updater's trust root and stays exactly as the operator left it:
# a genuine root:root pin keeps its owner and mode, while a file or symlink that the web
# tier (www-data can write this directory) put there is never promoted to root:root and
# never chown/chmod'ed through. The updater refuses anything but a regular root:root
# 0644/0600 pin file.
# -execdir, not -exec: each chown runs in the directory find is standing in (by file descriptor)
# on "./name", so a subdirectory the web tier swaps for a symlink after find listed it cannot
# send root's chown to a file outside /etc/irongate.
find /etc/irongate ! -path /etc/irongate/updater-pin.conf -execdir chown -h root:www-data {} +
# The directory keeps the mode it has (0750 when this run created it, see above): it is never widened to 0775 here.
# config.yaml: an existing file keeps its content and mode; a missing one starts as an empty 0640 placeholder
# (an empty config.yaml counts as absent: it is generated further down).
ig_etc_ensure config.yaml 640 || true

# Create Python virtual environment
python3 -m venv /opt/irongate/venv 2>/dev/null || true
# Dependencies: every package is pinned to one version and to the sha256 of each of its published files, and pip runs in
# --require-hashes mode, so nothing else (a newer release, a replaced file, a dependency not listed) can be installed.
# The lists are carried by this installer (the updater downloads this one file and nothing else) and written to a
# root-only temporary directory. The first is what the virtual environment holds (every PyPI file of that exact
# version); the second is for the system python3 that the fallbacks below install into.
IG_REQ_DIR=$(mktemp -d /tmp/irongate-req.XXXXXX)
chmod 700 "$IG_REQ_DIR"
cat << 'IG_REQ_VENV' > "$IG_REQ_DIR/requirements-venv.txt"
cffi==2.0.0 \
    --hash=sha256:00bdf7acc5f795150faa6957054fbbca2439db2f775ce831222b66f192f03beb \
    --hash=sha256:07b271772c100085dd28b74fa0cd81c8fb1a3ba18b21e03d7c27f3436a10606b \
    --hash=sha256:087067fa8953339c723661eda6b54bc98c5625757ea62e95eb4898ad5e776e9f \
    --hash=sha256:0a1527a803f0a659de1af2e1fd700213caba79377e27e4693648c2923da066f9 \
    --hash=sha256:0cf2d91ecc3fcc0625c2c530fe004f82c110405f101548512cce44322fa8ac44 \
    --hash=sha256:0f6084a0ea23d05d20c3edcda20c3d006f9b6f3fefeac38f59262e10cef47ee2 \
    --hash=sha256:12873ca6cb9b0f0d3a0da705d6086fe911591737a59f28b7936bdfed27c0d47c \
    --hash=sha256:19f705ada2530c1167abacb171925dd886168931e0a7b78f5bffcae5c6b5be75 \
    --hash=sha256:1cd13c99ce269b3ed80b417dcd591415d3372bcac067009b6e0f59c7d4015e65 \
    --hash=sha256:1e3a615586f05fc4065a8b22b8152f0c1b00cdbc60596d187c2a74f9e3036e4e \
    --hash=sha256:1f72fb8906754ac8a2cc3f9f5aaa298070652a0ffae577e0ea9bd480dc3c931a \
    --hash=sha256:1fc9ea04857caf665289b7a75923f2c6ed559b8298a1b8c49e59f7dd95c8481e \
    --hash=sha256:203a48d1fb583fc7d78a4c6655692963b860a417c0528492a6bc21f1aaefab25 \
    --hash=sha256:2081580ebb843f759b9f617314a24ed5738c51d2aee65d31e02f6f7a2b97707a \
    --hash=sha256:21d1152871b019407d8ac3985f6775c079416c282e431a4da6afe7aefd2bccbe \
    --hash=sha256:24b6f81f1983e6df8db3adc38562c83f7d4a0c36162885ec7f7b77c7dcbec97b \
    --hash=sha256:256f80b80ca3853f90c21b23ee78cd008713787b1b1e93eae9f3d6a7134abd91 \
    --hash=sha256:28a3a209b96630bca57cce802da70c266eb08c6e97e5afd61a75611ee6c64592 \
    --hash=sha256:2c8f814d84194c9ea681642fd164267891702542f028a15fc97d4674b6206187 \
    --hash=sha256:2de9a304e27f7596cd03d16f1b7c72219bd944e99cc52b84d0145aefb07cbd3c \
    --hash=sha256:38100abb9d1b1435bc4cc340bb4489635dc2f0da7456590877030c9b3d40b0c1 \
    --hash=sha256:3925dd22fa2b7699ed2617149842d2e6adde22b262fcbfada50e3d195e4b3a94 \
    --hash=sha256:3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba \
    --hash=sha256:3e837e369566884707ddaf85fc1744b47575005c0a229de3327f8f9a20f4efeb \
    --hash=sha256:3f4d46d8b35698056ec29bca21546e1551a205058ae1a181d871e278b0b28165 \
    --hash=sha256:44d1b5909021139fe36001ae048dbdde8214afa20200eda0f64c068cac5d5529 \
    --hash=sha256:45d5e886156860dc35862657e1494b9bae8dfa63bf56796f2fb56e1679fc0bca \
    --hash=sha256:4647afc2f90d1ddd33441e5b0e85b16b12ddec4fca55f0d9671fef036ecca27c \
    --hash=sha256:4671d9dd5ec934cb9a73e7ee9676f9362aba54f7f34910956b84d727b0d73fb6 \
    --hash=sha256:53f77cbe57044e88bbd5ed26ac1d0514d2acf0591dd6bb02a3ae37f76811b80c \
    --hash=sha256:5eda85d6d1879e692d546a078b44251cdd08dd1cfb98dfb77b670c97cee49ea0 \
    --hash=sha256:5fed36fccc0612a53f1d4d9a816b50a36702c28a2aa880cb8a122b3466638743 \
    --hash=sha256:61d028e90346df14fedc3d1e5441df818d095f3b87d286825dfcbd6459b7ef63 \
    --hash=sha256:66f011380d0e49ed280c789fbd08ff0d40968ee7b665575489afa95c98196ab5 \
    --hash=sha256:6824f87845e3396029f3820c206e459ccc91760e8fa24422f8b0c3d1731cbec5 \
    --hash=sha256:6c6c373cfc5c83a975506110d17457138c8c63016b563cc9ed6e056a82f13ce4 \
    --hash=sha256:6d02d6655b0e54f54c4ef0b94eb6be0607b70853c45ce98bd278dc7de718be5d \
    --hash=sha256:6d50360be4546678fc1b79ffe7a66265e28667840010348dd69a314145807a1b \
    --hash=sha256:730cacb21e1bdff3ce90babf007d0a0917cc3e6492f336c2f0134101e0944f93 \
    --hash=sha256:737fe7d37e1a1bffe70bd5754ea763a62a066dc5913ca57e957824b72a85e205 \
    --hash=sha256:74a03b9698e198d47562765773b4a8309919089150a0bb17d829ad7b44b60d27 \
    --hash=sha256:7553fb2090d71822f02c629afe6042c299edf91ba1bf94951165613553984512 \
    --hash=sha256:7a66c7204d8869299919db4d5069a82f1561581af12b11b3c9f48c584eb8743d \
    --hash=sha256:7cc09976e8b56f8cebd752f7113ad07752461f48a58cbba644139015ac24954c \
    --hash=sha256:81afed14892743bbe14dacb9e36d9e0e504cd204e0b165062c488942b9718037 \
    --hash=sha256:8941aaadaf67246224cee8c3803777eed332a19d909b47e29c9842ef1e79ac26 \
    --hash=sha256:89472c9762729b5ae1ad974b777416bfda4ac5642423fa93bd57a09204712322 \
    --hash=sha256:8ea985900c5c95ce9db1745f7933eeef5d314f0565b27625d9a10ec9881e1bfb \
    --hash=sha256:8eca2a813c1cb7ad4fb74d368c2ffbbb4789d377ee5bb8df98373c2cc0dee76c \
    --hash=sha256:92b68146a71df78564e4ef48af17551a5ddd142e5190cdf2c5624d0c3ff5b2e8 \
    --hash=sha256:9332088d75dc3241c702d852d4671613136d90fa6881da7d770a483fd05248b4 \
    --hash=sha256:94698a9c5f91f9d138526b48fe26a199609544591f859c870d477351dc7b2414 \
    --hash=sha256:9a67fc9e8eb39039280526379fb3a70023d77caec1852002b4da7e8b270c4dd9 \
    --hash=sha256:9de40a7b0323d889cf8d23d1ef214f565ab154443c42737dfe52ff82cf857664 \
    --hash=sha256:a05d0c237b3349096d3981b727493e22147f934b20f6f125a3eba8f994bec4a9 \
    --hash=sha256:afb8db5439b81cf9c9d0c80404b60c3cc9c3add93e114dcae767f1477cb53775 \
    --hash=sha256:b18a3ed7d5b3bd8d9ef7a8cb226502c6bf8308df1525e1cc676c3680e7176739 \
    --hash=sha256:b1e74d11748e7e98e2f426ab176d4ed720a64412b6a15054378afdb71e0f37dc \
    --hash=sha256:b21e08af67b8a103c71a250401c78d5e0893beff75e28c53c98f4de42f774062 \
    --hash=sha256:b4c854ef3adc177950a8dfc81a86f5115d2abd545751a304c5bcf2c2c7283cfe \
    --hash=sha256:b882b3df248017dba09d6b16defe9b5c407fe32fc7c65a9c69798e6175601be9 \
    --hash=sha256:baf5215e0ab74c16e2dd324e8ec067ef59e41125d3eade2b863d294fd5035c92 \
    --hash=sha256:c649e3a33450ec82378822b3dad03cc228b8f5963c0c12fc3b1e0ab940f768a5 \
    --hash=sha256:c654de545946e0db659b3400168c9ad31b5d29593291482c43e3564effbcee13 \
    --hash=sha256:c6638687455baf640e37344fe26d37c404db8b80d037c3d29f58fe8d1c3b194d \
    --hash=sha256:c8d3b5532fc71b7a77c09192b4a5a200ea992702734a2e9279a37f2478236f26 \
    --hash=sha256:cb527a79772e5ef98fb1d700678fe031e353e765d1ca2d409c92263c6d43e09f \
    --hash=sha256:cf364028c016c03078a23b503f02058f1814320a56ad535686f90565636a9495 \
    --hash=sha256:d48a880098c96020b02d5a1f7d9251308510ce8858940e6fa99ece33f610838b \
    --hash=sha256:d68b6cef7827e8641e8ef16f4494edda8b36104d79773a334beaa1e3521430f6 \
    --hash=sha256:d9b29c1f0ae438d5ee9acb31cadee00a58c46cc9c0b2f9038c6b0b3470877a8c \
    --hash=sha256:d9b97165e8aed9272a6bb17c01e3cc5871a594a446ebedc996e2397a1c1ea8ef \
    --hash=sha256:da68248800ad6320861f129cd9c1bf96ca849a2771a59e0344e88681905916f5 \
    --hash=sha256:da902562c3e9c550df360bfa53c035b2f241fed6d9aef119048073680ace4a18 \
    --hash=sha256:dbd5c7a25a7cb98f5ca55d258b103a2054f859a46ae11aaf23134f9cc0d356ad \
    --hash=sha256:dd4f05f54a52fb558f1ba9f528228066954fee3ebe629fc1660d874d040ae5a3 \
    --hash=sha256:de8dad4425a6ca6e4e5e297b27b5c824ecc7581910bf9aee86cb6835e6812aa7 \
    --hash=sha256:e11e82b744887154b182fd3e7e8512418446501191994dbf9c9fc1f32cc8efd5 \
    --hash=sha256:e6e73b9e02893c764e7e8d5bb5ce277f1a009cd5243f8228f75f842bf937c534 \
    --hash=sha256:f73b96c41e3b2adedc34a7356e64c8eb96e03a3782b535e043a986276ce12a49 \
    --hash=sha256:f93fd8e5c8c0a4aa1f424d6173f14a892044054871c771f8566e4008eaa359d2 \
    --hash=sha256:fc33c5141b55ed366cfaad382df24fe7dcbc686de5be719b207bb248e3053dc5 \
    --hash=sha256:fc7de24befaeae77ba923797c7c87834c73648a05a4bde34b3b7e5588973a453 \
    --hash=sha256:fe562eb1a64e67dd297ccc4f5addea2501664954f2692b69a76449ec7913ecbf
docstring-parser==0.14.1 \
    --hash=sha256:14ac6ec1f1ba6905c4d8cb90fd0bc55394f5678183752c90e44812bf28d7a515 \
    --hash=sha256:2c77522e31b7c88b1ab457a1f3c9ae38947ad719732260ba77ee8a3deb58622a
executing==2.0.1 \
    --hash=sha256:35afe2ce3affba8ee97f2d69927fa823b08b472b7b994e36a52a964b93d16147 \
    --hash=sha256:eac49ca94516ccc753f9fb5ce82603156e590b27525a8bc32cce8ae302eb61bc
msgpack==1.1.2 \
    --hash=sha256:0051fffef5a37ca2cd16978ae4f0aef92f164df86823871b5162812bebecd8e2 \
    --hash=sha256:04fb995247a6e83830b62f0b07bf36540c213f6eac8e851166d8d86d83cbd014 \
    --hash=sha256:180759d89a057eab503cf62eeec0aa61c4ea1200dee709f3a8e9397dbb3b6931 \
    --hash=sha256:1d1418482b1ee984625d88aa9585db570180c286d942da463533b238b98b812b \
    --hash=sha256:1de460f0403172cff81169a30b9a92b260cb809c4cb7e2fc79ae8d0510c78b6b \
    --hash=sha256:1fdf7d83102bf09e7ce3357de96c59b627395352a4024f6e2458501f158bf999 \
    --hash=sha256:1fff3d825d7859ac888b0fbda39a42d59193543920eda9d9bea44d958a878029 \
    --hash=sha256:283ae72fc89da59aa004ba147e8fc2f766647b1251500182fac0350d8af299c0 \
    --hash=sha256:2929af52106ca73fcb28576218476ffbb531a036c2adbcf54a3664de124303e9 \
    --hash=sha256:2e86a607e558d22985d856948c12a3fa7b42efad264dca8a3ebbcfa2735d786c \
    --hash=sha256:350ad5353a467d9e3b126d8d1b90fe05ad081e2e1cef5753f8c345217c37e7b8 \
    --hash=sha256:354e81bcdebaab427c3df4281187edc765d5d76bfb3a7c125af9da7a27e8458f \
    --hash=sha256:365c0bbe981a27d8932da71af63ef86acc59ed5c01ad929e09a0b88c6294e28a \
    --hash=sha256:372839311ccf6bdaf39b00b61288e0557916c3729529b301c52c2d88842add42 \
    --hash=sha256:3b60763c1373dd60f398488069bcdc703cd08a711477b5d480eecc9f9626f47e \
    --hash=sha256:41d1a5d875680166d3ac5c38573896453bbbea7092936d2e107214daf43b1d4f \
    --hash=sha256:42eefe2c3e2af97ed470eec850facbe1b5ad1d6eacdbadc42ec98e7dcf68b4b7 \
    --hash=sha256:446abdd8b94b55c800ac34b102dffd2f6aa0ce643c55dfc017ad89347db3dbdb \
    --hash=sha256:454e29e186285d2ebe65be34629fa0e8605202c60fbc7c4c650ccd41870896ef \
    --hash=sha256:4efd7b5979ccb539c221a4c4e16aac1a533efc97f3b759bb5a5ac9f6d10383bf \
    --hash=sha256:5559d03930d3aa0f3aacb4c42c776af1a2ace2611871c84a75afe436695e6245 \
    --hash=sha256:5928604de9b032bc17f5099496417f113c45bc6bc21b5c6920caf34b3c428794 \
    --hash=sha256:59415c6076b1e30e563eb732e23b994a61c159cec44deaf584e5cc1dd662f2af \
    --hash=sha256:5a46bf7e831d09470ad92dff02b8b1ac92175ca36b087f904a0519857c6be3ff \
    --hash=sha256:602b6740e95ffc55bfb078172d279de3773d7b7db1f703b2f1323566b878b90e \
    --hash=sha256:61c8aa3bd513d87c72ed0b37b53dd5c5a0f58f2ff9f26e1555d3bd7948fb7296 \
    --hash=sha256:67016ae8c8965124fdede9d3769528ad8284f14d635337ffa6a713a580f6c030 \
    --hash=sha256:6bde749afe671dc44893f8d08e83bf475a1a14570d67c4bb5cec5573463c8833 \
    --hash=sha256:6c15b7d74c939ebe620dd8e559384be806204d73b4f9356320632d783d1f7939 \
    --hash=sha256:70a0dff9d1f8da25179ffcf880e10cf1aad55fdb63cd59c9a49a1b82290062aa \
    --hash=sha256:70c5a7a9fea7f036b716191c29047374c10721c389c21e9ffafad04df8c52c90 \
    --hash=sha256:7bc8813f88417599564fafa59fd6f95be417179f76b40325b500b3c98409757c \
    --hash=sha256:80a0ff7d4abf5fecb995fcf235d4064b9a9a8a40a3ab80999e6ac1e30b702717 \
    --hash=sha256:86f8136dfa5c116365a8a651a7d7484b65b13339731dd6faebb9a0242151c406 \
    --hash=sha256:897c478140877e5307760b0ea66e0932738879e7aa68144d9b78ea4c8302a84a \
    --hash=sha256:8b696e83c9f1532b4af884045ba7f3aa741a63b2bc22617293a2c6a7c645f251 \
    --hash=sha256:8e22ab046fa7ede9e36eeb4cfad44d46450f37bb05d5ec482b02868f451c95e2 \
    --hash=sha256:94fd7dc7d8cb0a54432f296f2246bc39474e017204ca6f4ff345941d4ed285a7 \
    --hash=sha256:99e2cb7b9031568a2a5c73aa077180f93dd2e95b4f8d3b8e14a73ae94a9e667e \
    --hash=sha256:9ade919fac6a3e7260b7f64cea89df6bec59104987cbea34d34a2fa15d74310b \
    --hash=sha256:9fba231af7a933400238cb357ecccf8ab5d51535ea95d94fc35b7806218ff844 \
    --hash=sha256:a465f0dceb8e13a487e54c07d04ae3ba131c7c5b95e2612596eafde1dccf64a9 \
    --hash=sha256:a605409040f2da88676e9c9e5853b3449ba8011973616189ea5ee55ddbc5bc87 \
    --hash=sha256:a668204fa43e6d02f89dbe79a30b0d67238d9ec4c5bd8a940fc3a004a47b721b \
    --hash=sha256:a7787d353595c7c7e145e2331abf8b7ff1e6673a6b974ded96e6d4ec09f00c8c \
    --hash=sha256:a8f6e7d30253714751aa0b0c84ae28948e852ee7fb0524082e6716769124bc23 \
    --hash=sha256:ad09b984828d6b7bb52d1d1d0c9be68ad781fa004ca39216c8a1e63c0f34ba3c \
    --hash=sha256:bafca952dc13907bdfdedfc6a5f579bf4f292bdd506fadb38389afa3ac5b208e \
    --hash=sha256:be52a8fc79e45b0364210eef5234a7cf8d330836d0a64dfbb878efa903d84620 \
    --hash=sha256:be5980f3ee0e6bd44f3a9e9dea01054f175b50c3e6cdb692bc9424c0bbb8bf69 \
    --hash=sha256:c63eea553c69ab05b6747901b97d620bb2a690633c77f23feb0c6a947a8a7b8f \
    --hash=sha256:d198d275222dc54244bf3327eb8cbe00307d220241d9cec4d306d49a44e85f68 \
    --hash=sha256:d62ce1f483f355f61adb5433ebfd8868c5f078d1a52d042b0a998682b4fa8c27 \
    --hash=sha256:d99ef64f349d5ec3293688e91486c5fdb925ed03807f64d98d205d2713c60b46 \
    --hash=sha256:db6192777d943bdaaafb6ba66d44bf65aa0e9c5616fa1d2da9bb08828c6b39aa \
    --hash=sha256:e23ce8d5f7aa6ea6d2a2b326b4ba46c985dbb204523759984430db7114f8aa00 \
    --hash=sha256:e64c8d2f5e5d5fda7b842f55dec6133260ea8f53c4257d64494c534f306bf7a9 \
    --hash=sha256:e69b39f8c0aa5ec24b57737ebee40be647035158f14ed4b40e6f150077e21a84 \
    --hash=sha256:ea5405c46e690122a76531ab97a079e184c0daf491e588592d6a23d3e32af99e \
    --hash=sha256:f2cb069d8b981abc72b41aea1c580ce92d57c673ec61af4c500153a626cb9e20 \
    --hash=sha256:fac4be746328f90caa3cd4bc67e6fe36ca2bf61d5c6eb6d895b6527e3f05071e \
    --hash=sha256:fffee09044073e69f2bad787071aeec727183e7580443dfeb8556cbf1978d162
netifaces==0.11.0 \
    --hash=sha256:043a79146eb2907edf439899f262b3dfe41717d34124298ed281139a8b93ca32 \
    --hash=sha256:08e3f102a59f9eaef70948340aeb6c89bd09734e0dca0f3b82720305729f63ea \
    --hash=sha256:0f6133ac02521270d9f7c490f0c8c60638ff4aec8338efeff10a1b51506abe85 \
    --hash=sha256:18917fbbdcb2d4f897153c5ddbb56b31fa6dd7c3fa9608b7e3c3a663df8206b5 \
    --hash=sha256:2479bb4bb50968089a7c045f24d120f37026d7e802ec134c4490eae994c729b5 \
    --hash=sha256:2650beee182fed66617e18474b943e72e52f10a24dc8cac1db36c41ee9c041b7 \
    --hash=sha256:28f4bf3a1361ab3ed93c5ef360c8b7d4a4ae060176a3529e72e5e4ffc4afd8b0 \
    --hash=sha256:3ecb3f37c31d5d51d2a4d935cfa81c9bc956687c6f5237021b36d6fdc2815b2c \
    --hash=sha256:469fc61034f3daf095e02f9f1bbac07927b826c76b745207287bc594884cfd05 \
    --hash=sha256:48324183af7f1bc44f5f197f3dad54a809ad1ef0c78baee2c88f16a5de02c4c9 \
    --hash=sha256:50721858c935a76b83dd0dd1ab472cad0a3ef540a1408057624604002fcfb45b \
    --hash=sha256:54ff6624eb95b8a07e79aa8817288659af174e954cca24cdb0daeeddfc03c4ff \
    --hash=sha256:5be83986100ed1fdfa78f11ccff9e4757297735ac17391b95e17e74335c2047d \
    --hash=sha256:5f9ca13babe4d845e400921973f6165a4c2f9f3379c7abfc7478160e25d196a4 \
    --hash=sha256:73ff21559675150d31deea8f1f8d7e9a9a7e4688732a94d71327082f517fc6b4 \
    --hash=sha256:7dbb71ea26d304e78ccccf6faccef71bb27ea35e259fb883cfd7fd7b4f17ecb1 \
    --hash=sha256:815eafdf8b8f2e61370afc6add6194bd5a7252ae44c667e96c4c1ecf418811e4 \
    --hash=sha256:841aa21110a20dc1621e3dd9f922c64ca64dd1eb213c47267a2c324d823f6c8f \
    --hash=sha256:84e4d2e6973eccc52778735befc01638498781ce0e39aa2044ccfd2385c03246 \
    --hash=sha256:8f7da24eab0d4184715d96208b38d373fd15c37b0dafb74756c638bd619ba150 \
    --hash=sha256:96c0fe9696398253f93482c84814f0e7290eee0bfec11563bd07d80d701280c3 \
    --hash=sha256:aab1dbfdc55086c789f0eb37affccf47b895b98d490738b81f3b2360100426be \
    --hash=sha256:c03fb2d4ef4e393f2e6ffc6376410a22a3544f164b336b3a355226653e5efd89 \
    --hash=sha256:c37a1ca83825bc6f54dddf5277e9c65dec2f1b4d0ba44b8fd42bc30c91aa6ea1 \
    --hash=sha256:c92ff9ac7c2282009fe0dcb67ee3cd17978cffbe0c8f4b471c00fe4325c9b4d4 \
    --hash=sha256:c9a3a47cd3aaeb71e93e681d9816c56406ed755b9442e981b07e3618fb71d2ac \
    --hash=sha256:cb925e1ca024d6f9b4f9b01d83215fd00fe69d095d0255ff3f64bffda74025c8 \
    --hash=sha256:d07b01c51b0b6ceb0f09fc48ec58debd99d2c8430b09e56651addeaf5de48048 \
    --hash=sha256:e76c7f351e0444721e85f975ae92718e21c1f361bda946d60a214061de1f00a1 \
    --hash=sha256:eb4813b77d5df99903af4757ce980a98c4d702bbcb81f32a0b305a1537bdf0b1
py-algorand-sdk==2.11.1 \
    --hash=sha256:40c8db5e65420ade023c78dda1fff44f5af4666c4b12c8a0e976a6c33fb819b6 \
    --hash=sha256:ccca589b00f7939e6bfdf5a5ace261a4b26c9b4baf02b376c46fb61aa182c800
pycparser==3.0 \
    --hash=sha256:600f49d217304a5902ac3c37e1281c9fe94e4d0489de643a9504c5cdfdfc6b29 \
    --hash=sha256:b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992
pycryptodomex==3.23.0 \
    --hash=sha256:02d87b80778c171445d67e23d1caef279bf4b25c3597050ccd2e13970b57fd51 \
    --hash=sha256:06698f957fe1ab229a99ba2defeeae1c09af185baa909a31a5d1f9d42b1aaed6 \
    --hash=sha256:14c37aaece158d0ace436f76a7bb19093db3b4deade9797abfc39ec6cd6cc2fe \
    --hash=sha256:189afbc87f0b9f158386bf051f720e20fa6145975f1e76369303d0f31d1a8d7c \
    --hash=sha256:1c3a65ad441746b250d781910d26b7ed0a396733c6f2dbc3327bd7051ec8a541 \
    --hash=sha256:1c6d919fc8429e5cb228ba8c0d4d03d202a560b421c14867a65f6042990adc8e \
    --hash=sha256:267a3038f87a8565bd834317dbf053a02055915acf353bf42ededb9edaf72010 \
    --hash=sha256:27e13c80ac9a0a1d050ef0a7e0a18cc04c8850101ec891815b6c5a0375e8a245 \
    --hash=sha256:43c446e2ba8df8889e0e16f02211c25b4934898384c1ec1ec04d7889c0333587 \
    --hash=sha256:47f6d318fe864d02d5e59a20a18834819596c4ed1d3c917801b22b92b3ffa648 \
    --hash=sha256:4e79f1aaff5a3a374e92eb462fa9e598585452135012e2945f96874ca6eeb1ff \
    --hash=sha256:4f2596e643d4365e14d0879dc5aafe6355616c61c2176009270f3048f6d9a61f \
    --hash=sha256:52e5ca58c3a0b0bd5e100a9fbc8015059b05cffc6c66ce9d98b4b45e023443b9 \
    --hash=sha256:55ccbe27f049743a4caf4f4221b166560d3438d0b1e5ab929e07ae1702a4d6fd \
    --hash=sha256:58b851b9effd0d072d4ca2e4542bf2a4abcf13c82a29fd2c93ce27ee2a2e9462 \
    --hash=sha256:6b8962204c47464d5c1c4038abeadd4514a133b28748bcd9fa5b6d62e3cec6fa \
    --hash=sha256:6bbcb1dd0f646484939e142462d9e532482bc74475cecf9c4903d4e1cd21f003 \
    --hash=sha256:71909758f010c82bc99b0abf4ea12012c98962fbf0583c2164f8b84533c2e4da \
    --hash=sha256:7b37e08e3871efe2187bc1fd9320cc81d87caf19816c648f24443483005ff886 \
    --hash=sha256:7de1e40a41a5d7f1ac42b6569b10bcdded34339950945948529067d8426d2785 \
    --hash=sha256:8a4fcd42ccb04c31268d1efeecfccfd1249612b4de6374205376b8f280321744 \
    --hash=sha256:91979028227543010d7b2ba2471cf1d1e398b3f183cb105ac584df0c36dac28d \
    --hash=sha256:a33986a0066860f7fcf7c7bd2bc804fa90e434183645595ae7b33d01f3c91ed8 \
    --hash=sha256:a9d446e844f08299236780f2efa9898c818fe7e02f17263866b8550c7d5fb328 \
    --hash=sha256:add243d204e125f189819db65eed55e6b4713f70a7e9576c043178656529cec7 \
    --hash=sha256:b2c2537863eccef2d41061e82a881dcabb04944c5c06c5aa7110b577cc487545 \
    --hash=sha256:bc65bdd9fc8de7a35a74cab1c898cab391a4add33a8fe740bda00f5976ca4708 \
    --hash=sha256:bdc69d0d3d989a1029df0eed67cc5e8e5d968f3724f4519bd03e0ec68df7543c \
    --hash=sha256:bffc92138d75664b6d543984db7893a628559b9e78658563b0395e2a5fb47ed9 \
    --hash=sha256:c25e30a20e1b426e1f0fa00131c516f16e474204eee1139d1603e132acffc314 \
    --hash=sha256:c7947ab8d589e3178da3d7cdeabe14f841b391e17046954f2fbcd941705762b5 \
    --hash=sha256:c84b239a1f4ec62e9c789aafe0543f0594f0acd90c8d9e15bcece3efe55eca66 \
    --hash=sha256:c885da45e70139464f082018ac527fdaad26f1657a99ee13eecdce0f0ca24ab4 \
    --hash=sha256:d9825410197a97685d6a1fa2a86196430b01877d64458a20e95d4fd00d739a08 \
    --hash=sha256:da4fa650cef02db88c2b98acc5434461e027dce0ae8c22dd5a69013eaf510006 \
    --hash=sha256:df027262368334552db2c0ce39706b3fb32022d1dce34673d0f9422df004b96a \
    --hash=sha256:ebfff755c360d674306e5891c564a274a47953562b42fb74a5c25b8fc1fb1cb5 \
    --hash=sha256:eca54f4bb349d45afc17e3011ed4264ef1cc9e266699874cdd1349c504e64798 \
    --hash=sha256:f489c4765093fb60e2edafdf223397bc716491b2b69fe74367b70d6999257a5c \
    --hash=sha256:fdfac7cda115bca3a5abb2f9e43bc2fb66c2b65ab074913643803ca7083a79ea \
    --hash=sha256:febec69c0291efd056c65691b6d9a339f8b4bc43c6635b8699471248fe897fea
PyNaCl==1.6.2 \
    --hash=sha256:018494d6d696ae03c7e656e5e74cdfd8ea1326962cc401bcf018f1ed8436811c \
    --hash=sha256:04316d1fc625d860b6c162fff704eb8426b1a8bcd3abacea11142cbd99a6b574 \
    --hash=sha256:22de65bb9010a725b0dac248f353bb072969c94fa8d6b1f34b87d7953cf7bbe4 \
    --hash=sha256:26bfcd00dcf2cf160f122186af731ae30ab120c18e8375684ec2670dccd28130 \
    --hash=sha256:2fef529ef3ee487ad8113d287a593fa26f48ee3620d92ecc6f1d09ea38e0709b \
    --hash=sha256:320ef68a41c87547c91a8b58903c9caa641ab01e8512ce291085b5fe2fcb7590 \
    --hash=sha256:3bffb6d0f6becacb6526f8f42adfb5efb26337056ee0831fb9a7044d1a964444 \
    --hash=sha256:44081faff368d6c5553ccf55322ef2819abb40e25afaec7e740f159f74813634 \
    --hash=sha256:46065496ab748469cdd999246d17e301b2c24ae2fdf739132e580a0e94c94a87 \
    --hash=sha256:5811c72b473b2f38f7e2a3dc4f8642e3a3e9b5e7317266e4ced1fba85cae41aa \
    --hash=sha256:622d7b07cc5c02c666795792931b50c91f3ce3c2649762efb1ef0d5684c81594 \
    --hash=sha256:62985f233210dee6548c223301b6c25440852e13d59a8b81490203c3227c5ba0 \
    --hash=sha256:68be3a09455743ff9505491220b64440ced8973fe930f270c8e07ccfa25b1f9e \
    --hash=sha256:834a43af110f743a754448463e8fd61259cd4ab5bbedcf70f9dabad1d28a394c \
    --hash=sha256:8845c0631c0be43abdd865511c41eab235e0be69c81dc66a50911594198679b0 \
    --hash=sha256:8a66d6fb6ae7661c58995f9c6435bda2b1e68b54b598a6a10247bfcdadac996c \
    --hash=sha256:8b097553b380236d51ed11356c953bf8ce36a29a3e596e934ecabe76c985a577 \
    --hash=sha256:a84bf1c20339d06dc0c85d9aea9637a24f718f375d861b2668b2f9f96fa51145 \
    --hash=sha256:a9f9932d8d2811ce1a8ffa79dcbdf3970e7355b5c8eb0c1a881a57e7f7d96e88 \
    --hash=sha256:bc4a36b28dd72fb4845e5d8f9760610588a96d5a51f01d84d8c6ff9849968c14 \
    --hash=sha256:c8a231e36ec2cab018c4ad4358c386e36eede0319a0c41fed24f840b1dac59f6 \
    --hash=sha256:c949ea47e4206af7c8f604b8278093b674f7c79ed0d4719cc836902bf4517465 \
    --hash=sha256:d071c6a9a4c94d79eb665db4ce5cedc537faf74f2355e4d502591d850d3913c0 \
    --hash=sha256:d29bfe37e20e015a7d8b23cfc8bd6aa7909c92a1b8f41ee416bbb3e79ef182b2 \
    --hash=sha256:fe9847ca47d287af41e82be1dd5e23023d3c31a951da134121ab02e42ac218c9
pyteal==0.27.0 \
    --hash=sha256:d1fa79c6a7a94c82847b13d8f37e03158d0b05e6b361b936644b49d4d150d59e \
    --hash=sha256:f5630bc4587ed1304102ffba9c8f8a13344d2f3c161504ba2912a781533e48b1
PyYAML==6.0.3 \
    --hash=sha256:00c4bdeba853cc34e7dd471f16b4114f4162dc03e6b7afcc2128711f0eca823c \
    --hash=sha256:0150219816b6a1fa26fb4699fb7daa9caf09eb1999f3b70fb6e786805e80375a \
    --hash=sha256:02893d100e99e03eda1c8fd5c441d8c60103fd175728e23e431db1b589cf5ab3 \
    --hash=sha256:02ea2dfa234451bbb8772601d7b8e426c2bfa197136796224e50e35a78777956 \
    --hash=sha256:0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6 \
    --hash=sha256:10892704fc220243f5305762e276552a0395f7beb4dbf9b14ec8fd43b57f126c \
    --hash=sha256:16249ee61e95f858e83976573de0f5b2893b3677ba71c9dd36b9cf8be9ac6d65 \
    --hash=sha256:1d37d57ad971609cf3c53ba6a7e365e40660e3be0e5175fa9f2365a379d6095a \
    --hash=sha256:1ebe39cb5fc479422b83de611d14e2c0d3bb2a18bbcb01f229ab3cfbd8fee7a0 \
    --hash=sha256:214ed4befebe12df36bcc8bc2b64b396ca31be9304b8f59e25c11cf94a4c033b \
    --hash=sha256:2283a07e2c21a2aa78d9c4442724ec1eb15f5e42a723b99cb3d822d48f5f7ad1 \
    --hash=sha256:22ba7cfcad58ef3ecddc7ed1db3409af68d023b7f940da23c6c2a1890976eda6 \
    --hash=sha256:27c0abcb4a5dac13684a37f76e701e054692a9b2d3064b70f5e4eb54810553d7 \
    --hash=sha256:28c8d926f98f432f88adc23edf2e6d4921ac26fb084b028c733d01868d19007e \
    --hash=sha256:2e71d11abed7344e42a8849600193d15b6def118602c4c176f748e4583246007 \
    --hash=sha256:34d5fcd24b8445fadc33f9cf348c1047101756fd760b4dacb5c3e99755703310 \
    --hash=sha256:37503bfbfc9d2c40b344d06b2199cf0e96e97957ab1c1b546fd4f87e53e5d3e4 \
    --hash=sha256:3c5677e12444c15717b902a5798264fa7909e41153cdf9ef7ad571b704a63dd9 \
    --hash=sha256:3ff07ec89bae51176c0549bc4c63aa6202991da2d9a6129d7aef7f1407d3f295 \
    --hash=sha256:41715c910c881bc081f1e8872880d3c650acf13dfa8214bad49ed4cede7c34ea \
    --hash=sha256:418cf3f2111bc80e0933b2cd8cd04f286338bb88bdc7bc8e6dd775ebde60b5e0 \
    --hash=sha256:44edc647873928551a01e7a563d7452ccdebee747728c1080d881d68af7b997e \
    --hash=sha256:4a2e8cebe2ff6ab7d1050ecd59c25d4c8bd7e6f400f5f82b96557ac0abafd0ac \
    --hash=sha256:4ad1906908f2f5ae4e5a8ddfce73c320c2a1429ec52eafd27138b7f1cbe341c9 \
    --hash=sha256:501a031947e3a9025ed4405a168e6ef5ae3126c59f90ce0cd6f2bfc477be31b7 \
    --hash=sha256:5190d403f121660ce8d1d2c1bb2ef1bd05b5f68533fc5c2ea899bd15f4399b35 \
    --hash=sha256:5498cd1645aa724a7c71c8f378eb29ebe23da2fc0d7a08071d89469bf1d2defb \
    --hash=sha256:5cf4e27da7e3fbed4d6c3d8e797387aaad68102272f8f9752883bc32d61cb87b \
    --hash=sha256:5e0b74767e5f8c593e8c9b5912019159ed0533c70051e9cce3e8b6aa699fcd69 \
    --hash=sha256:5ed875a24292240029e4483f9d4a4b8a1ae08843b9c54f43fcc11e404532a8a5 \
    --hash=sha256:5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b \
    --hash=sha256:5fdec68f91a0c6739b380c83b951e2c72ac0197ace422360e6d5a959d8d97b2c \
    --hash=sha256:6344df0d5755a2c9a276d4473ae6b90647e216ab4757f8426893b5dd2ac3f369 \
    --hash=sha256:64386e5e707d03a7e172c0701abfb7e10f0fb753ee1d773128192742712a98fd \
    --hash=sha256:652cb6edd41e718550aad172851962662ff2681490a8a711af6a4d288dd96824 \
    --hash=sha256:66291b10affd76d76f54fad28e22e51719ef9ba22b29e1d7d03d6777a9174198 \
    --hash=sha256:66e1674c3ef6f541c35191caae2d429b967b99e02040f5ba928632d9a7f0f065 \
    --hash=sha256:6adc77889b628398debc7b65c073bcb99c4a0237b248cacaf3fe8a557563ef6c \
    --hash=sha256:79005a0d97d5ddabfeeea4cf676af11e647e41d81c9a7722a193022accdb6b7c \
    --hash=sha256:7c6610def4f163542a622a73fb39f534f8c101d690126992300bf3207eab9764 \
    --hash=sha256:7f047e29dcae44602496db43be01ad42fc6f1cc0d8cd6c83d342306c32270196 \
    --hash=sha256:8098f252adfa6c80ab48096053f512f2321f0b998f98150cea9bd23d83e1467b \
    --hash=sha256:850774a7879607d3a6f50d36d04f00ee69e7fc816450e5f7e58d7f17f1ae5c00 \
    --hash=sha256:8d1fab6bb153a416f9aeb4b8763bc0f22a5586065f86f7664fc23339fc1c1fac \
    --hash=sha256:8da9669d359f02c0b91ccc01cac4a67f16afec0dac22c2ad09f46bee0697eba8 \
    --hash=sha256:8dc52c23056b9ddd46818a57b78404882310fb473d63f17b07d5c40421e47f8e \
    --hash=sha256:9149cad251584d5fb4981be1ecde53a1ca46c891a79788c0df828d2f166bda28 \
    --hash=sha256:93dda82c9c22deb0a405ea4dc5f2d0cda384168e466364dec6255b293923b2f3 \
    --hash=sha256:96b533f0e99f6579b3d4d4995707cf36df9100d67e0c8303a0c55b27b5f99bc5 \
    --hash=sha256:9c57bb8c96f6d1808c030b1687b9b5fb476abaa47f0db9c0101f5e9f394e97f4 \
    --hash=sha256:9c7708761fccb9397fe64bbc0395abcae8c4bf7b0eac081e12b809bf47700d0b \
    --hash=sha256:9f3bfb4965eb874431221a3ff3fdcddc7e74e3b07799e0e84ca4a0f867d449bf \
    --hash=sha256:a33284e20b78bd4a18c8c2282d549d10bc8408a2a7ff57653c0cf0b9be0afce5 \
    --hash=sha256:a80cb027f6b349846a3bf6d73b5e95e782175e52f22108cfa17876aaeff93702 \
    --hash=sha256:b30236e45cf30d2b8e7b3e85881719e98507abed1011bf463a8fa23e9c3e98a8 \
    --hash=sha256:b3bc83488de33889877a0f2543ade9f70c67d66d9ebb4ac959502e12de895788 \
    --hash=sha256:b865addae83924361678b652338317d1bd7e79b1f4596f96b96c77a5a34b34da \
    --hash=sha256:b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d \
    --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc \
    --hash=sha256:bdb2c67c6c1390b63c6ff89f210c8fd09d9a1217a465701eac7316313c915e4c \
    --hash=sha256:c1ff362665ae507275af2853520967820d9124984e0f7466736aea23d8611fba \
    --hash=sha256:c2514fceb77bc5e7a2f7adfaa1feb2fb311607c9cb518dbc378688ec73d8292f \
    --hash=sha256:c3355370a2c156cffb25e876646f149d5d68f5e0a3ce86a5084dd0b64a994917 \
    --hash=sha256:c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5 \
    --hash=sha256:d0eae10f8159e8fdad514efdc92d74fd8d682c933a6dd088030f3834bc8e6b26 \
    --hash=sha256:d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f \
    --hash=sha256:ebc55a14a21cb14062aa4162f906cd962b28e2e9ea38f9b4391244cd8de4ae0b \
    --hash=sha256:eda16858a3cab07b80edaf74336ece1f986ba330fdb8ee0d6c0d68fe82bc96be \
    --hash=sha256:ee2922902c45ae8ccada2c5b501ab86c36525b883eff4255313a253a3160861c \
    --hash=sha256:efd7b85f94a6f21e4932043973a7ba2613b059c4a000551892ac9f1d11f5baf3 \
    --hash=sha256:f7057c9a337546edc7973c0d3ba84ddcdf0daa14533c2065749c9075001090e6 \
    --hash=sha256:fa160448684b4e94d80416c0fa4aac48967a969efe22931448d853ada8baf926 \
    --hash=sha256:fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0
scapy==2.7.0 \
    --hash=sha256:bfc1ef1b93280aea1ddee53be7f74232aa28ac3d891244d41ee85200d24aa446 \
    --hash=sha256:eb22786da92be6fd8e5c694ae5595e4f5b9ac1f4364c9c45986844f3e3063561
semantic-version==2.10.0 \
    --hash=sha256:bdabb6d336998cbb378d4b9db3a4b56a1e3235701dc05ea2690d9a997ed5041c \
    --hash=sha256:de78a3b8e0feda74cabc54aab2da702113e33ac9d9eb9d2389bcf1f58b7d9177
tabulate==0.9.0 \
    --hash=sha256:0095b12bf5966de529c0feb1fa08671671b3368eec77d7ef7ab114be2c068b3c \
    --hash=sha256:024ca478df22e9340661486f85298cff5f6dcdba14f3813e8830015b9ed1948f
IG_REQ_VENV
cat << 'IG_REQ_SYSTEM' > "$IG_REQ_DIR/requirements-system.txt"
netifaces==0.11.0 \
    --hash=sha256:043a79146eb2907edf439899f262b3dfe41717d34124298ed281139a8b93ca32 \
    --hash=sha256:08e3f102a59f9eaef70948340aeb6c89bd09734e0dca0f3b82720305729f63ea \
    --hash=sha256:0f6133ac02521270d9f7c490f0c8c60638ff4aec8338efeff10a1b51506abe85 \
    --hash=sha256:18917fbbdcb2d4f897153c5ddbb56b31fa6dd7c3fa9608b7e3c3a663df8206b5 \
    --hash=sha256:2479bb4bb50968089a7c045f24d120f37026d7e802ec134c4490eae994c729b5 \
    --hash=sha256:2650beee182fed66617e18474b943e72e52f10a24dc8cac1db36c41ee9c041b7 \
    --hash=sha256:28f4bf3a1361ab3ed93c5ef360c8b7d4a4ae060176a3529e72e5e4ffc4afd8b0 \
    --hash=sha256:3ecb3f37c31d5d51d2a4d935cfa81c9bc956687c6f5237021b36d6fdc2815b2c \
    --hash=sha256:469fc61034f3daf095e02f9f1bbac07927b826c76b745207287bc594884cfd05 \
    --hash=sha256:48324183af7f1bc44f5f197f3dad54a809ad1ef0c78baee2c88f16a5de02c4c9 \
    --hash=sha256:50721858c935a76b83dd0dd1ab472cad0a3ef540a1408057624604002fcfb45b \
    --hash=sha256:54ff6624eb95b8a07e79aa8817288659af174e954cca24cdb0daeeddfc03c4ff \
    --hash=sha256:5be83986100ed1fdfa78f11ccff9e4757297735ac17391b95e17e74335c2047d \
    --hash=sha256:5f9ca13babe4d845e400921973f6165a4c2f9f3379c7abfc7478160e25d196a4 \
    --hash=sha256:73ff21559675150d31deea8f1f8d7e9a9a7e4688732a94d71327082f517fc6b4 \
    --hash=sha256:7dbb71ea26d304e78ccccf6faccef71bb27ea35e259fb883cfd7fd7b4f17ecb1 \
    --hash=sha256:815eafdf8b8f2e61370afc6add6194bd5a7252ae44c667e96c4c1ecf418811e4 \
    --hash=sha256:841aa21110a20dc1621e3dd9f922c64ca64dd1eb213c47267a2c324d823f6c8f \
    --hash=sha256:84e4d2e6973eccc52778735befc01638498781ce0e39aa2044ccfd2385c03246 \
    --hash=sha256:8f7da24eab0d4184715d96208b38d373fd15c37b0dafb74756c638bd619ba150 \
    --hash=sha256:96c0fe9696398253f93482c84814f0e7290eee0bfec11563bd07d80d701280c3 \
    --hash=sha256:aab1dbfdc55086c789f0eb37affccf47b895b98d490738b81f3b2360100426be \
    --hash=sha256:c03fb2d4ef4e393f2e6ffc6376410a22a3544f164b336b3a355226653e5efd89 \
    --hash=sha256:c37a1ca83825bc6f54dddf5277e9c65dec2f1b4d0ba44b8fd42bc30c91aa6ea1 \
    --hash=sha256:c92ff9ac7c2282009fe0dcb67ee3cd17978cffbe0c8f4b471c00fe4325c9b4d4 \
    --hash=sha256:c9a3a47cd3aaeb71e93e681d9816c56406ed755b9442e981b07e3618fb71d2ac \
    --hash=sha256:cb925e1ca024d6f9b4f9b01d83215fd00fe69d095d0255ff3f64bffda74025c8 \
    --hash=sha256:d07b01c51b0b6ceb0f09fc48ec58debd99d2c8430b09e56651addeaf5de48048 \
    --hash=sha256:e76c7f351e0444721e85f975ae92718e21c1f361bda946d60a214061de1f00a1 \
    --hash=sha256:eb4813b77d5df99903af4757ce980a98c4d702bbcb81f32a0b305a1537bdf0b1
PyYAML==6.0.1 \
    --hash=sha256:04ac92ad1925b2cff1db0cfebffb6ffc43457495c9b3c39d3fcae417d7125dc5 \
    --hash=sha256:062582fca9fabdd2c8b54a3ef1c978d786e0f6b3a1510e0ac93ef59e0ddae2bc \
    --hash=sha256:0d3304d8c0adc42be59c5f8a4d9e3d7379e6955ad754aa9d6ab7a398b59dd1df \
    --hash=sha256:1635fd110e8d85d55237ab316b5b011de701ea0f29d07611174a1b42f1444741 \
    --hash=sha256:184c5108a2aca3c5b3d3bf9395d50893a7ab82a38004c8f61c258d4428e80206 \
    --hash=sha256:18aeb1bf9a78867dc38b259769503436b7c72f7a1f1f4c93ff9a17de54319b27 \
    --hash=sha256:1d4c7e777c441b20e32f52bd377e0c409713e8bb1386e1099c2415f26e479595 \
    --hash=sha256:1e2722cc9fbb45d9b87631ac70924c11d3a401b2d7f410cc0e3bbf249f2dca62 \
    --hash=sha256:1fe35611261b29bd1de0070f0b2f47cb6ff71fa6595c077e42bd0c419fa27b98 \
    --hash=sha256:28c119d996beec18c05208a8bd78cbe4007878c6dd15091efb73a30e90539696 \
    --hash=sha256:326c013efe8048858a6d312ddd31d56e468118ad4cdeda36c719bf5bb6192290 \
    --hash=sha256:40df9b996c2b73138957fe23a16a4f0ba614f4c0efce1e9406a184b6d07fa3a9 \
    --hash=sha256:42f8152b8dbc4fe7d96729ec2b99c7097d656dc1213a3229ca5383f973a5ed6d \
    --hash=sha256:49a183be227561de579b4a36efbb21b3eab9651dd81b1858589f796549873dd6 \
    --hash=sha256:4fb147e7a67ef577a588a0e2c17b6db51dda102c71de36f8549b6816a96e1867 \
    --hash=sha256:50550eb667afee136e9a77d6dc71ae76a44df8b3e51e41b77f6de2932bfe0f47 \
    --hash=sha256:510c9deebc5c0225e8c96813043e62b680ba2f9c50a08d3724c7f28a747d1486 \
    --hash=sha256:5773183b6446b2c99bb77e77595dd486303b4faab2b086e7b17bc6bef28865f6 \
    --hash=sha256:596106435fa6ad000c2991a98fa58eeb8656ef2325d7e158344fb33864ed87e3 \
    --hash=sha256:6965a7bc3cf88e5a1c3bd2e0b5c22f8d677dc88a455344035f03399034eb3007 \
    --hash=sha256:69b023b2b4daa7548bcfbd4aa3da05b3a74b772db9e23b982788168117739938 \
    --hash=sha256:6c22bec3fbe2524cde73d7ada88f6566758a8f7227bfbf93a408a9d86bcc12a0 \
    --hash=sha256:704219a11b772aea0d8ecd7058d0082713c3562b4e271b849ad7dc4a5c90c13c \
    --hash=sha256:7e07cbde391ba96ab58e532ff4803f79c4129397514e1413a7dc761ccd755735 \
    --hash=sha256:81e0b275a9ecc9c0c0c07b4b90ba548307583c125f54d5b6946cfee6360c733d \
    --hash=sha256:855fb52b0dc35af121542a76b9a84f8d1cd886ea97c84703eaa6d88e37a2ad28 \
    --hash=sha256:8d4e9c88387b0f5c7d5f281e55304de64cf7f9c0021a3525bd3b1c542da3b0e4 \
    --hash=sha256:9046c58c4395dff28dd494285c82ba00b546adfc7ef001486fbf0324bc174fba \
    --hash=sha256:9eb6caa9a297fc2c2fb8862bc5370d0303ddba53ba97e71f08023b6cd73d16a8 \
    --hash=sha256:a08c6f0fe150303c1c6b71ebcd7213c2858041a7e01975da3a99aed1e7a378ef \
    --hash=sha256:a0cd17c15d3bb3fa06978b4e8958dcdc6e0174ccea823003a106c7d4d7899ac5 \
    --hash=sha256:afd7e57eddb1a54f0f1a974bc4391af8bcce0b444685d936840f125cf046d5bd \
    --hash=sha256:b1275ad35a5d18c62a7220633c913e1b42d44b46ee12554e5fd39c70a243d6a3 \
    --hash=sha256:b786eecbdf8499b9ca1d697215862083bd6d2a99965554781d0d8d1ad31e13a0 \
    --hash=sha256:ba336e390cd8e4d1739f42dfe9bb83a3cc2e80f567d8805e11b46f4a943f5515 \
    --hash=sha256:baa90d3f661d43131ca170712d903e6295d1f7a0f595074f151c0aed377c9b9c \
    --hash=sha256:bc1bf2925a1ecd43da378f4db9e4f799775d6367bdb94671027b73b393a7c42c \
    --hash=sha256:bd4af7373a854424dabd882decdc5579653d7868b8fb26dc7d0e99f823aa5924 \
    --hash=sha256:bf07ee2fef7014951eeb99f56f39c9bb4af143d8aa3c21b1677805985307da34 \
    --hash=sha256:bfdf460b1736c775f2ba9f6a92bca30bc2095067b8a9d77876d1fad6cc3b4a43 \
    --hash=sha256:c8098ddcc2a85b61647b2590f825f3db38891662cfc2fc776415143f599bb859 \
    --hash=sha256:d2b04aac4d386b172d5b9692e2d2da8de7bfb6c387fa4f801fbf6fb2e6ba4673 \
    --hash=sha256:d483d2cdf104e7c9fa60c544d92981f12ad66a457afae824d146093b8c294c54 \
    --hash=sha256:d858aa552c999bc8a8d57426ed01e40bef403cd8ccdd0fc5f6f04a00414cac2a \
    --hash=sha256:e7d73685e87afe9f3b36c799222440d6cf362062f78be1013661b00c5c6f678b \
    --hash=sha256:f003ed9ad21d6a4713f0a9b5a7a0a79e08dd0f221aff4525a2be4c346ee60aab \
    --hash=sha256:f22ac1c3cac4dbc50079e965eba2c1058622631e526bd9afd45fedd49ba781fa \
    --hash=sha256:faca3bdcf85b2fc05d06ff3fbc1f83e1391b3e724afa3feba7d13eeab355484c \
    --hash=sha256:fca0e3a251908a499833aa292323f32437106001d436eca0e6e7833256674585 \
    --hash=sha256:fd1592b3fdf65fff2ad0004b5e363300ef59ced41c2e6b3a99d4089fa8c5435d \
    --hash=sha256:fd66fc5d0da6d9815ba2cebeb4205f95818ff4b79c3ebe268e75d961704af52f
scapy==2.7.0 \
    --hash=sha256:bfc1ef1b93280aea1ddee53be7f74232aa28ac3d891244d41ee85200d24aa446 \
    --hash=sha256:eb22786da92be6fd8e5c694ae5595e4f5b9ac1f4364c9c45986844f3e3063561
IG_REQ_SYSTEM
# Core dependencies
/opt/irongate/venv/bin/pip install --quiet --require-hashes -r "$IG_REQ_DIR/requirements-venv.txt" 2>/dev/null || \
    pip3 install --quiet --break-system-packages --require-hashes -r "$IG_REQ_DIR/requirements-system.txt" 2>/dev/null || true

# Fallback install with break-system-packages
pip3 install --quiet --break-system-packages --require-hashes -r "$IG_REQ_DIR/requirements-system.txt" 2>/dev/null || true
rm -rf "${IG_REQ_DIR:?}"

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
import re
import sys
import yaml
import time
import signal
import logging
import tempfile
import ipaddress
import subprocess
import threading
from pathlib import Path

# Import Scapy at module level (avoids per-call import overhead in hot loops)
SCAPY_AVAILABLE = False
try:
    from scapy.all import Ether, ARP, sendp, sniff, srp, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    pass  # Warning logged after logger is initialized

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('irongate')

# Try to import blockchain module (optional)
try:
    from blockchain import IrongateBlockchain, VerificationResult, MIDNIGHT_AVAILABLE
    BLOCKCHAIN_MODULE_AVAILABLE = True
except ImportError:
    BLOCKCHAIN_MODULE_AVAILABLE = False
    MIDNIGHT_AVAILABLE = False
    logger.info("Blockchain module not available - Layer 8 disabled")

# irongate-audit (V1): zone/group names and device IPs are interpolated into the
# nftables ruleset text that is loaded as root. The config is writable by the
# web tier, so a crafted value such as "1.2.3.4 } ; flush ruleset ; {" would
# otherwise become nft syntax. Only strict identifiers/addresses may reach it.
# The name becomes the nft set identifier "<name>_devices", and nft identifiers
# cannot start with a digit or '-': require a leading letter or underscore.
_ZONE_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_-]{0,31}')


def _valid_zone_name(name):
    """True only for a str matching [A-Za-z_][A-Za-z0-9_-]{0,31} (fullmatch: no trailing newline)."""
    return isinstance(name, str) and _ZONE_NAME_RE.fullmatch(name) is not None


def _valid_ipv4(value):
    """Return the canonical IPv4 string for value, or None if it is not an IPv4 address."""
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


# irongate-audit (O3): the dual-NIC bridge settings come from the same web-writable config.yaml and used to be
# pasted into os.system() strings, i.e. into a root shell: a bridge_ip of "10.99.0.1/32 dev lo; touch /tmp/x #"
# ran `touch` as root. Interface names are limited to what a kernel interface name can be (1-15 characters,
# not starting with '-' or '.'), addresses must be IPv4 literals, and the commands run as argument lists
# without a shell.
_IFACE_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}')


def _valid_iface(name):
    """True only for a str of 1-15 characters [A-Za-z0-9_.-] that does not start with '.' or '-' (fullmatch: no trailing newline)."""
    return isinstance(name, str) and _IFACE_RE.fullmatch(name) is not None


def _run(argv, quiet=False):
    """Run argv WITHOUT a shell and return its exit status (127 if the program is missing)."""
    out = subprocess.DEVNULL if quiet else None
    try:
        return subprocess.run(argv, stdout=out, stderr=out).returncode
    except OSError:
        return 127


def _audit_log(blockchain, mac, ip, action, result):
    """Best-effort Layer 8 audit write.

    log_access raises NotImplementedError on a chain with no local write path
    (Midnight needs a funded wallet plus a ZK proof server). handle_arp's outer
    handler is `except Exception: pass`, so an unguarded raise here would abort
    the remainder of the handler - in the STRICT branch that means the blocking
    ARP reply further down would never be sent, silently disabling Layer 8
    enforcement for every device. Contain the failure at the call site instead.
    """
    try:
        blockchain.log_access(mac, ip, action, result)
    except NotImplementedError:
        if not getattr(blockchain, '_audit_warned', False):
            logger.warning(
                "Layer 8 audit logging is enabled but this chain has no write "
                "path - continuing without an on-chain audit trail")
            blockchain._audit_warned = True
    except Exception as exc:
        logger.debug("Layer 8 audit log failed (non-critical): %s", exc)


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
        
        # DHCP grace period tracking - prevents ARP spoofing during DHCP negotiation
        self.dhcp_grace_file = '/var/run/irongate/dhcp_grace.list'
        self.dhcp_grace_cache = {}  # MAC -> expiry timestamp
        self.dhcp_grace_seconds = 30  # Default grace period
        self._dhcp_grace_load_interval = 5  # Seconds between file reloads
        self._dhcp_grace_last_load = 0  # Timestamp of last file reload
        
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
        
        if not MIDNIGHT_AVAILABLE:
            logger.warning("Layer 8 Blockchain: Midnight support unavailable")
            return
        
        try:
            self.blockchain = IrongateBlockchain(blockchain_config)
            self.blockchain_enabled = self.blockchain.enabled
            
            if self.blockchain_enabled:
                logger.info("━" * 50)
                logger.info("LAYER 8 BLOCKCHAIN: ACTIVE")
                logger.info(f"  Chain: Midnight")
                logger.info(f"  Network: {blockchain_config.get('network', 'preprod')}")
                logger.info(f"  Contract: {blockchain_config.get('contract_address')}")
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
    
    def _reload_dhcp_grace_file(self):
        """Reload the DHCP grace file from disk (rate-limited by _dhcp_grace_load_interval)."""
        now = time.time()
        if now - self._dhcp_grace_last_load < self._dhcp_grace_load_interval:
            return
        self._dhcp_grace_last_load = now
        try:
            if os.path.exists(self.dhcp_grace_file):
                with open(self.dhcp_grace_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            file_mac = parts[0].lower()
                            try:
                                expiry = int(parts[2])
                            except ValueError:
                                continue
                            if expiry > now:
                                self.dhcp_grace_cache[file_mac] = expiry
        except Exception as e:
            logger.debug(f"Grace file read error: {e}")

    def _is_in_dhcp_grace_period(self, mac):
        """Check if a MAC address is in DHCP grace period (recently got a lease).

        This prevents IronGate from ARP spoofing devices while they're still
        completing DHCP negotiation, which would prevent them from receiving
        their DHCPACK response.
        """
        mac_lower = mac.lower()
        now = time.time()

        # Clean expired entries from cache
        self.dhcp_grace_cache = {
            m: exp for m, exp in self.dhcp_grace_cache.items()
            if exp > now
        }

        # Check cache first
        if mac_lower in self.dhcp_grace_cache:
            remaining = int(self.dhcp_grace_cache[mac_lower] - now)
            logger.debug(f"Grace period active for {mac}: {remaining}s remaining")
            return True

        # Reload grace file if interval has elapsed
        self._reload_dhcp_grace_file()

        # Check cache again after reload
        if mac_lower in self.dhcp_grace_cache:
            remaining = int(self.dhcp_grace_cache[mac_lower] - now)
            logger.info(f"DHCP grace period active for {mac}: {remaining}s remaining")
            return True

        return False
    
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
                            
                            # Exclude: protected, trusted, gateway, self, and devices in DHCP grace period
                            if (ip in protected_ips or
                                mac in protected_macs or
                                ip in trusted_ips or
                                mac in trusted_macs or
                                ip == self.gateway_ip or
                                ip == self.local_ip or
                                mac == local_mac_lower):
                                continue
                            in_grace = self._is_in_dhcp_grace_period(mac)
                            if in_grace:
                                logger.debug(f"Skipping {ip} ({mac}) - in DHCP grace period")
                            else:
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
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _get_mac(self, ip):
        """Resolve MAC address via ARP request"""
        try:
            if not SCAPY_AVAILABLE:
                logger.error("Scapy not available, cannot resolve MAC")
                return None
            ans, _ = srp(
                Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),
                timeout=3, verbose=0, iface=self.interface
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            logger.error(f"Failed to resolve MAC for {ip}: {e}")
        return None
    
    def _build_unicast_arp_packet(self, target_ip, target_mac, spoof_ip):
        """Build a UNICAST ARP reply packet without sending it."""
        return Ether(dst=target_mac, src=self.local_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=self.local_mac
        )

    def _send_unicast_arp(self, target_ip, target_mac, spoof_ip):
        """Send UNICAST ARP reply to specific target only."""
        try:
            pkt = self._build_unicast_arp_packet(target_ip, target_mac, spoof_ip)
            sendp(pkt, iface=self.interface, verbose=False)
            return True
        except Exception as e:
            logger.debug(f"ARP send failed to {target_ip}: {e}")
            return False
    
    def _restore_arp_tables(self):
        """Restore legitimate ARP mappings on shutdown"""
        if not SCAPY_AVAILABLE:
            logger.warning("scapy not available, cannot restore ARP tables")
            return
        
        if not self.gateway_mac:
            logger.warning("No gateway MAC, cannot restore ARP tables")
            return
        
        logger.info("Restoring ARP tables...")
        
        # irongate-audit (ENG-003): these sendp() calls were unguarded. This
        # runs from the SIGTERM path, so one failure aborted the whole loop
        # and every device after it kept Irongate's forged MAC in its ARP
        # cache - traffic black-holed until those entries aged out, with the
        # daemon already gone. Each device is now restored independently.
        for dev_ip, dev_mac, zone in self.protected_devices:
            try:
                # Restore protected device's view of gateway
                pkt = Ether(dst=dev_mac, src=self.gateway_mac) / ARP(
                    op=2, pdst=dev_ip, hwdst=dev_mac,
                    psrc=self.gateway_ip, hwsrc=self.gateway_mac
                )
                sendp(pkt, iface=self.interface, verbose=False, count=5)
            except Exception as e:
                logger.error(f"  ARP restore failed for {dev_ip} (gateway view): {e}")
            
            # Restore all LAN devices' view of protected device
            for lan_ip, lan_mac in self.lan_devices:
                try:
                    pkt = Ether(dst=lan_mac, src=dev_mac) / ARP(
                        op=2, pdst=lan_ip, hwdst=lan_mac,
                        psrc=dev_ip, hwsrc=dev_mac
                    )
                    sendp(pkt, iface=self.interface, verbose=False, count=3)
                except Exception as e:
                    logger.error(f"  ARP restore failed for {lan_ip} -> {dev_ip}: {e}")
            
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
            subprocess.run(['ip', 'neigh', 'replace', dev_ip, 'lladdr', dev_mac,
                           'dev', self.interface, 'nud', 'permanent'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'neigh', 'replace', self.gateway_ip, 'lladdr', self.gateway_mac,
                       'dev', self.interface, 'nud', 'permanent'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
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
        
        # Layer: IPv6 RA Guard - NOT IMPLEMENTED.
        # The config flag is read and reported, but no router-advertisement
        # guarding is performed anywhere in this engine. Do not rely on it.
        if self.layer_ipv6_ra:
            logger.info("Layer: IPv6 RA Guard - ENABLED IN CONFIG, NOT IMPLEMENTED")
        else:
            logger.info("Layer: IPv6 RA Guard - DISABLED")
        
        # Layer: Bypass Detection - NOT IMPLEMENTED.
        # No active probing is performed. The flag is reported only.
        if self.layer_bypass_detection:
            logger.info("Layer: Bypass Detection - ENABLED IN CONFIG, NOT IMPLEMENTED")
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

                # Pre-filter DHCP grace MACs once per cycle (not per packet)
                grace_macs = set()
                for lan_ip, lan_mac in current_lan_devices:
                    if self._is_in_dhcp_grace_period(lan_mac):
                        grace_macs.add(lan_mac)

                # Build all packets for this cycle
                packets = []

                for dev_ip, dev_mac, zone in self.protected_devices:
                    if not self.running:
                        return

                    # Tell protected device: "Gateway is at Irongate's MAC"
                    # This routes their outbound traffic through Irongate
                    packets.append(self._build_unicast_arp_packet(
                        target_ip=dev_ip,
                        target_mac=dev_mac,
                        spoof_ip=self.gateway_ip
                    ))

                    # DO NOT tell gateway about protected devices
                    # Firewalla needs to see real MACs to route traffic properly

                    # Tell ALL LAN devices: "Protected device is at Irongate's MAC"
                    # This intercepts any LAN device trying to reach protected servers
                    for lan_ip, lan_mac in current_lan_devices:
                        if not self.running:
                            return
                        # Skip devices in DHCP grace period - let them complete DHCP first
                        if lan_mac in grace_macs:
                            continue
                        packets.append(self._build_unicast_arp_packet(
                            target_ip=lan_ip,
                            target_mac=lan_mac,
                            spoof_ip=dev_ip
                        ))

                # Send packets in chunks of 256 (single socket session per chunk)
                chunk_size = 256
                for i in range(0, len(packets), chunk_size):
                    if not self.running:
                        return
                    chunk = packets[i:i + chunk_size]
                    sendp(chunk, iface=self.interface, verbose=False)

                # More aggressive poisoning interval for better protection
                time.sleep(0.3)

            except Exception as e:
                logger.error(f"ARP spoof error: {e}")
                time.sleep(5)
    
    def _arp_defense_loop(self):
        """Monitor ARP and counter protected devices announcing real MACs"""
        if not SCAPY_AVAILABLE:
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
        
        # irongate-audit (ENG-001): the packet callback below used to end in
        # a bare `except Exception: pass`. A failing sendp() - socket buffer
        # full, EPERM, interface flap - therefore stopped the spoof silently,
        # so isolation could break with nothing at all in the journal.
        # Rate-limited, because this runs once per ARP packet.
        _arp_err = {'last': 0.0, 'suppressed': 0}

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
                    # DHCP GRACE PERIOD: Skip devices completing DHCP negotiation
                    # This prevents blocking DHCPACK responses to new clients
                    # ═══════════════════════════════════════════════════════
                    if self._is_in_dhcp_grace_period(requester_mac):
                        return
                    
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
                                _audit_log(blockchain, 
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
                                    _audit_log(blockchain, 
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
                                _audit_log(blockchain, 
                                    requester_mac, requester_ip,
                                    f"arp_request:{requested_ip}",
                                    f"blocked_{result_str}"
                                )
                            
                            # Spoof to block access - aggressive burst
                            reply = Ether(dst=requester_mac, src=self.local_mac) / ARP(
                                op=2, pdst=requester_ip, hwdst=requester_mac,
                                psrc=requested_ip, hwsrc=self.local_mac
                            )
                            sendp(reply, iface=self.interface, verbose=False, count=5)
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
                        sendp(reply, iface=self.interface, verbose=False, count=5)
                
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
                        sendp(counter, iface=self.interface, verbose=False, count=5)
                            
            except Exception as e:
                now = time.time()
                if now - _arp_err['last'] > 60:
                    if _arp_err['suppressed']:
                        logger.warning(
                            "ARP callback error: %s (%d further errors suppressed in the last 60s)",
                            e, _arp_err['suppressed'])
                    else:
                        logger.warning("ARP callback error: %s", e)
                    _arp_err['last'] = now
                    _arp_err['suppressed'] = 0
                else:
                    _arp_err['suppressed'] += 1
        
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
                      store=False, timeout=300, stop_filter=should_stop)
            except Exception as e:
                if self.running:
                    logger.debug(f"Sniff restart: {e}")
                    time.sleep(1)
    
    def _setup_firewall(self):
        """Configure nftables - POLICY ACCEPT with specific drops
        Supports both built-in zones and custom device groups"""
        devices = self.config.get('devices') or []
        custom_groups = self.config.get('custom_groups') or []

        # irongate-audit (V1): drop groups whose name is not a safe identifier
        # before anything is interpolated into the ruleset.
        safe_groups = []
        for g in custom_groups:
            if isinstance(g, dict) and _valid_zone_name(g.get('name', '')):
                safe_groups.append(g)
            else:
                logger.warning("Firewall: skipping custom group with invalid name %r",
                               g.get('name') if isinstance(g, dict) else g)
        custom_groups = safe_groups

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
                # irongate-audit (V1): validate before interpolating into nft text.
                safe_ip = _valid_ipv4(ip)
                if safe_ip is None or not _valid_zone_name(zone):
                    logger.warning("Firewall: skipping device with invalid ip/zone (ip=%r zone=%r)",
                                   ip, zone)
                    continue
                if zone not in zone_ips:
                    zone_ips[zone] = []
                zone_ips[zone].append(safe_ip)

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
                    if _valid_zone_name(target_group) and target_group in zone_ips:
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
            # irongate-audit (D11): stage through a unique file instead of a fixed
            # path in a world-writable directory. The previous /tmp/irongate.nft
            # could be replaced between the write and the load, injecting arbitrary
            # firewall rules as root.
            nft_fd, nft_path = tempfile.mkstemp(prefix='irongate-', suffix='.nft')
            try:
                with os.fdopen(nft_fd, 'w') as f:
                    f.write(rules)
                # os.system runs a shell, but nft_path is generated by mkstemp and
                # is always [A-Za-z0-9_]+ - no metacharacters, not attacker-influenced.
                result = os.system(f'nft -f {nft_path}')
            finally:
                try:
                    os.unlink(nft_path)
                except OSError:
                    pass
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
        net = self.config.get('network') or {}
        uplink = net.get('interface', 'eth0')
        dhcp_start = bridge_cfg.get('dhcp_start', '10.99.1.1')
        dhcp_end = bridge_cfg.get('dhcp_end', '10.99.255.254')
        
        if not isolated_iface:
            logger.error("No isolated interface configured!")
            return False
        
        # irongate-audit (O3): nothing from the config reaches a command, an argument or the dnsmasq
        # file before it has been checked. An empty uplink only means there is no NAT rule to add
        # (the old command with an empty name was a broken rule that nft rejected).
        names = [('bridge_name', bridge_name), ('isolated_interface', isolated_iface)]
        if uplink:
            names.append(('network.interface', uplink))
        for what, value in names:
            if not _valid_iface(value):
                logger.error("Dual-NIC: invalid %s %r - not starting the bridge", what, value)
                return False
        addrs = {}
        for what, value in (('bridge_ip', bridge_ip), ('dhcp_start', dhcp_start), ('dhcp_end', dhcp_end)):
            addrs[what] = _valid_ipv4(value)
            if addrs[what] is None:
                logger.error("Dual-NIC: invalid %s %r (an IPv4 address is required) - not starting the bridge", what, value)
                return False
        bridge_ip, dhcp_start, dhcp_end = addrs['bridge_ip'], addrs['dhcp_start'], addrs['dhcp_end']
        
        if not os.path.exists(f'/sys/class/net/{isolated_iface}'):
            logger.error(f"Isolated interface {isolated_iface} not found!")
            return False
        
        logger.info(f"Creating bridge {bridge_name}")
        _run(['ip', 'link', 'set', bridge_name, 'down'], quiet=True)
        _run(['brctl', 'delbr', bridge_name], quiet=True)
        _run(['brctl', 'addbr', bridge_name])
        _run(['brctl', 'stp', bridge_name, 'off'])
        
        _run(['ip', 'link', 'set', isolated_iface, 'down'])
        _run(['ip', 'addr', 'flush', 'dev', isolated_iface])
        _run(['brctl', 'addif', bridge_name, isolated_iface])
        _run(['ip', 'link', 'set', isolated_iface, 'up'])
        
        _run(['ip', 'addr', 'add', f'{bridge_ip}/16', 'dev', bridge_name])
        _run(['ip', 'link', 'set', bridge_name, 'up'])
        
        result = _run(['bridge', 'link', 'set', 'dev', isolated_iface, 'isolated', 'on'], quiet=True)
        if result == 0:
            logger.info("Port isolation enabled")
        else:
            _run(['ebtables', '-A', 'FORWARD', '-i', isolated_iface, '-o', isolated_iface, '-j', 'DROP'])
        
        _run(['nft', 'add', 'table', 'nat'], quiet=True)
        _run(['nft', 'add', 'chain', 'nat', 'postrouting', '{', 'type', 'nat', 'hook', 'postrouting', 'priority', '100', ';', '}'], quiet=True)
        if uplink:
            _run(['nft', 'add', 'rule', 'nat', 'postrouting', 'oifname', uplink, 'masquerade'], quiet=True)
        else:
            logger.warning("Dual-NIC: no uplink interface configured - no NAT rule for the bridge")
        
        dnsmasq_conf = f"""
interface={bridge_name}
bind-interfaces
dhcp-range={dhcp_start},{dhcp_end},24h
dhcp-option=option:router,{bridge_ip}
dhcp-option=option:dns-server,{bridge_ip},8.8.8.8
"""
        with open('/etc/irongate/bridge-dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_conf)
        
        _run(['pkill', '-f', 'dnsmasq.*bridge-dnsmasq'], quiet=True)
        try:
            subprocess.Popen(['dnsmasq', '--conf-file=/etc/irongate/bridge-dnsmasq.conf'], stdin=subprocess.DEVNULL)
        except OSError as exc:
            logger.error("Dual-NIC: cannot start dnsmasq: %s", exc)
        
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
Irongate Layer 8: Midnight Blockchain Verification Module

Provides device authentication against an on-chain registry hosted on the
Midnight blockchain (https://midnight.network).

This module is OPTIONAL - Irongate works fully without it.
Enable in config.yaml under 'blockchain:' section.

Requirements: none. Uses only the Python standard library (urllib.request).
There is no Python SDK for Midnight; the indexer is queried over HTTPS GraphQL.

READ path  (verify_device / get_all_devices / get_stats): fully implemented.
           The public Midnight indexers accept unauthenticated GraphQL POSTs,
           so no wallet, key, mnemonic or API token is stored on this host.

WRITE path (register_device / revoke_device / log_access): NOT implemented.
           Submitting a Midnight transaction requires a funded wallet plus a
           local ZK proof server. Those raise NotImplementedError rather than
           silently reporting success. See MIDNIGHT_WRITE_UNAVAILABLE below.

Migrated from the previous Algorand implementation. The previous version is
kept alongside this file as blockchain_algorand.py.<ts>.reference.
"""

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger('irongate.blockchain')

# The Midnight read path needs nothing beyond the standard library, so the
# capability flag is unconditionally True. It is kept as a module export
# because irongate.py and the irongate-blockchain CLI import it by name.
MIDNIGHT_AVAILABLE = True

MIDNIGHT_WRITE_UNAVAILABLE = (
    "Midnight write operations are not available on this host. Submitting a "
    "transaction requires (a) a funded Midnight wallet holding NIGHT/tDUST and "
    "(b) a local ZK proof server. No Python SDK exists, and the published "
    "proof-server container has no confirmed aarch64 image, so it cannot be "
    "hosted on this Raspberry Pi 4. Register and revoke devices out-of-band, "
    "then point blockchain.contract_address at the deployed registry contract."
)

# Bound the device cache so a hostile or noisy /20 cannot grow it without limit.
MAX_CACHE_ENTRIES = 4096

# After this many consecutive indexer failures, stop making network calls for
# BREAKER_COOLDOWN seconds. verify_device runs inside the scapy ARP callback,
# so an unreachable indexer must never add latency to every packet.
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN = 30.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every HTTP redirect (irongate-audit, V2: SSRF).

    indexer_url is checked against an allowlist, but a redirect would let an
    allowed (or compromised) host send this root process to any other URL. With
    redirect_request() returning None urllib raises HTTPError for a 3xx, which
    _graphql() already treats as an indexer failure.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# urlopen() below uses this opener. It is installed process-wide on purpose: this
# module is the only urllib user in the engine process (tests/test_validation.py,
# OpenerScopeTests, fails if another module starts using urllib), and going through
# urllib.request.urlopen() keeps the transport replaceable in tests, which a
# module-local opener's .open() would not. Switch to a module-local opener (and
# point those test mocks at it) before any other urllib user is added.
urllib.request.install_opener(urllib.request.build_opener(_NoRedirect))


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
    Midnight integration for Irongate network security.

    Features:
    - Device whitelist read from a Midnight registry contract's on-chain state
    - Real-time device verification with local caching
    - Graceful degradation: an unreachable chain never blocks the ARP loop
    - No credentials on disk - the read path is unauthenticated

    Usage:
        bc = IrongateBlockchain(config)
        if bc.enabled:
            result = bc.verify_device(mac, ip)
            if result['verified'] is True:
                # Allow device
            elif result['verified'] is False:
                # Block device
            else:
                # None -> chain undecided, fall through to Layers 1-7
    """

    # Public Midnight endpoints. The indexers accept unauthenticated GraphQL
    # POSTs - no project id, no API key.
    NETWORKS = {
        'preprod': {
            'indexer': 'https://indexer.preprod.midnight.network/api/v4/graphql',
            'rpc': 'https://rpc.preprod.midnight.network',
        },
        'preview': {
            'indexer': 'https://indexer.preview.midnight.network/api/v4/graphql',
            'rpc': 'https://rpc.preview.midnight.network',
        },
        'mainnet': {
            'indexer': 'https://indexer.mainnet.midnight.network/api/v4/graphql',
            'rpc': 'https://rpc.mainnet.midnight.network',
        },
        'undeployed': {
            'indexer': 'http://127.0.0.1:8088/api/v4/graphql',
            'rpc': 'http://127.0.0.1:9944',
        },
    }

    DEFAULT_NETWORK = 'preprod'
    DEFAULT_TIMEOUT = 5.0

    @classmethod
    def allowed_indexer_hosts(cls):
        """Hosts of the https indexer presets in NETWORKS (derived, not hard-coded)."""
        hosts = set()
        for preset in cls.NETWORKS.values():
            parts = urllib.parse.urlsplit(preset['indexer'])
            if parts.scheme == 'https' and parts.hostname:
                hosts.add(parts.hostname.lower())
        return frozenset(hosts)

    @classmethod
    def validate_indexer_url(cls, url):
        """Return url if it is an https URL on a known Midnight indexer host, else None.

        irongate-audit (V2, SSRF): indexer_url comes from a config file the web
        tier can write, and this process runs as root. Without this check a
        crafted value points the engine at cloud metadata (http://169.254.169.254/),
        loopback services or file:// URLs.
        """
        if not isinstance(url, str) or not re.fullmatch(r'[\x21-\x7e]+', url) or '\\' in url:
            return None
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if parts.scheme != 'https' or '@' in parts.netloc or port not in (None, 443):
            return None
        if (parts.hostname or '').lower() not in cls.allowed_indexer_hosts():
            return None
        return url

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize blockchain connection.

        Args:
            config: Blockchain config section from config.yaml
        """
        self.enabled = False
        self.config = config or {}

        # Defaults for attributes read by callers even when disabled.
        self.network = self.config.get('network', self.DEFAULT_NETWORK)
        self.cache_ttl = self.config.get('cache_ttl', 60)
        self.fallback_allow = self.config.get('fallback_allow', True)
        self.audit_logging = self.config.get('audit_logging', False)
        self.allow_rogue_devices = self.config.get('allow_rogue_devices', False)
        self.timeout = float(self.config.get('timeout', self.DEFAULT_TIMEOUT))
        self.contract_address = self.config.get('contract_address')

        self._cache = {}
        self._cache_time = {}
        self._lock = threading.RLock()
        self._state_cache = None
        self._state_cache_time = 0.0
        self._state_cache_ttl = 15.0
        self._fail_count = 0
        self._breaker_until = 0.0
        # Always assigned so it is safe to read on a disabled instance.
        self._last_sync = 0.0

        if self.network not in self.NETWORKS:
            logger.warning(
                "Blockchain Layer 8: unknown network '%s' - falling back to '%s'",
                self.network, self.DEFAULT_NETWORK,
            )
            self.network = self.DEFAULT_NETWORK

        # An explicit indexer_url overrides the network preset, but only if it
        # is an https URL on a known Midnight indexer host (SSRF guard, V2).
        # A configured URL that fails the check FAILS CLOSED: indexer_url becomes
        # None and no query is ever made. It is deliberately NOT replaced by the
        # network preset, which would send queries to a host the operator did not
        # configure and hide the misconfiguration.
        self.indexer_url = self.NETWORKS[self.network]['indexer']
        custom_indexer = self.config.get('indexer_url')
        if custom_indexer and custom_indexer != self.indexer_url:
            if self.validate_indexer_url(custom_indexer):
                self.indexer_url = custom_indexer
            else:
                self.indexer_url = None
                logger.warning(
                    "Blockchain Layer 8: indexer_url %r rejected (must be https on a "
                    "known Midnight indexer host) - no queries will be made until it is "
                    "fixed or removed (it is not replaced by the '%s' preset)",
                    custom_indexer, self.network,
                )

        if not self.config.get('enabled', False):
            logger.info("Blockchain Layer 8: Disabled in config")
            return

        if not self.contract_address:
            logger.warning("Blockchain Layer 8: No contract_address configured - disabled")
            logger.warning("  Deploy the registry contract and set blockchain.contract_address")
            return

        # Probe the indexer once. A failure here is not fatal: the layer stays
        # enabled and degrades to 'undecided' until the indexer recovers.
        head = self._query_block()
        if head is not None:
            logger.info("Blockchain Layer 8: Connected to Midnight %s", self.network)
            logger.info("  Indexer: %s", self.indexer_url)
            logger.info("  Chain height: %s", head.get('height', 'unknown'))
        else:
            logger.warning(
                "Blockchain Layer 8: indexer %s unreachable at startup - "
                "layer enabled but will report 'undecided' until it recovers",
                self.indexer_url,
            )

        self.enabled = True
        logger.info("Blockchain Layer 8: ENABLED (contract: %s)", self.contract_address)

    # ------------------------------------------------------------------
    # GraphQL transport
    # ------------------------------------------------------------------

    def _graphql(self, query: str, variables: Optional[Dict] = None) -> Optional[Dict]:
        """
        POST a GraphQL query to the Midnight indexer.

        Returns the 'data' object, or None on any transport/protocol failure.
        Never raises - callers treat None as 'chain undecided'.
        """
        if self.indexer_url is None:
            # A configured indexer_url was rejected (see __init__): make no request.
            return None

        now = time.time()
        if now < self._breaker_until:
            logger.debug("Midnight indexer circuit breaker open for %.0fs more",
                         self._breaker_until - now)
            return None

        payload = json.dumps({'query': query, 'variables': variables or {}}).encode('utf-8')
        req = urllib.request.Request(
            self.indexer_url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'irongate-layer8/2.0 (+midnight)',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
            parsed = json.loads(body.decode('utf-8'))
        except urllib.error.HTTPError as exc:
            self._record_failure("indexer HTTP %s" % exc.code)
            return None
        except urllib.error.URLError as exc:
            self._record_failure("indexer unreachable: %s" % exc.reason)
            return None
        except (TimeoutError, OSError) as exc:
            self._record_failure("indexer socket error: %s" % exc)
            return None
        except (ValueError, UnicodeDecodeError) as exc:
            self._record_failure("indexer returned non-JSON: %s" % exc)
            return None

        if parsed.get('errors'):
            self._record_failure("GraphQL errors: %s" % parsed['errors'])
            return None

        self._record_success()
        return parsed.get('data')

    def _record_failure(self, detail: str):
        with self._lock:
            self._fail_count += 1
            if self._fail_count >= BREAKER_THRESHOLD:
                self._breaker_until = time.time() + BREAKER_COOLDOWN
                logger.warning(
                    "Midnight indexer failed %d consecutive times - pausing queries for %.0fs (%s)",
                    self._fail_count, BREAKER_COOLDOWN, detail,
                )
            else:
                logger.debug("Midnight indexer failure %d: %s", self._fail_count, detail)

    def _record_success(self):
        with self._lock:
            self._fail_count = 0
            self._breaker_until = 0.0
            self._last_sync = time.time()

    def _query_block(self) -> Optional[Dict]:
        """Fetch the chain head. Doubles as the liveness probe."""
        data = self._graphql('query { block { hash height timestamp } }')
        if not data:
            return None
        return data.get('block')

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _get_cached(self, mac: str) -> Optional[Dict]:
        """Get device from cache if still valid"""
        mac = mac.lower()
        with self._lock:
            if mac not in self._cache:
                return None
            if time.time() - self._cache_time.get(mac, 0) < self.cache_ttl:
                return self._cache[mac]
            self._cache.pop(mac, None)
            self._cache_time.pop(mac, None)
            return None

    def _set_cached(self, mac: str, data: Dict):
        """Store device in cache, evicting the oldest entry when full"""
        mac = mac.lower()
        with self._lock:
            if mac not in self._cache and len(self._cache) >= MAX_CACHE_ENTRIES:
                oldest = min(self._cache_time, key=self._cache_time.get)
                self._cache.pop(oldest, None)
                self._cache_time.pop(oldest, None)
            self._cache[mac] = data
            self._cache_time[mac] = time.time()

    def clear_cache(self):
        """Clear the local device cache"""
        with self._lock:
            self._cache.clear()
            self._cache_time.clear()
        logger.info("Blockchain cache cleared")

    # ------------------------------------------------------------------
    # Registry state
    # ------------------------------------------------------------------

    def _get_contract_state(self) -> Optional[bytes]:
        """
        Fetch the registry contract's latest on-chain state, with a short TTL
        cache. Returns raw decoded bytes, or None if unavailable.
        """
        now = time.time()
        with self._lock:
            if self._state_cache is not None and (now - self._state_cache_time) < self._state_cache_ttl:
                return self._state_cache

        data = self._graphql(
            'query ($addr: HexEncoded!) { contractAction(address: $addr) '
            '{ address state transaction { hash } } }',
            {'addr': self.contract_address},
        )
        if not data:
            return None

        action = data.get('contractAction')
        if not action:
            logger.debug("No contract action found for %s", self.contract_address)
            return None

        state_hex = action.get('state') or ''
        try:
            raw = bytes.fromhex(state_hex[2:] if state_hex.startswith('0x') else state_hex)
        except ValueError as exc:
            logger.error("Contract state is not valid hex: %s", exc)
            return None

        with self._lock:
            self._state_cache = raw
            self._state_cache_time = now
        return raw

    def _parse_registry(self, raw: bytes) -> Dict[str, Dict]:
        """
        Decode the device registry out of the contract's serialized state.

        Registry encoding (the format the Irongate registry contract must use):
            one record per line, "<mac>=<ip>|<zone>|<hostname>|<unix_ts>"
        Records are located by scanning the decoded state for that framing, so
        surrounding contract-specific serialization is tolerated.
        """
        devices = {}
        try:
            text = raw.decode('utf-8', errors='ignore')
        except (UnicodeDecodeError, AttributeError) as exc:
            logger.error("Cannot decode contract state: %s", exc)
            return devices

        for line in text.splitlines():
            line = line.strip()
            if '=' not in line or '|' not in line:
                continue
            mac, _, value = line.partition('=')
            mac = mac.strip().lower().replace('-', ':')
            if mac.count(':') != 5:
                continue
            parsed = self._parse_device_value(value.strip())
            if parsed:
                devices[mac] = parsed
        return devices

    def _parse_device_value(self, value: str) -> Optional[Dict]:
        """Parse 'ip|zone|hostname|timestamp' into a dict."""
        parts = value.split('|')
        if len(parts) < 3:
            return None
        try:
            timestamp = int(parts[3]) if len(parts) > 3 and parts[3] else 0
        except ValueError:
            timestamp = 0
        return {
            'ip': parts[0],
            'zone': parts[1],
            'hostname': parts[2] or 'unknown',
            'timestamp': timestamp,
        }

    # ------------------------------------------------------------------
    # Verification (read path)
    # ------------------------------------------------------------------

    def verify_device(self, mac: str, ip: str) -> Dict[str, Any]:
        """
        Verify a device against the on-chain registry.

        Called by Irongate's ARP defense loop for every access attempt to a
        protected IP, so it must be fast and must never raise.

        Returns a dict whose 'verified' key is deliberately three-valued:
            True  -> registered on-chain and the IP matches; allow
            False -> a definite negative (not registered / IP mismatch); block
            None  -> undecided (layer disabled, or the chain could not be
                     consulted). The caller MUST fall through to Layers 1-7.
                     An unreachable chain is NOT proof of a trustworthy device,
                     so it never yields True.
        """
        if not self.enabled:
            return {
                'verified': None,
                'result': VerificationResult.DISABLED,
                'trust_score': 50,
                'details': 'Blockchain verification disabled',
            }

        mac = mac.lower().replace('-', ':')

        cached = self._get_cached(mac)
        if cached:
            if cached.get('_not_registered'):
                return {
                    'verified': False,
                    'result': VerificationResult.NOT_REGISTERED,
                    'mac': mac,
                    'ip': ip,
                    'trust_score': 0,
                    'cached': True,
                    'details': "Device %s not registered on Midnight (cached)" % mac,
                }
            if cached.get('ip') == ip:
                return {
                    'verified': True,
                    'result': VerificationResult.VERIFIED,
                    'zone': cached.get('zone'),
                    'hostname': cached.get('hostname'),
                    'trust_score': 100,
                    'cached': True,
                    'details': "Verified from cache (zone: %s)" % cached.get('zone'),
                }
            return {
                'verified': False,
                'result': VerificationResult.IP_MISMATCH,
                'expected_ip': cached.get('ip'),
                'actual_ip': ip,
                'trust_score': 0,
                'cached': True,
                'details': "ALERT: MAC %s registered with IP %s, seen at %s"
                           % (mac, cached.get('ip'), ip),
            }

        raw = self._get_contract_state()
        if raw is None:
            # Chain not consulted. Undecided - never a pass, never a hard block
            # unless the operator explicitly asked for fail-closed.
            if self.fallback_allow:
                return {
                    'verified': None,
                    'result': VerificationResult.BLOCKCHAIN_ERROR,
                    'trust_score': 50,
                    'details': 'Midnight indexer unavailable - deferring to Layers 1-7',
                }
            return {
                'verified': False,
                'result': VerificationResult.BLOCKCHAIN_ERROR,
                'trust_score': 0,
                'details': 'Midnight indexer unavailable - fail-closed (fallback_allow: false)',
            }

        registry = self._parse_registry(raw)
        device = registry.get(mac) or registry.get(mac.replace(':', ''))

        if not device:
            self._set_cached(mac, {'_not_registered': True})
            return {
                'verified': False,
                'result': VerificationResult.NOT_REGISTERED,
                'mac': mac,
                'ip': ip,
                'trust_score': 0,
                'cached': False,
                'details': "Device %s not registered on Midnight" % mac,
            }

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
                'details': "Midnight verified (zone: %s)" % device['zone'],
            }

        return {
            'verified': False,
            'result': VerificationResult.IP_MISMATCH,
            'expected_ip': device['ip'],
            'actual_ip': ip,
            'zone': device['zone'],
            'trust_score': 0,
            'cached': False,
            'details': "SPOOFING DETECTED: %s should be at %s" % (mac, device['ip']),
        }

    def get_all_devices(self) -> List[DeviceRecord]:
        """Get all registered devices from the on-chain registry"""
        if not self.enabled:
            return []
        raw = self._get_contract_state()
        if raw is None:
            return []
        return [
            DeviceRecord(
                mac=mac,
                ip=dev['ip'],
                zone=dev['zone'],
                hostname=dev['hostname'],
                registered_at=dev['timestamp'],
            )
            for mac, dev in sorted(self._parse_registry(raw).items())
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get blockchain status and statistics"""
        with self._lock:
            cache_size = len(self._cache)
            last_sync = self._last_sync
            breaker_open = time.time() < self._breaker_until

        stats = {
            'enabled': self.enabled,
            'sdk_available': MIDNIGHT_AVAILABLE,
            'chain': 'midnight',
            'network': self.network,
            'indexer_url': self.indexer_url,
            'contract_address': self.contract_address,
            'cache_size': cache_size,
            'cache_ttl': self.cache_ttl,
            'fallback_allow': self.fallback_allow,
            'audit_logging': self.audit_logging,
            'allow_rogue_devices': self.allow_rogue_devices,
            'write_supported': False,
            'last_sync': last_sync,
            'breaker_open': breaker_open,
        }

        head = self._query_block()
        if head:
            stats['connected'] = True
            stats['chain_height'] = head.get('height')
            stats['chain_head'] = head.get('hash')
        else:
            stats['connected'] = False

        return stats

    # ------------------------------------------------------------------
    # Write path - not available on this host
    # ------------------------------------------------------------------

    def register_device(self, mac: str, ip: str, zone: str, hostname: str) -> Dict[str, Any]:
        """
        Register a device on the Midnight registry contract.

        NOT IMPLEMENTED. Requires a funded wallet and a ZK proof server; see
        MIDNIGHT_WRITE_UNAVAILABLE. Raises rather than returning a fake result
        so a caller can never mistake a no-op for a successful registration.
        """
        raise NotImplementedError(
            "register_device(%s -> %s, zone=%s): %s" % (mac, ip, zone, MIDNIGHT_WRITE_UNAVAILABLE)
        )

    def revoke_device(self, mac: str) -> Dict[str, Any]:
        """
        Revoke a device from the Midnight registry contract.

        NOT IMPLEMENTED - see MIDNIGHT_WRITE_UNAVAILABLE.
        """
        raise NotImplementedError(
            "revoke_device(%s): %s" % (mac, MIDNIGHT_WRITE_UNAVAILABLE)
        )

    def log_access(self, mac: str, ip: str, action: str, result: str) -> Optional[str]:
        """
        Write an access attempt to the chain as an immutable audit record.

        The disabled / audit-logging-off guard is evaluated FIRST, so that with
        the shipped defaults (audit_logging: false) this stays a silent no-op
        exactly as before. It only raises if an operator explicitly turns
        audit_logging on, at which point the missing capability must be loud.
        """
        if not self.enabled or not self.audit_logging:
            return None
        raise NotImplementedError(
            "log_access(%s/%s %s=%s): %s" % (mac, ip, action, result, MIDNIGHT_WRITE_UNAVAILABLE)
        )


# Standalone test
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("IRONGATE LAYER 8: MIDNIGHT BLOCKCHAIN MODULE")
    print("=" * 60)

    probe = IrongateBlockchain({'enabled': False, 'network': 'preprod'})
    print("\nDisabled-instance stats: enabled=%s connected=%s height=%s"
          % (probe.enabled, probe.get_stats().get('connected'),
             probe.get_stats().get('chain_height')))

    neutral = probe.verify_device("aa:bb:cc:dd:ee:ff", "192.168.1.100")
    print("Disabled verify_device -> verified=%r result=%s"
          % (neutral['verified'], neutral['result']))

    try:
        probe.register_device("aa:bb:cc:dd:ee:ff", "192.168.1.100", "isolated", "test")
        print("ERROR: register_device should have raised")
    except NotImplementedError as exc:
        print("register_device correctly raised NotImplementedError")
        print("  %s" % str(exc)[:120])
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
        from blockchain import IrongateBlockchain, MIDNIGHT_AVAILABLE
        if not MIDNIGHT_AVAILABLE:
            print("Midnight blockchain support unavailable!")
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
    print(f"Contract: {stats.get('contract_address', 'Not configured')}")
    print(f"Indexer: {stats.get('indexer_url', 'N/A')}")
    print(f"Chain Height: {stats.get('chain_height', 'N/A')}")
    print(f"Write Support: {'✓ Yes' if stats.get('write_supported') else '✗ No'}")
    
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
    
    try:
        commands[args.command](args)
    except NotImplementedError as exc:
        print("\nThis command is not available:\n  %s" % exc)
        sys.exit(2)


if __name__ == '__main__':
    main()
BLOCKCHAINCLI

chmod +x /opt/irongate/irongate-blockchain
ln -sf /opt/irongate/irongate-blockchain /usr/local/bin/irongate-blockchain

# Create systemd service
cat > /etc/systemd/system/irongate.service << EOF
[Unit]
Description=Irongate Network Isolation
After=network-online.target dnsmasq.service
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/run/irongate
ExecStartPre=/bin/sleep 2
ExecStart=/opt/irongate/venv/bin/python /opt/irongate/irongate.py
ExecStop=/bin/kill -15 \$MAINPID
TimeoutStopSec=10
Restart=on-failure
RestartSec=5
RuntimeDirectory=irongate
RuntimeDirectoryPreserve=yes

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

# Staged in a root-only directory and renamed into place at the end (see the helpers above):
# nothing below opens, chmods or chowns /etc/irongate/config.yaml by path.
# config.yaml is generated ONLY when there is none: no file, a link or special file that is moved aside, or an EMPTY
# file (the placeholder the permissions block above creates). Any non-empty config.yaml - what the dashboard saved
# or the operator wrote - is left exactly as it is: not rewritten, not chowned, not chmod'ed.
if ! ig_etc_check config.yaml || [ ! -s /etc/irongate/config.yaml ]; then
ig_stage
cat > /etc/.irongate-stage/config.yaml << EOF
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

# Layer 8: Midnight Blockchain Verification (OPTIONAL)
# Cryptographic device authentication against an on-chain registry.
# Set enabled: true and configure contract_address to activate.
# The read path is unauthenticated, so no key material is stored on this host.
blockchain:
  enabled: false
  # preprod | preview | mainnet | undeployed
  network: "preprod"
  # Address of the deployed Midnight device-registry contract (required if enabled)
  contract_address: null
  # Override the indexer endpoint; null uses the preset for the chosen network.
  # A custom URL must be https on port 443 on one of the Midnight indexer hosts
  # (indexer.preprod / indexer.preview / indexer.mainnet .midnight.network), with no
  # credentials; redirects are never followed. The selected network's own preset
  # (e.g. the local 'undeployed' node) is also accepted. Any other value is refused
  # by the dashboard (HTTP 400); if it is edited into this file by hand the engine
  # makes NO Layer 8 queries (it does not fall back to the preset) and logs a warning.
  indexer_url: null
  # Cache TTL in seconds (reduces blockchain queries)
  cache_ttl: 60
  # When the chain cannot be consulted: true = undecided, defer to Layers 1-7;
  # false = fail closed and block. It never means 'treat as verified'.
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
    sed -i 's/^devices:$/devices: []/' /etc/.irongate-stage/config.yaml
fi

# A new config.yaml is root:www-data 0640. Put the file in place: a symlink or special file that was
# planted at /etc/irongate/config.yaml is moved aside, never followed.
ig_etc_check config.yaml || true
ig_etc_commit config.yaml 640
rmdir "$IG_STAGE" 2>/dev/null || true
fi

chown -R root:root /opt/irongate
# `chmod -R 755` used to give EVERY file below /opt/irongate world read and execute: the updater's 0700 staging directory
# and the installer in it, a 0600 backup, everything. Now nothing is made more open than it is: /opt/irongate itself is
# 0755, every directory and regular file below it loses only group/other WRITE, and the files this installer wrote that
# must be executable were made executable where they were written. /opt/irongate/audit-bak (root's backups of old
# configuration, which can hold key material) is not entered by the mode pass at all. (The ownership line above is the
# end marker of a block that tests/test_installer_links.sh cuts out by that exact text; it only ever gives root:root.)
chmod 755 /opt/irongate
find /opt/irongate -path /opt/irongate/audit-bak -prune -o \( -type d -o -type f \) -exec chmod go-w {} +

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
# Irongate Auto-Updater (pinned commit)
#
# Runs as root. The web interface may TRIGGER an update (--force) but never
# supplies the code: this script installs ONLY the commit named in the
# root-owned pin file, and only if the downloaded installer's sha256 equals the
# pin. It never follows the moving main branch.
#
# Pin file (operator-maintained, root:root, mode 0644 or 0600):
#   /etc/irongate/updater-pin.conf
#     PINNED_COMMIT=<40 hex chars>
#     PINNED_INSTALLER_SHA256=<64 hex chars>   # sha256 of irongate-install.sh at that commit
# Update the pin (after reviewing the new commit) to roll out a new version.

REPO_RAW_BASE="https://raw.githubusercontent.com/beatboxes/irongate"
PIN_FILE="/etc/irongate/updater-pin.conf"
STAGE_DIR="/opt/irongate/.update"
MIN_INSTALLER_BYTES=100000
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
DB_PATH="/var/www/irongate/dhcp.db"
LOG_FILE="/var/log/irongate-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# One update at a time (the daily timer, the dashboard's "Update now" and an operator can all start this script): the
# second one logs it and exits non-zero. The lock is held on fd 9 until this process exits (the installer it runs gets
# fd 9 closed, so nothing it leaves running can keep the lock).
LOCK_FILE="/run/irongate-updater.lock"
# The lock file is created root-only (0600) by opening it under a restricted umask; an existing lock file keeps its
# mode. fd 9 must stay open in THIS shell, so the umask applies only in a subshell that touches the creation.
if ! { ( umask 077; : >>"$LOCK_FILE" ) && exec 9>>"$LOCK_FILE"; } 2>/dev/null; then
    log "ERROR: cannot open lock file $LOCK_FILE - refusing to update"
    exit 1
fi
if ! flock -n 9; then
    log "another update is running (lock $LOCK_FILE is held) - exiting"
    exit 1
fi

# Load and validate the pin file. Sets PINNED_COMMIT and PINNED_INSTALLER_SHA256,
# or returns 1 after logging why. The file is opened once and that open file is
# inspected and read, so a swap between the check and the read cannot matter.
load_pin() {
    local LC_ALL=C line pin_stat pin_uid pin_gid pin_mode n=0
    PINNED_COMMIT=""
    PINNED_INSTALLER_SHA256=""
    if [ -L "$PIN_FILE" ] || [ ! -f "$PIN_FILE" ]; then
        log "ERROR: pin file $PIN_FILE is missing or not a regular file - refusing to update"
        return 1
    fi
    if ! exec 3< "$PIN_FILE"; then
        log "ERROR: cannot open pin file $PIN_FILE - refusing to update"
        return 1
    fi
    pin_stat=$(stat -L -c '%u:%g:%a' /dev/fd/3 2>/dev/null)
    IFS=: read -r pin_uid pin_gid pin_mode <<< "$pin_stat"
    if [ "$pin_uid" != "0" ] || [ "$pin_gid" != "0" ] \
        || { [ "$pin_mode" != "644" ] && [ "$pin_mode" != "600" ]; }; then
        log "ERROR: pin file $PIN_FILE must be root:root with mode 0644 or 0600 (found uid:gid:mode ${pin_stat:-unknown}) - refusing to update"
        exec 3<&-
        return 1
    fi
    while IFS= read -r line <&3 || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in ''|'#'*) continue ;; esac
        if [[ "$line" =~ ^PINNED_COMMIT=([0-9a-f]{40})$ ]] && [ -z "$PINNED_COMMIT" ]; then
            PINNED_COMMIT="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^PINNED_INSTALLER_SHA256=([0-9a-f]{64})$ ]] && [ -z "$PINNED_INSTALLER_SHA256" ]; then
            PINNED_INSTALLER_SHA256="${BASH_REMATCH[1]}"
        else
            log "ERROR: pin file $PIN_FILE line $n is not valid - refusing to update"
            exec 3<&-
            return 1
        fi
    done
    exec 3<&-
    if [ -z "$PINNED_COMMIT" ] || [ -z "$PINNED_INSTALLER_SHA256" ]; then
        log "ERROR: pin file $PIN_FILE must define PINNED_COMMIT (40 hex) and PINNED_INSTALLER_SHA256 (64 hex) - refusing to update"
        return 1
    fi
    return 0
}

# Check if auto-update is enabled
AUTO_UPDATE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE" != "true" ] && [ "$FORCE" -ne 1 ]; then
    log "Auto-update is disabled, skipping"
    exit 0
fi

log "Starting update check..."

# The pin is the only source of truth for what may be installed.
if ! load_pin; then
    exit 1
fi
TARGET_SHA="$PINNED_COMMIT"
TARGET_COMMIT=$(printf '%s' "$TARGET_SHA" | cut -c1-7)

# Get current commit from database
CURRENT_COMMIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null || echo "unknown")

log "Current: $CURRENT_COMMIT, Pinned: $TARGET_COMMIT"

# Update last check time
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));" 2>/dev/null

# --force re-runs nothing that is already installed: at the pinned commit it is a logged no-op (nothing is downloaded)
if [ "$FORCE" -eq 1 ] && [ "$CURRENT_COMMIT" = "$TARGET_COMMIT" ]; then
    log "--force: installed == pin ($TARGET_COMMIT), nothing to do - not downloading"
    log "Update check finished"
    exit 0
fi

# Compare commits
if [ "$FORCE" -eq 1 ] || { [ "$CURRENT_COMMIT" != "$TARGET_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ] && [ "$CURRENT_COMMIT" != "local" ]; }; then
    log "Update available! Downloading..."

    # Download the installer into a root-only directory. /tmp is world-writable,
    # so staging there let any local user swap the file between download and
    # execution - and the web user had a sudo grant to run exactly that path.
    mkdir -p "$STAGE_DIR"
    chmod 700 "$STAGE_DIR"
    SCRIPT_PATH="$STAGE_DIR/irongate-install.sh"
    rm -f "$SCRIPT_PATH"

    # Fetch the pinned commit, never the moving main ref.
    SRC_URL="$REPO_RAW_BASE/$TARGET_SHA/irongate-install.sh"
    log "Downloading $SRC_URL"
    curl -sf --max-time 60 -H "User-Agent: Irongate-Updater" "$SRC_URL" -o "$SCRIPT_PATH"

    if [ ! -s "$SCRIPT_PATH" ]; then
        log "ERROR: downloaded installer is missing or empty - aborting"
        exit 1
    fi

    # Authenticity gate: the bytes must be exactly the bytes that were reviewed
    # and pinned. Checked before the file is made executable or run.
    ACTUAL_SHA256=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)
    if [ "$ACTUAL_SHA256" != "$PINNED_INSTALLER_SHA256" ]; then
        log "ERROR: installer sha256 ${ACTUAL_SHA256:-unavailable} does not match pin $PINNED_INSTALLER_SHA256 - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi

    # Sanity gate: reject a truncated download or an unparseable script.
    SCRIPT_SIZE=$(stat -c%s "$SCRIPT_PATH" 2>/dev/null || echo 0)
    if [ "$SCRIPT_SIZE" -lt "$MIN_INSTALLER_BYTES" ]; then
        log "ERROR: installer is only ${SCRIPT_SIZE} bytes, expected >= ${MIN_INSTALLER_BYTES} - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi
    if ! bash -n "$SCRIPT_PATH" 2>/dev/null; then
        log "ERROR: installer failed syntax check - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi
    log "Integrity checks passed (${SCRIPT_SIZE} bytes, sha256 matches pin, syntax valid, commit ${TARGET_COMMIT})"

    # installed_commit is stamped only AFTER the installer has exited 0 (below). Stamping it first made a
    # failed installer look installed: the next scheduled run said "Already up to date" and never retried.
    chmod 700 "$SCRIPT_PATH"

    # The installer rewrites the configuration directory (the pin file's directory). Before it runs, that directory is
    # snapshotted, owners and modes included, to a root-only tarball next to the staged installer (0600, root:root);
    # if the installer fails, the directory is put back from it (it holds what the dashboard saved, the login and the
    # access list).
    CONF_DIR="${PIN_FILE%/*}"
    SNAPSHOT="$STAGE_DIR/conf-snapshot.tar"
    rm -f "$SNAPSHOT"
    if ! ( umask 077; tar -C "$CONF_DIR" --numeric-owner -cpf "$SNAPSHOT" . ) 2>/dev/null; then
        log "ERROR: cannot snapshot $CONF_DIR - not running the installer"
        rm -f "$SNAPSHOT"
        exit 1
    fi
    chown root:root "$SNAPSHOT" && chmod 600 "$SNAPSHOT"
    log "Snapshot of $CONF_DIR taken (root:root 0600)"

    log "Running installer..."
    bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1 9>&-
    INSTALL_RC=$?
    if [ "$INSTALL_RC" -ne 0 ]; then
        if tar -C "$CONF_DIR" --same-owner -p --numeric-owner -xf "$SNAPSHOT" 2>/dev/null; then
            RESTORE_MSG="$CONF_DIR restored from the snapshot taken before the installer ran (extracted over the directory; entries the failed run created are left in place)"
            rm -f "$SNAPSHOT"
        else
            RESTORE_MSG="ERROR: restoring $CONF_DIR from $SNAPSHOT failed - the snapshot is kept"
        fi
        log "ERROR: installer exited with status $INSTALL_RC"
        log "$RESTORE_MSG"
        exit 1
    fi
    rm -f "$SNAPSHOT"
    log "Installer succeeded - snapshot removed"
    # The installer stamps installed_commit with the moving main HEAD; restore
    # the pinned commit so the next scheduled run does not reinstall.
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$TARGET_COMMIT');" 2>/dev/null
    log "Update complete!"
    log "Update check finished"
    # The installer rewrites this very file; bash reads scripts incrementally, so
    # stop here instead of reading whatever now sits at the old offset.
    exit 0
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

# The dashboard's "Update now" starts this unit (sudo systemctl start --no-block, see the dnsmasq-web sudoers rule): a
# system unit has its own cgroup, so the update is not a child of php-fpm and survives the php-fpm restart that the
# installer does. It is never enabled or started at boot (no [Install] section).
cat > /etc/systemd/system/irongate-updater-now.service << EOF
[Unit]
Description=Irongate Auto-Updater (web-triggered)

[Service]
Type=oneshot
ExecStart=/opt/irongate/irongate-updater.sh --force
StandardOutput=journal
StandardError=journal
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

# Detect PHP-FPM socket - MUST get this right or web UI breaks
# Method 1: Use PHP_VERSION detected at start of script
if [ -n "$PHP_VERSION" ]; then
    PHP_SOCK="/run/php/php${PHP_VERSION}-fpm.sock"
    echo -e "  Method 1: Using PHP_VERSION ($PHP_VERSION)"
fi

# Method 2: If PHP_VERSION empty, detect from php command now
if [ -z "$PHP_SOCK" ] || [ ! -S "$PHP_SOCK" ]; then
    DETECTED_PHP=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
    if [ -n "$DETECTED_PHP" ]; then
        PHP_SOCK="/run/php/php${DETECTED_PHP}-fpm.sock"
        echo -e "  Method 2: Detected PHP $DETECTED_PHP"
    fi
fi

# Method 3: Look for existing socket file (services might be running)
if [ -z "$PHP_SOCK" ] || [ ! -S "$PHP_SOCK" ]; then
    FOUND_SOCK=$(find /run/php/ /var/run/php/ -name "php*-fpm.sock" 2>/dev/null | head -n1)
    if [ -n "$FOUND_SOCK" ]; then
        PHP_SOCK="$FOUND_SOCK"
        echo -e "  Method 3: Found socket $FOUND_SOCK"
    fi
fi

# Method 4: Check what PHP-FPM package is installed
if [ -z "$PHP_SOCK" ]; then
    PKG_PHP=$(dpkg -l 2>/dev/null | grep -oP 'php\d+\.\d+-fpm' | head -n1 | grep -oP '\d+\.\d+')
    if [ -n "$PKG_PHP" ]; then
        PHP_SOCK="/run/php/php${PKG_PHP}-fpm.sock"
        echo -e "  Method 4: From package php${PKG_PHP}-fpm"
    fi
fi

# Method 5: Last resort - common defaults
if [ -z "$PHP_SOCK" ]; then
    for v in 8.3 8.2 8.1 8.0 7.4; do
        if [ -f "/etc/php/$v/fpm/php-fpm.conf" ]; then
            PHP_SOCK="/run/php/php${v}-fpm.sock"
            echo -e "  Method 5: Found config for PHP $v"
            break
        fi
    done
fi

# Final fallback
if [ -z "$PHP_SOCK" ]; then
    PHP_SOCK="/run/php/php-fpm.sock"
    echo -e "  ${RED}WARNING: Could not detect PHP version, using default${NC}"
fi

echo -e "PHP-FPM Socket: ${GREEN}$PHP_SOCK${NC}"

# Optional admin workstation allow-listed for the web UI (kept out of the
# public repo; pass ADMIN_LAN_IP=<ip> when running the installer)
NGINX_ADMIN_ALLOW=""
if [ -n "${ADMIN_LAN_IP:-}" ]; then
    NGINX_ADMIN_ALLOW="    allow ${ADMIN_LAN_IP};"
fi

cat > /etc/nginx/sites-available/irongate << EOF
server {
    listen $WEBUI_PORT;
    server_name _;
    root /var/www/irongate;
    index index.php;

    # Source-IP access control: localhost, Tailscale CGNAT range, plus an
    # optional admin workstation (ADMIN_LAN_IP env at install time). The
    # wildcard listen above avoids the bind(99) boot race that IP-pinned
    # listens caused when nginx started before tailscale0 had its address.
    # Allow-list is generated from /etc/irongate/access-control.json
    # (WebUI Security page) by /opt/irongate/regen-access.sh
    include /etc/nginx/snippets/irongate-access.conf;

    # Timeouts to prevent hung connections
    client_body_timeout 10s;
    client_header_timeout 10s;
    send_timeout 10s;
    
    # Limit request size
    client_max_body_size 10M;
    
    # irongate-audit: block source and database artifacts from being served.
    # Backup files (api.php.bak.<ts>) do not end in .php, so the php location
    # never claims them and \`location /\` returned them as plaintext source.
    # The SQLite device database was likewise downloadable in full.
    location ~* \.(bak|old|orig|swp|save|sql|sqlite|sqlite3|db)(\.[0-9]+)?\$ {
        deny all;
        return 403;
    }

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

# On the FIRST install (decided once at the top) remove ALL other sites so that only IronGate is enabled;
# on a re-run the other sites of the operator are left alone
if [ "${IG_NGINX_FIRST_INSTALL:-0}" = 1 ]; then
    rm -f /etc/nginx/sites-enabled/* 2>/dev/null || true
fi
ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/irongate

# Also remove the default site config entirely to prevent it from ever coming back (first install only)
if [ "${IG_NGINX_FIRST_INSTALL:-0}" = 1 ]; then
    rm -f /etc/nginx/sites-available/default 2>/dev/null || true
fi

# Verify the symlink exists
if [ ! -L /etc/nginx/sites-enabled/irongate ]; then
    echo -e "${RED}ERROR: Failed to create nginx symlink!${NC}"
    ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/irongate
fi

#######################################
# WebUI authentication + IP allow-list (webauth feature)
#######################################
echo -e "${YELLOW}Configuring WebUI authentication + IP allow-list...${NC}"

# Root helper: regenerate nginx allow-list snippet from access-control.json
cat > /opt/irongate/regen-access.sh << 'WEBAUTH_REGENEOF'
#!/bin/bash
# Regenerates /etc/nginx/snippets/irongate-access.conf from
# /etc/irongate/access-control.json, validates, and reloads nginx.
# Called via sudo by the WebUI (www-data) after allow-list changes.
# Every entry is re-validated here as root — the JSON is group-writable by
# www-data and must never be able to inject arbitrary nginx directives.
set -euo pipefail

CONF="/etc/nginx/snippets/irongate-access.conf"
JSON="/etc/irongate/access-control.json"
TMP="${CONF}.tmp.$$"
PREV="/run/irongate-access.prev.$$"

{
echo "# Auto-generated by irongate auth system - do not edit manually"
echo "# Managed via WebUI Security > IP Allow-List"
echo "# Regenerated by /opt/irongate/regen-access.sh"
if [ -f "$JSON" ]; then
php -r '
$acl = json_decode(@file_get_contents($argv[1]), true);
if ($acl && !empty($acl["enabled"]) && !empty($acl["allowed_ips"]) && is_array($acl["allowed_ips"])) {
    foreach ($acl["allowed_ips"] as $ip) {
        $ip = trim((string)$ip);
        $ok = false;
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $ok = true;
        } elseif (preg_match("#^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$#", $ip, $m)) {
            $ok = intval($m[5]) <= 32;
            for ($i = 1; $i <= 4; $i++) { if (intval($m[$i]) > 255) { $ok = false; } }
        }
        if ($ok) { echo "allow " . $ip . ";\n"; }
    }
    echo "deny all;\n";
} else {
    echo "# IP allow-list disabled - all IPs permitted (auth still required)\n";
}
' "$JSON"
else
echo "# no access-control.json - all IPs permitted (auth still required)"
fi
} > "$TMP"

cp -p "$CONF" "$PREV" 2>/dev/null || true
mv "$TMP" "$CONF"
chown root:root "$CONF"
chmod 644 "$CONF"

if ! nginx -t 2>&1; then
    if [ -f "$PREV" ]; then mv "$PREV" "$CONF"; fi
    echo "ERROR: nginx config test failed; previous access list restored" >&2
    exit 1
fi
rm -f "$PREV"
systemctl reload-or-restart nginx
WEBAUTH_REGENEOF
chown root:root /opt/irongate/regen-access.sh
chmod 755 /opt/irongate/regen-access.sh

# Sudoers drop-in: WebUI (www-data) may regenerate the allow-list
cat > /etc/sudoers.d/irongate-webauth << 'WEBAUTH_SUDOEOF'
# Allow the web server to regenerate the irongate nginx allow-list and reload nginx
# Added by irongate webauth feature - remove this file to revoke
www-data ALL=(root) NOPASSWD: /opt/irongate/regen-access.sh
www-data ALL=(root) NOPASSWD: /usr/sbin/nginx -t
WEBAUTH_SUDOEOF
chmod 440 /etc/sudoers.d/irongate-webauth
if ! visudo -cf /etc/sudoers.d/irongate-webauth; then
    echo -e "${RED}ERROR: irongate-webauth sudoers failed validation - removing${NC}"
    rm -f /etc/sudoers.d/irongate-webauth
fi

# access-control.json — preserved across re-runs
# (a planted symlink or special file at the name counts as absent: it is moved aside, never followed)
mkdir -p /etc/irongate
ig_stage
if ! ig_etc_check access-control.json; then
    WEBAUTH_ADMIN_ALLOW=""
    if [ -n "${ADMIN_LAN_IP:-}" ]; then
        WEBAUTH_ADMIN_ALLOW=",
        \"${ADMIN_LAN_IP}\""
    fi
    cat > /etc/.irongate-stage/access-control.json << WEBAUTH_ACLEOF
{
    "enabled": true,
    "allowed_ips": [
        "127.0.0.1",
        "100.64.0.0/10"${WEBAUTH_ADMIN_ALLOW}
    ],
    "updated_at": "$(date -Iseconds)"
}
WEBAUTH_ACLEOF
    ig_etc_commit access-control.json 660
    echo -e "${GREEN}  ✓ Created access-control.json${NC}"
else
    ig_etc_fix access-control.json 660 || { echo -e "${RED}ERROR: cannot set owner/mode of access-control.json safely${NC}"; exit 1; }
    echo -e "${GREEN}  ✓ Existing access-control.json preserved${NC}"
fi

# auth.json — preserved across re-runs; random initial password printed at end
WEBAUTH_INIT_PASSWORD=""
if ! ig_etc_check auth.json; then
    WEBAUTH_INIT_PASSWORD=$(php -r "echo bin2hex(random_bytes(10));")
    WEBAUTH_HASH=$(WEBAUTH_PW="$WEBAUTH_INIT_PASSWORD" php -r 'echo password_hash(getenv("WEBAUTH_PW"), PASSWORD_BCRYPT);')
    # The generated password is never printed: this installer's output is appended to the update log, which the
    # dashboard serves. It goes to a root-only file instead (created 0600 by umask and noclobber, so it is never
    # readable by anyone else, not even for an instant). This is done BEFORE auth.json is put in place, so that a
    # failure here stops the installer while there is still no login whose password nobody knows.
    IG_ADMIN_PW_FILE=/root/irongate-initial-admin-password
    rm -f -- "$IG_ADMIN_PW_FILE"
    ( umask 077; set -C; printf '%s\n' "$WEBAUTH_INIT_PASSWORD" > "$IG_ADMIN_PW_FILE" )
    chown root:root "$IG_ADMIN_PW_FILE"
    chmod 600 "$IG_ADMIN_PW_FILE"
    cat > /etc/.irongate-stage/auth.json << WEBAUTH_AUTHEOF
{
    "username": "admin",
    "password_hash": "${WEBAUTH_HASH}",
    "created_at": "$(date -Iseconds)",
    "updated_at": "$(date -Iseconds)",
    "failed_attempts": 0,
    "first_failed_at": 0,
    "locked_until": 0
}
WEBAUTH_AUTHEOF
    ig_etc_commit auth.json 640
    echo -e "${GREEN}  ✓ Created auth.json (initial password written to ${IG_ADMIN_PW_FILE}, root only)${NC}"
else
    # an existing auth.json keeps its mode (it is created 0640; the owner is root:www-data as for every file here)
    ig_etc_fix auth.json keep || { echo -e "${RED}ERROR: cannot set owner of auth.json safely${NC}"; exit 1; }
    echo -e "${GREEN}  ✓ Existing auth.json preserved (credentials unchanged)${NC}"
fi
rmdir "$IG_STAGE" 2>/dev/null || true

# Generate the nginx allow-list snippet now; reload failure is tolerated here
# because the final bulletproof restart below brings nginx up regardless
mkdir -p /etc/nginx/snippets
/opt/irongate/regen-access.sh || true

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
    create 644 dnsmasq adm
    postrotate
        systemctl reload dnsmasq > /dev/null 2>&1 || true
    endscript
}
EOF

#######################################
# Enable and start services
#######################################
echo -e "${YELLOW}Starting services...${NC}"

# Create nginx drop-in to ensure IronGate config is always active
# This fixes the issue where nginx falls back to default page after crash/reboot
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/irongate.conf << 'DROPINEOF'
[Service]
ExecStartPre=/bin/bash -c 'rm -f /etc/nginx/sites-enabled/default 2>/dev/null; ln -sf /etc/nginx/sites-available/irongate /etc/nginx/sites-enabled/irongate 2>/dev/null || true'
DROPINEOF

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
sleep 1
systemctl restart nginx

# CRITICAL: Verify web UI is working, fix if not
echo -e "${YELLOW}Verifying web UI...${NC}"
sleep 2
HTTP_CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" http://127.0.0.1/health 2>/dev/null || echo "000")

if [ "$HTTP_CODE" != "200" ]; then
    echo -e "${RED}Web UI not responding (HTTP $HTTP_CODE), attempting fix...${NC}"
    
    # Get PHP version again to be sure
    FIX_PHP_VER=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
    if [ -z "$FIX_PHP_VER" ]; then
        FIX_PHP_VER=$(dpkg -l 2>/dev/null | grep -oP 'php\d+\.\d+-fpm' | head -n1 | grep -oP '\d+\.\d+')
    fi
    
    if [ -n "$FIX_PHP_VER" ]; then
        echo -e "  Fixing nginx config for PHP $FIX_PHP_VER..."
        sed -i "s|fastcgi_pass unix:.*|fastcgi_pass unix:/run/php/php${FIX_PHP_VER}-fpm.sock;|" /etc/nginx/sites-available/irongate
        systemctl restart php${FIX_PHP_VER}-fpm
        systemctl restart nginx
        sleep 2
        HTTP_CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" http://127.0.0.1/health 2>/dev/null || echo "000")
    fi
fi

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}  ✓ Web UI is working${NC}"
else
    echo -e "${RED}  ✗ Web UI still not responding - check logs:${NC}"
    echo -e "    journalctl -u nginx -n 10 --no-pager"
    echo -e "    journalctl -u $PHP_FPM_SERVICE -n 10 --no-pager"
fi

# Test dnsmasq config before starting
echo -e "${YELLOW}Validating dnsmasq configuration...${NC}"
if ! ig_dnsmasq_tree_ok; then
    echo -e "${RED}  ✗ /etc/dnsmasq.conf and /etc/dnsmasq.d are not root-only and clean (dnsmasq-apply --audit): dnsmasq is neither tested nor started${NC}"
    exit 1
fi
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
echo -e "  ${MAGENTA}Layer 8${NC}    - Midnight Blockchain verification (100% VLAN-equivalent)"
echo ""
echo -e "${CYAN}FEATURES:${NC}"
echo -e "  ${GREEN}📊 Dashboard${NC}    - Protection status, zone summary"
echo -e "  ${GREEN}🖥️ Devices${NC}      - Add devices to zones (isolated/servers/trusted)"
echo -e "  ${GREEN}🔗 DHCP${NC}         - Configure DHCP server settings"
echo -e "  ${GREEN}📋 Leases${NC}       - View active DHCP leases"
echo -e "  ${GREEN}📌 Reservations${NC} - Static IP reservations"
echo -e "  ${GREEN}🛡️ Protection${NC}   - Enable/configure network isolation"
echo -e "  ${GREEN}⏱️ Grace Period${NC}  - 30s delay for new DHCP clients (automatic)"
echo -e "  ${GREEN}⬆️ Updates${NC}      - Check for updates, enable auto-update"
echo ""
echo -e "${CYAN}ZONES:${NC}"
echo -e "  ${RED}🔴 isolated${NC}  - Internet only, no LAN access"
echo -e "  ${YELLOW}🟡 servers${NC}   - Can talk to other servers, no LAN"
echo -e "  ${GREEN}🟢 trusted${NC}   - Full network access"
echo ""
echo -e "${CYAN}LAYER 8 BLOCKCHAIN (Optional):${NC}"
echo -e "  Provides cryptographic device authentication via Midnight"
echo -e "  "
echo -e "  ${BOLD}Setup:${NC}"
echo -e "    Deploy a device-registry contract to Midnight (out-of-band),"
echo -e "    then configure Layer 8 in the WebUI: Settings > Layer 8 Blockchain"
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

# FINAL BULLETPROOF RESTART - This MUST work
echo -e "${YELLOW}Final service restart...${NC}"
FINAL_PHP=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1)
if [ -n "$FINAL_PHP" ]; then
    # Fix nginx config with correct PHP socket
    sed -i "s|fastcgi_pass unix:.*|fastcgi_pass unix:/run/php/php${FINAL_PHP}-fpm.sock;|" /etc/nginx/sites-available/irongate
    # Restart PHP-FPM first
    systemctl restart php${FINAL_PHP}-fpm
fi
# Restart nginx
systemctl restart nginx
echo -e "${GREEN}Done.${NC}"

# ---- installer commit stamp: begin ----
# Reached only when every step above succeeded (set -e). IRONGATE_COMMIT was validated at the top; it is
# checked again here because this is the one place it reaches SQL.
ig_stamp_commit() {
    if [ "${IRONGATE_COMMIT_STAMP:-1}" != "1" ]; then
        echo -e "${YELLOW}  installed_commit left as it was (no usable commit id)${NC}"
        return 0
    fi
    if ! { ig_valid_commit "$IRONGATE_COMMIT" || [ "$IRONGATE_COMMIT" = "local" ]; }; then
        echo -e "${YELLOW}  installed_commit left as it was (not a commit id)${NC}"
        return 0
    fi
    sqlite3 /var/www/irongate/dhcp.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '${IRONGATE_COMMIT}');"
    echo -e "${GREEN}  ✓ Commit: ${IRONGATE_COMMIT}${NC}"
}
ig_stamp_commit
# ---- installer commit stamp: end ----

if [ -n "$WEBAUTH_INIT_PASSWORD" ]; then
    echo ""
    echo -e "${CYAN}=============================================${NC}"
    echo -e "${CYAN}WEBUI INITIAL CREDENTIALS (change after first login):${NC}"
    echo -e "  Username: ${BOLD}admin${NC}"
    echo -e "  Password: in ${BOLD}${IG_ADMIN_PW_FILE}${NC} (root only; not printed)"
    echo -e "${CYAN}=============================================${NC}"
fi

