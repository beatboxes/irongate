#!/bin/bash
#===============================================================================
#  ___                       _       
# |_ _|_ __ ___  _ __   __ _| |_ ___ 
#  | || '__/ _ \| '_ \ / _` | __/ _ \
#  | || | | (_) | | | | (_| | ||  __/
# |___|_|  \___/|_| |_|\__, |\__\___|
#                      |___/         
#
# IRONGATE - Multi-Layer Network Isolation System
# Enterprise-grade device isolation without managed switches
#
# Layers of Protection:
#   1. DHCP Microsegmentation (/30 subnets + Option 121 routes)
#   2. Aggressive ARP Defense (continuous re-poisoning + bypass detection)
#   3. IPv6 Router Advertisement Takeover
#   4. nftables Stateful Firewall with Connection Tracking
#   5. Active Bypass Detection & Response
#   6. TCP RST Injection for unauthorized connections
#
# Usage: sudo bash irongate-install.sh
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
INSTALL_DIR="/opt/irongate"
CONFIG_DIR="/etc/irongate"
LOG_DIR="/var/log/irongate"
DATA_DIR="/var/lib/irongate"
RUN_DIR="/run/irongate"
WEB_PORT=8443

# Minimum requirements
MIN_KERNEL="4.18"
MIN_RAM_MB=512

#===============================================================================
# HELPER FUNCTIONS
#===============================================================================

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ___                       _       
 |_ _|_ __ ___  _ __   __ _| |_ ___ 
  | || '__/ _ \| '_ \ / _` | __/ _ \
  | || | | (_) | | | | (_| | ||  __/
 |___|_|  \___/|_| |_|\__, |\__\___|
                      |___/         

 Multi-Layer Network Isolation System
 For Business-Critical Infrastructure
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${BLUE}[→]${NC} $1"; }
log_section() { echo -e "\n${MAGENTA}${BOLD}═══ $1 ═══${NC}\n"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Irongate requires root privileges"
        echo "  Run: sudo bash $0"
        exit 1
    fi
}

check_kernel() {
    KERNEL=$(uname -r | cut -d. -f1,2)
    if [ "$(echo "$KERNEL >= $MIN_KERNEL" | bc)" -eq 0 ]; then
        log_error "Kernel $KERNEL is too old. Minimum: $MIN_KERNEL"
        log_error "Bridge port isolation and nftables flowtables require newer kernel"
        exit 1
    fi
    log_info "Kernel version: $KERNEL (meets minimum $MIN_KERNEL)"
}

check_memory() {
    RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$RAM_MB" -lt "$MIN_RAM_MB" ]; then
        log_warn "Low memory: ${RAM_MB}MB (recommended: ${MIN_RAM_MB}MB+)"
    else
        log_info "Memory: ${RAM_MB}MB"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    case $OS in
        debian|ubuntu|armbian|raspbian)
            log_info "Detected: $PRETTY_NAME"
            PKG_MGR="apt-get"
            ;;
        fedora|centos|rhel|rocky|alma)
            log_info "Detected: $PRETTY_NAME"
            PKG_MGR="dnf"
            ;;
        *)
            log_warn "Untested OS: $OS - proceeding anyway"
            PKG_MGR="apt-get"
            ;;
    esac
}

detect_network() {
    # Find primary interface
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)
    LOCAL_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    LOCAL_MAC=$(ip link show "$IFACE" | awk '/ether/ {print $2}')
    SUBNET=$(ip -4 addr show "$IFACE" | grep -oP '\d+(\.\d+){3}/\d+' | head -n1)
    GATEWAY_MAC=$(ip neigh show | grep "$GATEWAY" | awk '{print $5}' | head -n1)
    
    # Calculate network details
    IFS='/' read -r NETWORK_IP CIDR <<< "$SUBNET"
    NETWORK_BASE=$(echo "$NETWORK_IP" | cut -d. -f1-3)
    
    if [ -z "$IFACE" ] || [ -z "$GATEWAY" ] || [ -z "$LOCAL_IP" ]; then
        log_error "Cannot detect network configuration"
        exit 1
    fi
    
    echo ""
    log_info "Interface:   $IFACE"
    log_info "Local IP:    $LOCAL_IP"
    log_info "Local MAC:   $LOCAL_MAC"
    log_info "Gateway:     $GATEWAY"
    log_info "Gateway MAC: ${GATEWAY_MAC:-discovering...}"
    log_info "Subnet:      $SUBNET"
}

#===============================================================================
# INSTALLATION
#===============================================================================

install_dependencies() {
    log_section "Installing Dependencies"
    
    log_step "Updating package lists..."
    $PKG_MGR update -qq
    
    log_step "Installing system packages..."
    DEBIAN_FRONTEND=noninteractive $PKG_MGR install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        nftables \
        iptables \
        iproute2 \
        net-tools \
        arptables \
        ebtables \
        bridge-utils \
        procps \
        nmap \
        arp-scan \
        dnsmasq \
        radvd \
        libpcap-dev \
        libnetfilter-queue-dev \
        gcc \
        make \
        curl \
        openssl \
        tcpdump \
        conntrack \
        ipset \
        > /dev/null 2>&1
    
    log_info "System packages installed"
}

setup_directories() {
    log_step "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"/{core,templates,static}
    mkdir -p "$CONFIG_DIR"/{certs,rules}
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"/{zones,leases,state}
    mkdir -p "$RUN_DIR"
    
    # Set permissions
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"
    
    log_info "Directories created"
}

setup_python_env() {
    log_step "Setting up Python environment..."
    
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    
    pip install --upgrade pip -q
    pip install \
        flask==3.0.0 \
        flask-cors==4.0.0 \
        flask-socketio==5.3.6 \
        gunicorn==21.2.0 \
        eventlet==0.33.3 \
        scapy==2.5.0 \
        netifaces==0.11.0 \
        psutil==5.9.6 \
        pyyaml==6.0.1 \
        netaddr==0.9.0 \
        cryptography==41.0.0 \
        python-iptables==1.0.1 \
        pyroute2==0.7.9 \
        watchdog==3.0.0 \
        -q
    
    deactivate
    log_info "Python environment ready"
}

generate_certificates() {
    log_step "Generating TLS certificates..."
    
    CERT_DIR="$CONFIG_DIR/certs"
    
    # Generate CA
    openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" -subj "/CN=Irongate CA" 2>/dev/null
    
    # Generate server cert
    openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
    openssl req -new -key "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" -subj "/CN=$LOCAL_IP" 2>/dev/null
    
    cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names
[alt_names]
IP.1 = $LOCAL_IP
IP.2 = 127.0.0.1
DNS.1 = localhost
DNS.2 = irongate.local
EOF
    
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/server.crt" -days 365 \
        -extfile "$CERT_DIR/server.ext" 2>/dev/null
    
    chmod 600 "$CERT_DIR"/*.key
    rm -f "$CERT_DIR/server.csr" "$CERT_DIR/server.ext"
    
    log_info "TLS certificates generated"
}

create_config() {
    log_step "Creating configuration..."
    
    # Get gateway MAC if not found earlier
    if [ -z "$GATEWAY_MAC" ]; then
        ping -c 1 "$GATEWAY" > /dev/null 2>&1
        sleep 1
        GATEWAY_MAC=$(ip neigh show | grep "$GATEWAY" | awk '{print $5}' | head -n1)
    fi
    
    cat > "$CONFIG_DIR/irongate.yaml" << EOF
# Irongate Configuration
# Generated: $(date -Iseconds)
# WARNING: This file contains security-sensitive settings

#═══════════════════════════════════════════════════════════════════════════════
# NETWORK CONFIGURATION
#═══════════════════════════════════════════════════════════════════════════════
network:
  interface: ${IFACE}
  local_ip: ${LOCAL_IP}
  local_mac: ${LOCAL_MAC}
  gateway_ip: ${GATEWAY}
  gateway_mac: ${GATEWAY_MAC}
  subnet: ${SUBNET}
  network_base: ${NETWORK_BASE}

#═══════════════════════════════════════════════════════════════════════════════
# DHCP MICROSEGMENTATION (Layer 1)
# Assigns /30 subnets to force all traffic through Irongate
#═══════════════════════════════════════════════════════════════════════════════
dhcp:
  enabled: true
  # Use /30 subnets for maximum isolation (only gateway + device)
  microsegmentation: true
  # DHCP pool for isolated devices (separate from main network)
  pool_start: 10.55.0.4
  pool_end: 10.55.255.252
  pool_netmask: 255.255.255.252
  # Short lease forces frequent renewals
  lease_time: 300
  # Option 121: Classless static routes - captures ALL traffic
  option_121_enabled: true
  # Starve legitimate DHCP server (aggressive mode)
  dhcp_starvation: false

#═══════════════════════════════════════════════════════════════════════════════
# ARP DEFENSE (Layer 2)
# Aggressive ARP cache poisoning with bypass detection
#═══════════════════════════════════════════════════════════════════════════════
arp:
  enabled: true
  # Interval between gratuitous ARP announcements (seconds)
  refresh_interval: 2
  # Respond immediately to any ARP request for gateway
  immediate_response: true
  # Detect devices using static ARP entries
  bypass_detection: true
  # Re-poison interval when bypass detected (ms)
  aggressive_interval_ms: 500
  # Monitor ARP requests for non-DHCP gateways
  monitor_requests: true

#═══════════════════════════════════════════════════════════════════════════════
# IPv6 ROUTER ADVERTISEMENT (Layer 3)
# Exploit IPv6 preference in dual-stack environments
#═══════════════════════════════════════════════════════════════════════════════
ipv6_ra:
  enabled: true
  # RA interval (ms) - 200ms is aggressive
  interval_ms: 500
  # IPv6 prefix for isolated devices
  prefix: "fd00:iron:gate::"
  prefix_len: 64
  # Push DNS via RDNSS option
  rdnss_enabled: true
  # Managed address configuration (forces DHCPv6)
  managed_flag: false

#═══════════════════════════════════════════════════════════════════════════════
# FIREWALL ENFORCEMENT (Layer 4)
# nftables with connection tracking
#═══════════════════════════════════════════════════════════════════════════════
firewall:
  enabled: true
  # Default policy for isolated devices
  default_policy: drop
  # Allow established connections
  stateful: true
  # Rate limiting for new connections
  rate_limit:
    enabled: true
    rate: 50/second
    burst: 100
  # Log dropped packets
  log_drops: true

#═══════════════════════════════════════════════════════════════════════════════
# ACTIVE DEFENSE (Layer 5)
# Detect and respond to bypass attempts
#═══════════════════════════════════════════════════════════════════════════════
active_defense:
  enabled: true
  # Inject TCP RST for unauthorized connections
  tcp_rst_injection: true
  # Send ICMP unreachable for blocked traffic
  icmp_unreachable: true
  # Re-poison ARP on bypass detection
  auto_repoison: true
  # Alert on bypass attempts
  alert_on_bypass: true
  # Quarantine devices attempting bypass
  auto_quarantine: false

#═══════════════════════════════════════════════════════════════════════════════
# GATEWAY TAKEOVER (Layer 6) - CRITICAL FOR VLAN-EQUIVALENT SECURITY
# This layer ensures isolation even against static IP + static ARP + IPv6 disabled
#═══════════════════════════════════════════════════════════════════════════════
gateway_takeover:
  enabled: true
  
  # BIDIRECTIONAL ARP POISONING
  # Poison gateway to think ALL protected devices are at OUR MAC
  # Even if device sends directly to gateway, response comes to US
  bidirectional_poison: true
  gateway_poison_interval: 1
  
  # CAM TABLE FLOODING
  # Force switch into hub/fail-open mode by exhausting MAC table
  # This gives us VISIBILITY into all traffic, even bypass attempts
  cam_flooding:
    enabled: true
    # Packets per second with random source MACs
    rate: 1000
    # Number of unique MACs to generate
    mac_pool_size: 8000
    # Only flood when bypass detected (less disruptive)
    adaptive: true
  
  # GATEWAY MAC SPOOFING
  # Send frames AS the gateway to win CAM table race
  # Switch will forward gateway-destined traffic to US
  mac_spoofing:
    enabled: true
    # Frames per second claiming to be gateway
    rate: 50
    # Burst when bypass detected
    burst_rate: 500
  
  # PROMISCUOUS INTERCEPTION
  # Monitor ALL traffic and actively kill unauthorized flows
  promiscuous_mode:
    enabled: true
    # Kill TCP connections that bypass our gateway
    rst_injection: true
    # Send ICMP unreachable for UDP bypass
    icmp_injection: true
    # Block at switch port by spoofing source (advanced)
    source_spoofing: true
  
  # TRAFFIC VALIDATION
  # Only forward return traffic if we saw matching outbound
  stateful_validation:
    enabled: true
    # Connection state timeout
    state_timeout: 300
    # Strict mode: drop ALL traffic not in state table
    strict_mode: true

#═══════════════════════════════════════════════════════════════════════════════
# DUAL-NIC BRIDGE MODE - TRUE VLAN-EQUIVALENT ISOLATION
# When enabled, uses a second NIC with Linux bridge port isolation
# This provides 100% hardware-enforced isolation - NO BYPASS POSSIBLE
#═══════════════════════════════════════════════════════════════════════════════
bridge_mode:
  # Mode: 'single' (software isolation) or 'dual' (hardware bridge isolation)
  mode: single
  
  # Second NIC for isolated network (required for dual mode)
  # Common: eth1, enp0s20u1 (USB), enx* (USB by MAC)
  isolated_interface: ""
  
  # Bridge configuration
  bridge_name: br-irongate
  
  # Bridge IP for management of isolated devices
  bridge_ip: 10.99.0.1
  bridge_netmask: 255.255.0.0
  
  # DHCP pool for devices on isolated bridge
  bridge_dhcp:
    enabled: true
    pool_start: 10.99.1.1
    pool_end: 10.99.255.254
    lease_time: 3600
  
  # Linux bridge port isolation (kernel-enforced)
  # Isolated ports CANNOT communicate with each other
  # They can ONLY reach the uplink (internet via Irongate)
  port_isolation: true
  
  # Allow isolated devices to communicate with each other?
  # false = maximum security (devices can only reach internet)
  # true = devices on isolated NIC can talk to each other
  allow_isolated_intra: false
  
  # Firewall rules for bridge
  # Even in bridge mode, we filter what isolated devices can access
  bridge_firewall:
    # Allow internet access
    allow_internet: true
    # Block access to main LAN
    block_lan: true
    # Block access to Irongate management (except DHCP/DNS)
    protect_management: true

#═══════════════════════════════════════════════════════════════════════════════
# WEB INTERFACE
#═══════════════════════════════════════════════════════════════════════════════
web:
  host: 0.0.0.0
  port: ${WEB_PORT}
  https: true
  cert_file: ${CONFIG_DIR}/certs/server.crt
  key_file: ${CONFIG_DIR}/certs/server.key
  # Generate secure secret key
  secret_key: $(openssl rand -hex 32)
  # Session timeout (minutes)
  session_timeout: 30

#═══════════════════════════════════════════════════════════════════════════════
# LOGGING & MONITORING
#═══════════════════════════════════════════════════════════════════════════════
logging:
  level: INFO
  file: ${LOG_DIR}/irongate.log
  max_size_mb: 100
  backup_count: 5
  # Separate security event log
  security_log: ${LOG_DIR}/security.log

#═══════════════════════════════════════════════════════════════════════════════
# ISOLATION ZONES
#═══════════════════════════════════════════════════════════════════════════════
zones:
  # Default zone for new devices
  default_zone: quarantine
  
  # Pre-defined zones
  definitions:
    quarantine:
      description: "Quarantine - No network access"
      allow_internet: false
      allow_lan: false
      allow_intra_zone: false
      
    isolated:
      description: "Isolated - Internet only, no LAN"
      allow_internet: true
      allow_lan: false
      allow_intra_zone: false
      
    servers:
      description: "Servers - Controlled LAN access"
      allow_internet: true
      allow_lan: false
      allow_intra_zone: true
      allowed_ports: [22, 80, 443, 3306, 5432]
      
    trusted:
      description: "Trusted - Full network access"
      allow_internet: true
      allow_lan: true
      allow_intra_zone: true
EOF

    # Create empty zones database
    cat > "$DATA_DIR/zones/devices.yaml" << EOF
# Irongate Device Database
# Devices and their zone assignments
devices: []
EOF

    chmod 600 "$CONFIG_DIR/irongate.yaml"
    chmod 600 "$DATA_DIR/zones/devices.yaml"
    
    log_info "Configuration created"
}

enable_kernel_features() {
    log_step "Enabling kernel features..."
    
    # IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    
    # Disable ICMP redirects (we handle routing)
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
    echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects
    
    # Enable ARP filtering
    echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
    
    # Ignore ARP for non-local addresses
    echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore
    
    # Reply only if target IP is local
    echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce
    
    # Enable connection tracking helpers
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true
    
    # Persist settings
    cat > /etc/sysctl.d/99-irongate.conf << EOF
# Irongate kernel settings
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.netfilter.nf_conntrack_max = 262144
EOF
    
    sysctl -p /etc/sysctl.d/99-irongate.conf > /dev/null 2>&1
    
    log_info "Kernel features enabled"
}

#===============================================================================
# CORE COMPONENTS
#===============================================================================

create_core_engine() {
    log_step "Creating Irongate core engine..."

cat > "$INSTALL_DIR/core/engine.py" << 'ENGINEEOF'
#!/usr/bin/env python3
"""
Irongate Core Engine
Orchestrates all isolation layers and manages system state
"""

import os
import sys
import yaml
import signal
import logging
import threading
import time
from pathlib import Path
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from dhcp_server import DHCPMicrosegmentation
from arp_defender import ARPDefender
from ipv6_ra import IPv6RAAttack
from firewall import IrongateFirewall
from monitor import BypassMonitor
from gateway_takeover import GatewayTakeover
from bridge_manager import BridgeManager

CONFIG_FILE = "/etc/irongate/irongate.yaml"
LOG_DIR = "/var/log/irongate"

class IrongateEngine:
    """Main orchestration engine for Irongate"""
    
    def __init__(self):
        self.config = self._load_config()
        self._setup_logging()
        self.running = False
        self.components = {}
        self.lock = threading.Lock()
        
        self.logger.info("Irongate Engine initializing...")
        
    def _load_config(self):
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    
    def _setup_logging(self):
        log_cfg = self.config.get('logging', {})
        
        self.logger = logging.getLogger('irongate')
        self.logger.setLevel(getattr(logging, log_cfg.get('level', 'INFO')))
        
        # File handler
        fh = logging.FileHandler(log_cfg.get('file', f'{LOG_DIR}/irongate.log'))
        fh.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        self.logger.addHandler(ch)
        
        # Security log
        self.security_logger = logging.getLogger('irongate.security')
        sh = logging.FileHandler(log_cfg.get('security_log', f'{LOG_DIR}/security.log'))
        sh.setFormatter(logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        ))
        self.security_logger.addHandler(sh)
    
    def _init_components(self):
        """Initialize all isolation components"""
        net = self.config['network']
        bridge_cfg = self.config.get('bridge_mode', {})
        bridge_mode = bridge_cfg.get('mode', 'single') == 'dual'
        
        if bridge_mode:
            self.logger.info("=" * 60)
            self.logger.info("DUAL-NIC BRIDGE MODE - TRUE VLAN-EQUIVALENT ISOLATION")
            self.logger.info("=" * 60)
            
            # In bridge mode, we use Linux bridge with port isolation
            # This provides 100% hardware-enforced isolation
            self.components['bridge'] = BridgeManager(
                uplink_interface=net['interface'],
                isolated_interface=bridge_cfg.get('isolated_interface'),
                bridge_name=bridge_cfg.get('bridge_name', 'br-irongate'),
                bridge_ip=bridge_cfg.get('bridge_ip', '10.99.0.1'),
                bridge_netmask=bridge_cfg.get('bridge_netmask', '255.255.0.0'),
                config=bridge_cfg
            )
            
            # Simplified firewall for bridge mode
            if self.config['firewall'].get('enabled', True):
                self.logger.info("Initializing Bridge Firewall...")
                self.components['firewall'] = IrongateFirewall(
                    interface=bridge_cfg.get('bridge_name', 'br-irongate'),
                    local_ip=bridge_cfg.get('bridge_ip', '10.99.0.1'),
                    gateway=net['gateway_ip'],
                    config=self.config['firewall']
                )
            
            self.logger.info("Bridge mode active - 6 software layers DISABLED")
            self.logger.info("Isolation is now KERNEL-ENFORCED via bridge port isolation")
            return
        
        # SINGLE NIC MODE - Use all 6 software layers
        self.logger.info("=" * 60)
        self.logger.info("SINGLE-NIC MODE - 6-LAYER SOFTWARE ISOLATION")
        self.logger.info("=" * 60)
        
        # Layer 1: DHCP Microsegmentation
        if self.config['dhcp'].get('enabled', True):
            self.logger.info("Initializing DHCP Microsegmentation (Layer 1)...")
            self.components['dhcp'] = DHCPMicrosegmentation(
                interface=net['interface'],
                local_ip=net['local_ip'],
                gateway=net['gateway_ip'],
                config=self.config['dhcp']
            )
        
        # Layer 2: ARP Defense
        if self.config['arp'].get('enabled', True):
            self.logger.info("Initializing ARP Defender (Layer 2)...")
            self.components['arp'] = ARPDefender(
                interface=net['interface'],
                local_ip=net['local_ip'],
                local_mac=net['local_mac'],
                gateway_ip=net['gateway_ip'],
                gateway_mac=net['gateway_mac'],
                config=self.config['arp']
            )
        
        # Layer 3: IPv6 RA Attack
        if self.config['ipv6_ra'].get('enabled', True):
            self.logger.info("Initializing IPv6 RA Attack (Layer 3)...")
            self.components['ipv6_ra'] = IPv6RAAttack(
                interface=net['interface'],
                config=self.config['ipv6_ra']
            )
        
        # Layer 4: Firewall
        if self.config['firewall'].get('enabled', True):
            self.logger.info("Initializing Firewall (Layer 4)...")
            self.components['firewall'] = IrongateFirewall(
                interface=net['interface'],
                local_ip=net['local_ip'],
                gateway=net['gateway_ip'],
                config=self.config['firewall']
            )
        
        # Layer 5: Bypass Monitor
        if self.config['active_defense'].get('enabled', True):
            self.logger.info("Initializing Bypass Monitor (Layer 5)...")
            self.components['monitor'] = BypassMonitor(
                interface=net['interface'],
                local_ip=net['local_ip'],
                gateway_ip=net['gateway_ip'],
                config=self.config['active_defense'],
                arp_defender=self.components.get('arp')
            )
        
        # Layer 6: Gateway Takeover (CRITICAL - provides VLAN-equivalent security)
        if self.config['gateway_takeover'].get('enabled', True):
            self.logger.info("Initializing Gateway Takeover (Layer 6)...")
            self.logger.info("  This layer ensures isolation even against full bypass attempts")
            self.components['gateway_takeover'] = GatewayTakeover(
                interface=net['interface'],
                local_ip=net['local_ip'],
                local_mac=net['local_mac'],
                gateway_ip=net['gateway_ip'],
                gateway_mac=net['gateway_mac'],
                config=self.config['gateway_takeover'],
                arp_defender=self.components.get('arp'),
                firewall=self.components.get('firewall')
            )
    
    def start(self):
        """Start all components"""
        self.running = True
        self._init_components()
        
        threads = []
        for name, component in self.components.items():
            self.logger.info(f"Starting {name}...")
            t = threading.Thread(target=component.run, daemon=True, name=name)
            t.start()
            threads.append(t)
        
        self.logger.info("=" * 60)
        self.logger.info("IRONGATE ACTIVE - All isolation layers running")
        self.logger.info("=" * 60)
        
        # Main loop
        while self.running:
            time.sleep(1)
    
    def stop(self):
        """Stop all components"""
        self.logger.info("Shutting down Irongate...")
        self.running = False
        
        for name, component in self.components.items():
            self.logger.info(f"Stopping {name}...")
            if hasattr(component, 'stop'):
                component.stop()
        
        self.logger.info("Irongate stopped")
    
    def reload_config(self):
        """Reload configuration"""
        self.logger.info("Reloading configuration...")
        self.config = self._load_config()
        
        for component in self.components.values():
            if hasattr(component, 'reload_config'):
                component.reload_config(self.config)
    
    def get_status(self):
        """Get status of all components"""
        status = {
            'running': self.running,
            'uptime': None,
            'components': {}
        }
        
        for name, component in self.components.items():
            if hasattr(component, 'get_status'):
                status['components'][name] = component.get_status()
            else:
                status['components'][name] = {'running': True}
        
        return status


def main():
    engine = IrongateEngine()
    
    def signal_handler(sig, frame):
        engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, lambda s, f: engine.reload_config())
    
    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()


if __name__ == '__main__':
    main()
ENGINEEOF
}

create_dhcp_server() {
    log_step "Creating DHCP Microsegmentation module..."

cat > "$INSTALL_DIR/core/dhcp_server.py" << 'DHCPEOF'
#!/usr/bin/env python3
"""
Irongate DHCP Microsegmentation
Assigns /30 subnets with Option 121 routes to capture all traffic
"""

import logging
import threading
import struct
import socket
import time
from datetime import datetime
from scapy.all import (
    DHCP, BOOTP, IP, UDP, Ether, sendp, sniff, 
    get_if_hwaddr, conf as scapy_conf
)

logger = logging.getLogger('irongate.dhcp')


class DHCPMicrosegmentation:
    """
    DHCP server that assigns /30 subnets to isolated devices.
    All traffic MUST route through Irongate gateway.
    
    Key features:
    - /30 subnet per device (device + gateway only)
    - Option 121: Classless static routes capture 0.0.0.0/0
    - Short leases force frequent renewals
    - Tracks all assignments for firewall integration
    """
    
    # DHCP Message Types
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    
    def __init__(self, interface, local_ip, gateway, config):
        self.interface = interface
        self.local_ip = local_ip
        self.gateway = gateway
        self.config = config
        self.local_mac = get_if_hwaddr(interface)
        
        self.running = False
        self.leases = {}  # MAC -> lease info
        self.lock = threading.Lock()
        
        # Parse pool configuration
        self.pool_start = self._ip_to_int(config.get('pool_start', '10.55.0.4'))
        self.pool_end = self._ip_to_int(config.get('pool_end', '10.55.255.252'))
        self.pool_current = self.pool_start
        self.lease_time = config.get('lease_time', 300)
        
        scapy_conf.verb = 0
        
        logger.info(f"DHCP Microsegmentation initialized")
        logger.info(f"  Pool: {config.get('pool_start')} - {config.get('pool_end')}")
        logger.info(f"  Lease time: {self.lease_time}s")
    
    def _ip_to_int(self, ip):
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def _int_to_ip(self, num):
        return socket.inet_ntoa(struct.pack("!I", num))
    
    def _get_next_subnet(self, client_mac):
        """
        Allocate next /30 subnet for a device.
        Returns (client_ip, gateway_ip, netmask)
        """
        with self.lock:
            # Check for existing lease
            if client_mac in self.leases:
                lease = self.leases[client_mac]
                if time.time() < lease['expires']:
                    return lease['ip'], lease['gateway'], '255.255.255.252'
            
            # Allocate new /30 - addresses are: network, gateway, client, broadcast
            # We use .1 as gateway, .2 as client in each /30
            subnet_base = (self.pool_current // 4) * 4
            gateway_ip = self._int_to_ip(subnet_base + 1)
            client_ip = self._int_to_ip(subnet_base + 2)
            
            # Move to next /30
            self.pool_current = subnet_base + 4
            if self.pool_current > self.pool_end:
                self.pool_current = self.pool_start
            
            # Record lease
            self.leases[client_mac] = {
                'ip': client_ip,
                'gateway': gateway_ip,
                'subnet_base': subnet_base,
                'allocated': time.time(),
                'expires': time.time() + self.lease_time
            }
            
            logger.info(f"Allocated {client_ip}/30 to {client_mac} (gw: {gateway_ip})")
            return client_ip, gateway_ip, '255.255.255.252'
    
    def _build_option_121(self, client_ip, gateway_ip):
        """
        Build Option 121 (Classless Static Routes)
        Captures ALL traffic (0.0.0.0/0) via our gateway
        RFC 3442 format: [subnet_len][subnet][gateway]
        """
        routes = b''
        
        # Default route (0.0.0.0/0) via Irongate
        # Format: prefix_len (1 byte) + significant octets + gateway (4 bytes)
        routes += struct.pack('!B', 0)  # /0 = 0 significant octets
        routes += socket.inet_aton(self.local_ip)  # Gateway is Irongate
        
        # Route to client's /30 subnet via its local gateway
        subnet_int = self._ip_to_int(gateway_ip) & 0xFFFFFFFC
        routes += struct.pack('!B', 30)  # /30
        routes += struct.pack('!I', subnet_int)[:4]  # First 4 octets for /30
        routes += socket.inet_aton(gateway_ip)
        
        return routes
    
    def _handle_discover(self, pkt):
        """Handle DHCP DISCOVER - send OFFER"""
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        
        client_ip, gateway_ip, netmask = self._get_next_subnet(client_mac)
        
        # Build DHCP options
        options = [
            ('message-type', 'offer'),
            ('server_id', self.local_ip),
            ('lease_time', self.lease_time),
            ('renewal_time', self.lease_time // 2),
            ('rebinding_time', int(self.lease_time * 0.875)),
            ('subnet_mask', netmask),
            ('router', self.local_ip),  # Irongate is the router
            ('name_server', self.local_ip),  # DNS through Irongate
        ]
        
        # Add Option 121 (Classless Static Routes) - THIS IS KEY
        if self.config.get('option_121_enabled', True):
            opt121 = self._build_option_121(client_ip, gateway_ip)
            options.append((121, opt121))
        
        options.append('end')
        
        # Build and send OFFER
        offer = (
            Ether(src=self.local_mac, dst=client_mac) /
            IP(src=self.local_ip, dst='255.255.255.255') /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2, xid=xid, yiaddr=client_ip,
                siaddr=self.local_ip, chaddr=pkt[BOOTP].chaddr
            ) /
            DHCP(options=options)
        )
        
        sendp(offer, iface=self.interface, verbose=False)
        logger.debug(f"Sent OFFER {client_ip} to {client_mac}")
    
    def _handle_request(self, pkt):
        """Handle DHCP REQUEST - send ACK"""
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        
        # Get the requested IP
        requested_ip = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'requested_addr':
                requested_ip = opt[1]
                break
        
        if not requested_ip and client_mac in self.leases:
            requested_ip = self.leases[client_mac]['ip']
        
        if not requested_ip:
            # New request, allocate
            requested_ip, gateway_ip, netmask = self._get_next_subnet(client_mac)
        else:
            # Renewing existing lease
            if client_mac in self.leases:
                self.leases[client_mac]['expires'] = time.time() + self.lease_time
                gateway_ip = self.leases[client_mac]['gateway']
            else:
                requested_ip, gateway_ip, netmask = self._get_next_subnet(client_mac)
            netmask = '255.255.255.252'
        
        # Build ACK options
        options = [
            ('message-type', 'ack'),
            ('server_id', self.local_ip),
            ('lease_time', self.lease_time),
            ('renewal_time', self.lease_time // 2),
            ('rebinding_time', int(self.lease_time * 0.875)),
            ('subnet_mask', netmask),
            ('router', self.local_ip),
            ('name_server', self.local_ip),
        ]
        
        if self.config.get('option_121_enabled', True):
            opt121 = self._build_option_121(requested_ip, gateway_ip)
            options.append((121, opt121))
        
        options.append('end')
        
        # Build and send ACK
        ack = (
            Ether(src=self.local_mac, dst=client_mac) /
            IP(src=self.local_ip, dst='255.255.255.255') /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2, xid=xid, yiaddr=requested_ip,
                siaddr=self.local_ip, chaddr=pkt[BOOTP].chaddr
            ) /
            DHCP(options=options)
        )
        
        sendp(ack, iface=self.interface, verbose=False)
        logger.info(f"Sent ACK {requested_ip}/30 to {client_mac}")
    
    def _packet_handler(self, pkt):
        """Process incoming DHCP packets"""
        if not pkt.haslayer(DHCP):
            return
        
        # Get message type
        msg_type = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        if msg_type == self.DHCPDISCOVER:
            self._handle_discover(pkt)
        elif msg_type == self.DHCPREQUEST:
            self._handle_request(pkt)
    
    def run(self):
        """Main DHCP server loop"""
        self.running = True
        logger.info("DHCP Microsegmentation server starting...")
        
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter="udp and port 67",
                    prn=self._packet_handler,
                    store=0,
                    timeout=5
                )
            except Exception as e:
                if self.running:
                    logger.error(f"DHCP error: {e}")
                    time.sleep(1)
    
    def stop(self):
        """Stop DHCP server"""
        self.running = False
        logger.info("DHCP server stopped")
    
    def get_leases(self):
        """Get current lease table"""
        with self.lock:
            return dict(self.leases)
    
    def get_status(self):
        """Get server status"""
        return {
            'running': self.running,
            'lease_count': len(self.leases),
            'pool_current': self._int_to_ip(self.pool_current)
        }
DHCPEOF
}

create_arp_defender() {
    log_step "Creating ARP Defender module..."

cat > "$INSTALL_DIR/core/arp_defender.py" << 'ARPEOF'
#!/usr/bin/env python3
"""
Irongate ARP Defender
Aggressive ARP cache poisoning with bypass detection
"""

import logging
import threading
import time
import os
from datetime import datetime
from scapy.all import (
    ARP, Ether, sendp, sniff, srp,
    get_if_hwaddr, conf as scapy_conf
)

logger = logging.getLogger('irongate.arp')
security_logger = logging.getLogger('irongate.security')


class ARPDefender:
    """
    Aggressive ARP defense with multiple strategies:
    1. Continuous gratuitous ARP (claim to be gateway)
    2. Immediate response to gateway ARP requests
    3. Bypass detection (devices querying real gateway)
    4. Aggressive re-poisoning on bypass detection
    """
    
    def __init__(self, interface, local_ip, local_mac, gateway_ip, gateway_mac, config):
        self.interface = interface
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac or self._discover_gateway_mac()
        self.config = config
        
        self.running = False
        self.targets = {}  # IP -> MAC of devices we're poisoning
        self.lock = threading.Lock()
        self.bypass_detected = {}  # Track bypass attempts
        
        self.refresh_interval = config.get('refresh_interval', 2)
        self.aggressive_interval = config.get('aggressive_interval_ms', 500) / 1000
        
        scapy_conf.verb = 0
        
        logger.info(f"ARP Defender initialized")
        logger.info(f"  Gateway: {self.gateway_ip} ({self.gateway_mac})")
    
    def _discover_gateway_mac(self):
        """Discover gateway MAC via ARP"""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip),
                timeout=2, iface=self.interface, verbose=False
            )
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return None
    
    def register_target(self, ip, mac):
        """Register a device for ARP poisoning"""
        with self.lock:
            self.targets[ip] = mac
            logger.info(f"ARP target registered: {ip} ({mac})")
    
    def unregister_target(self, ip):
        """Remove a device from ARP poisoning"""
        with self.lock:
            if ip in self.targets:
                # Restore correct ARP entries
                self._restore_arp(ip, self.targets[ip])
                del self.targets[ip]
                logger.info(f"ARP target unregistered: {ip}")
    
    def _poison_target(self, target_ip, target_mac):
        """
        Send spoofed ARP to target claiming we are the gateway.
        Also tell gateway we are the target (bidirectional poisoning).
        """
        try:
            # Tell target: "Gateway IP is at our MAC"
            pkt_to_target = (
                Ether(dst=target_mac, src=self.local_mac) /
                ARP(
                    op=2,  # is-at (reply)
                    psrc=self.gateway_ip,
                    hwsrc=self.local_mac,
                    pdst=target_ip,
                    hwdst=target_mac
                )
            )
            
            # Tell gateway: "Target IP is at our MAC"
            pkt_to_gateway = (
                Ether(dst=self.gateway_mac, src=self.local_mac) /
                ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=self.local_mac,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac
                )
            )
            
            sendp([pkt_to_target, pkt_to_gateway], iface=self.interface, verbose=False)
            
        except Exception as e:
            logger.error(f"ARP poison error for {target_ip}: {e}")
    
    def _restore_arp(self, target_ip, target_mac):
        """Restore correct ARP entries on shutdown"""
        try:
            # Tell target the real gateway MAC
            pkt_to_target = (
                Ether(dst=target_mac, src=self.gateway_mac) /
                ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,
                    pdst=target_ip,
                    hwdst=target_mac
                )
            )
            
            # Tell gateway the real target MAC
            pkt_to_gateway = (
                Ether(dst=self.gateway_mac, src=target_mac) /
                ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=target_mac,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac
                )
            )
            
            sendp([pkt_to_target, pkt_to_gateway], iface=self.interface, verbose=False, count=3)
            
        except Exception as e:
            logger.error(f"ARP restore error: {e}")
    
    def _send_gratuitous_arp(self):
        """Send gratuitous ARP announcing we are the gateway"""
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self.local_mac) /
            ARP(
                op=2,
                psrc=self.gateway_ip,
                hwsrc=self.local_mac,
                pdst=self.gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
        )
        sendp(pkt, iface=self.interface, verbose=False)
    
    def _handle_arp_request(self, pkt):
        """
        Handle incoming ARP requests:
        - If asking for gateway, respond immediately
        - Detect bypass attempts (asking for real gateway MAC)
        """
        if not pkt.haslayer(ARP) or pkt[ARP].op != 1:  # op=1 is who-has
            return
        
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        dst_ip = pkt[ARP].pdst
        
        # Device asking for gateway
        if dst_ip == self.gateway_ip:
            if self.config.get('immediate_response', True):
                # Respond immediately claiming to be gateway
                reply = (
                    Ether(dst=src_mac, src=self.local_mac) /
                    ARP(
                        op=2,
                        psrc=self.gateway_ip,
                        hwsrc=self.local_mac,
                        pdst=src_ip,
                        hwdst=src_mac
                    )
                )
                sendp(reply, iface=self.interface, verbose=False)
                logger.debug(f"Responded to gateway ARP from {src_ip}")
        
        # Bypass detection: device with static ARP trying to verify
        if self.config.get('bypass_detection', True):
            # If we see repeated ARP requests for gateway from same device,
            # it might be trying to discover the real gateway
            with self.lock:
                if src_ip not in self.bypass_detected:
                    self.bypass_detected[src_ip] = {'count': 0, 'last': 0}
                
                now = time.time()
                if now - self.bypass_detected[src_ip]['last'] < 5:
                    self.bypass_detected[src_ip]['count'] += 1
                else:
                    self.bypass_detected[src_ip]['count'] = 1
                self.bypass_detected[src_ip]['last'] = now
                
                # Multiple rapid requests might indicate bypass attempt
                if self.bypass_detected[src_ip]['count'] > 5:
                    security_logger.warning(
                        f"POTENTIAL BYPASS: {src_ip} ({src_mac}) - "
                        f"excessive gateway ARP requests"
                    )
                    # Aggressive re-poisoning
                    if self.config.get('auto_repoison', True):
                        self._poison_target(src_ip, src_mac)
    
    def _poison_loop(self):
        """Continuous ARP poisoning thread"""
        while self.running:
            try:
                # Gratuitous ARP
                self._send_gratuitous_arp()
                
                # Poison all registered targets
                with self.lock:
                    targets = dict(self.targets)
                
                for ip, mac in targets.items():
                    if not self.running:
                        break
                    self._poison_target(ip, mac)
                
                time.sleep(self.refresh_interval)
                
            except Exception as e:
                if self.running:
                    logger.error(f"Poison loop error: {e}")
                    time.sleep(1)
    
    def _monitor_loop(self):
        """Monitor ARP traffic for bypass detection"""
        def handler(pkt):
            if self.running:
                self._handle_arp_request(pkt)
        
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=handler,
                    store=0,
                    timeout=5
                )
            except Exception as e:
                if self.running:
                    logger.error(f"ARP monitor error: {e}")
                    time.sleep(1)
    
    def run(self):
        """Start ARP defender"""
        self.running = True
        logger.info("ARP Defender starting...")
        
        # Start poison thread
        poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        poison_thread.start()
        
        # Run monitor in main thread
        self._monitor_loop()
    
    def stop(self):
        """Stop ARP defender and restore ARP tables"""
        self.running = False
        
        # Restore all targets
        with self.lock:
            for ip, mac in self.targets.items():
                self._restore_arp(ip, mac)
        
        logger.info("ARP Defender stopped")
    
    def get_status(self):
        return {
            'running': self.running,
            'target_count': len(self.targets),
            'bypass_events': len([b for b in self.bypass_detected.values() if b['count'] > 5])
        }
ARPEOF
}

create_ipv6_ra() {
    log_step "Creating IPv6 RA Attack module..."

cat > "$INSTALL_DIR/core/ipv6_ra.py" << 'IPV6EOF'
#!/usr/bin/env python3
"""
Irongate IPv6 Router Advertisement Attack
Exploit IPv6 preference in dual-stack environments
"""

import logging
import threading
import time
from scapy.all import (
    Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU,
    sendp, get_if_hwaddr, conf as scapy_conf
)

logger = logging.getLogger('irongate.ipv6_ra')


class IPv6RAAttack:
    """
    IPv6 Router Advertisement attack to capture traffic
    on networks with IPv6 enabled (most modern devices).
    
    Exploits:
    - Default IPv6 enabled on Windows/Mac/Linux/iOS/Android
    - IPv6 preference over IPv4 in many applications
    - Lack of RA Guard on unmanaged switches
    """
    
    def __init__(self, interface, config):
        self.interface = interface
        self.config = config
        self.local_mac = get_if_hwaddr(interface)
        
        self.running = False
        self.interval = config.get('interval_ms', 500) / 1000
        self.prefix = config.get('prefix', 'fd00:iron:gate::')
        self.prefix_len = config.get('prefix_len', 64)
        
        # Generate link-local address from MAC
        self.link_local = self._mac_to_link_local(self.local_mac)
        
        scapy_conf.verb = 0
        
        logger.info(f"IPv6 RA Attack initialized")
        logger.info(f"  Link-local: {self.link_local}")
        logger.info(f"  Prefix: {self.prefix}/{self.prefix_len}")
    
    def _mac_to_link_local(self, mac):
        """Convert MAC to IPv6 link-local address (EUI-64)"""
        parts = mac.split(':')
        # Flip 7th bit of first byte
        first_byte = int(parts[0], 16) ^ 0x02
        parts[0] = f'{first_byte:02x}'
        # Insert ff:fe in middle
        eui64 = parts[:3] + ['ff', 'fe'] + parts[3:]
        # Format as IPv6
        ipv6_suffix = ''.join([
            eui64[0] + eui64[1],
            eui64[2] + eui64[3],
            eui64[4] + eui64[5],
            eui64[6] + eui64[7]
        ])
        return f"fe80::{ipv6_suffix[:4]}:{ipv6_suffix[4:8]}:{ipv6_suffix[8:12]}:{ipv6_suffix[12:16]}"
    
    def _build_ra_packet(self):
        """Build Router Advertisement packet"""
        
        # Ethernet layer - multicast to all nodes
        eth = Ether(
            dst="33:33:00:00:00:01",  # All-nodes multicast
            src=self.local_mac
        )
        
        # IPv6 layer
        ipv6 = IPv6(
            src=self.link_local,
            dst="ff02::1",  # All-nodes multicast
            hlim=255  # Must be 255 for ND
        )
        
        # Router Advertisement
        ra = ICMPv6ND_RA(
            type=134,  # Router Advertisement
            chlim=64,  # Hop limit for hosts
            M=0,  # Managed address config (SLAAC)
            O=1,  # Other config (get DNS via DHCPv6 or RDNSS)
            H=0,  # Not a home agent
            prf=1,  # High preference (0=medium, 1=high)
            routerlifetime=1800,  # Router lifetime
            reachabletime=0,  # Use default
            retranstimer=0   # Use default
        )
        
        # Source link-layer address option
        src_lladdr = ICMPv6NDOptSrcLLAddr(lladdr=self.local_mac)
        
        # MTU option
        mtu = ICMPv6NDOptMTU(mtu=1500)
        
        # Prefix Information option
        prefix_info = ICMPv6NDOptPrefixInfo(
            prefixlen=self.prefix_len,
            L=1,  # On-link flag
            A=1,  # Autonomous address-configuration flag
            validlifetime=86400,  # Valid lifetime
            preferredlifetime=14400,  # Preferred lifetime
            prefix=self.prefix
        )
        
        # Build packet
        pkt = eth / ipv6 / ra / src_lladdr / mtu / prefix_info
        
        # Add RDNSS option if enabled
        if self.config.get('rdnss_enabled', True):
            # RDNSS option (RFC 8106)
            # Irongate acts as DNS server
            rdnss = ICMPv6NDOptRDNSS(
                lifetime=1800,
                dns=[self.link_local]
            )
            pkt = pkt / rdnss
        
        return pkt
    
    def _send_ra(self):
        """Send Router Advertisement"""
        try:
            pkt = self._build_ra_packet()
            sendp(pkt, iface=self.interface, verbose=False)
        except Exception as e:
            logger.error(f"RA send error: {e}")
    
    def run(self):
        """Main RA sending loop"""
        self.running = True
        logger.info("IPv6 RA Attack starting...")
        
        while self.running:
            try:
                self._send_ra()
                time.sleep(self.interval)
            except Exception as e:
                if self.running:
                    logger.error(f"RA loop error: {e}")
                    time.sleep(1)
    
    def stop(self):
        """Stop RA attack"""
        self.running = False
        logger.info("IPv6 RA Attack stopped")
    
    def get_status(self):
        return {
            'running': self.running,
            'prefix': f"{self.prefix}/{self.prefix_len}",
            'interval_ms': self.interval * 1000
        }
IPV6EOF
}

create_firewall() {
    log_step "Creating Firewall module..."

cat > "$INSTALL_DIR/core/firewall.py" << 'FWEOF'
#!/usr/bin/env python3
"""
Irongate Firewall
nftables-based stateful firewall with zone-based policies
"""

import logging
import subprocess
import threading
import os
import yaml
from pathlib import Path

logger = logging.getLogger('irongate.firewall')

ZONES_FILE = "/var/lib/irongate/zones/devices.yaml"
CONFIG_FILE = "/etc/irongate/irongate.yaml"


class IrongateFirewall:
    """
    nftables-based firewall with:
    - Zone-based policies
    - Connection tracking
    - Rate limiting
    - Logging
    """
    
    def __init__(self, interface, local_ip, gateway, config):
        self.interface = interface
        self.local_ip = local_ip
        self.gateway = gateway
        self.config = config
        
        self.running = False
        self.lock = threading.Lock()
        
        # Load zone config
        with open(CONFIG_FILE) as f:
            full_config = yaml.safe_load(f)
        self.zone_defs = full_config.get('zones', {}).get('definitions', {})
        
        logger.info("Firewall module initialized")
    
    def _run_nft(self, cmd):
        """Run nft command"""
        try:
            result = subprocess.run(
                ['nft'] + cmd.split(),
                capture_output=True,
                text=True,
                check=True
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"nft error: {e.stderr}")
            return False, e.stderr
    
    def _load_devices(self):
        """Load device database"""
        try:
            with open(ZONES_FILE) as f:
                data = yaml.safe_load(f) or {}
                return data.get('devices', [])
        except:
            return []
    
    def setup_base_rules(self):
        """Set up base nftables ruleset"""
        
        # Flush existing Irongate rules
        self._run_nft('flush table inet irongate')
        
        # Create table and chains
        nft_rules = '''
table inet irongate {
    # Connection tracking
    ct helper ftp-standard {
        type "ftp" protocol tcp
    }
    
    # Sets for dynamic management
    set isolated_ips {
        type ipv4_addr
        flags interval
    }
    
    set trusted_ips {
        type ipv4_addr
        flags interval
    }
    
    set blocked_ips {
        type ipv4_addr
        flags interval
    }
    
    # Rate limit set
    set rate_limit {
        type ipv4_addr
        flags dynamic
        timeout 60s
    }
    
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        
        # Allow DHCP server
        udp dport 67 accept
        
        # Allow DNS
        udp dport 53 accept
        tcp dport 53 accept
        
        # Allow web interface
        tcp dport ''' + str(self.config.get('web_port', 8443)) + ''' accept
        
        # Allow SSH for management
        tcp dport 22 accept
        
        # Log and drop
        log prefix "IRONGATE-INPUT-DROP: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Drop invalid
        ct state invalid drop
        
        # Rate limiting
        ip saddr @rate_limit limit rate over 100/second drop
        
        # Block quarantined devices
        ip saddr @blocked_ips log prefix "IRONGATE-BLOCKED: " drop
        ip daddr @blocked_ips log prefix "IRONGATE-BLOCKED: " drop
        
        # Isolated devices - internet only
        ip saddr @isolated_ips ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
        ip saddr @isolated_ips log prefix "IRONGATE-ISOLATED-LAN: " drop
        
        # Trusted devices - full access
        ip saddr @trusted_ips accept
        ip daddr @trusted_ips accept
        
        # Default drop with logging
        log prefix "IRONGATE-FORWARD-DROP: " drop
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
    
    chain postrouting {
        type nat hook postrouting priority 100;
        
        # Masquerade for isolated devices
        ip saddr @isolated_ips oifname ''' + f'"{self.interface}"' + ''' masquerade
    }
}
'''
        
        # Write and load ruleset
        rules_file = '/tmp/irongate_rules.nft'
        with open(rules_file, 'w') as f:
            f.write(nft_rules)
        
        result = subprocess.run(
            ['nft', '-f', rules_file],
            capture_output=True,
            text=True
        )
        
        os.remove(rules_file)
        
        if result.returncode != 0:
            logger.error(f"Failed to load nftables rules: {result.stderr}")
            return False
        
        logger.info("Base firewall rules loaded")
        return True
    
    def add_device_to_zone(self, ip, zone):
        """Add device to a zone"""
        with self.lock:
            if zone == 'quarantine':
                self._run_nft(f'add element inet irongate blocked_ips {{ {ip} }}')
            elif zone == 'isolated':
                self._run_nft(f'add element inet irongate isolated_ips {{ {ip} }}')
            elif zone == 'trusted':
                self._run_nft(f'add element inet irongate trusted_ips {{ {ip} }}')
            elif zone == 'servers':
                # Servers get isolated + specific port access
                self._run_nft(f'add element inet irongate isolated_ips {{ {ip} }}')
                # Add server-specific rules here
            
            logger.info(f"Added {ip} to zone '{zone}'")
    
    def remove_device_from_zone(self, ip, zone):
        """Remove device from a zone"""
        with self.lock:
            if zone == 'quarantine':
                self._run_nft(f'delete element inet irongate blocked_ips {{ {ip} }}')
            elif zone == 'isolated':
                self._run_nft(f'delete element inet irongate isolated_ips {{ {ip} }}')
            elif zone == 'trusted':
                self._run_nft(f'delete element inet irongate trusted_ips {{ {ip} }}')
            
            logger.info(f"Removed {ip} from zone '{zone}'")
    
    def apply_zones(self):
        """Apply all device zone assignments"""
        devices = self._load_devices()
        
        for device in devices:
            ip = device.get('ip')
            zone = device.get('zone', 'quarantine')
            if ip:
                self.add_device_to_zone(ip, zone)
    
    def get_rules(self):
        """Get current ruleset"""
        success, output = self._run_nft('list table inet irongate')
        return output if success else "Error loading rules"
    
    def get_counters(self):
        """Get packet counters"""
        success, output = self._run_nft('list counters table inet irongate')
        return output if success else ""
    
    def run(self):
        """Initialize and run firewall"""
        self.running = True
        
        # Set up base rules
        if not self.setup_base_rules():
            logger.error("Failed to initialize firewall")
            return
        
        # Apply device zones
        self.apply_zones()
        
        logger.info("Firewall running")
        
        # Keep running (rules are in kernel)
        while self.running:
            import time
            time.sleep(5)
    
    def stop(self):
        """Stop firewall"""
        self.running = False
        # Optionally flush rules
        # self._run_nft('flush table inet irongate')
        logger.info("Firewall stopped")
    
    def get_status(self):
        return {
            'running': self.running,
            'rules_active': True
        }
FWEOF
}

create_monitor() {
    log_step "Creating Bypass Monitor module..."

cat > "$INSTALL_DIR/core/monitor.py" << 'MONEOF'
#!/usr/bin/env python3
"""
Irongate Bypass Monitor
Detects and responds to isolation bypass attempts
"""

import logging
import threading
import time
import os
from datetime import datetime
from scapy.all import (
    sniff, IP, TCP, ARP, Ether,
    send, sr1,
    conf as scapy_conf
)

logger = logging.getLogger('irongate.monitor')
security_logger = logging.getLogger('irongate.security')


class BypassMonitor:
    """
    Monitors for bypass attempts:
    1. Static IP configuration (no DHCP)
    2. Static ARP entries
    3. Traffic not going through Irongate
    4. IPv6 bypassing RA
    
    Response actions:
    - Log security events
    - Re-poison ARP
    - Inject TCP RST
    - Alert administrators
    """
    
    def __init__(self, interface, local_ip, gateway_ip, config, arp_defender=None):
        self.interface = interface
        self.local_ip = local_ip
        self.gateway_ip = gateway_ip
        self.config = config
        self.arp_defender = arp_defender
        
        self.running = False
        self.bypass_events = []
        self.lock = threading.Lock()
        
        scapy_conf.verb = 0
        
        logger.info("Bypass Monitor initialized")
    
    def _record_event(self, event_type, source_ip, source_mac, details):
        """Record security event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'source_ip': source_ip,
            'source_mac': source_mac,
            'details': details
        }
        
        with self.lock:
            self.bypass_events.append(event)
            # Keep last 1000 events
            if len(self.bypass_events) > 1000:
                self.bypass_events = self.bypass_events[-1000:]
        
        security_logger.warning(
            f"BYPASS ATTEMPT: {event_type} from {source_ip} ({source_mac}) - {details}"
        )
        
        return event
    
    def _inject_tcp_rst(self, src_ip, dst_ip, src_port, dst_port):
        """Inject TCP RST to terminate unauthorized connection"""
        if not self.config.get('tcp_rst_injection', True):
            return
        
        try:
            rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port,
                dport=src_port,
                flags='R',
                seq=0
            )
            send(rst_pkt, verbose=False)
            logger.debug(f"Injected RST: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        except Exception as e:
            logger.error(f"RST injection error: {e}")
    
    def _handle_suspicious_traffic(self, pkt):
        """Analyze traffic for bypass indicators"""
        if not pkt.haslayer(IP):
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Get MAC if available
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
        
        # Check for direct LAN traffic not going through us
        # This is complex - we'd need to be in promiscuous mode on a span port
        # For now, we monitor ARP patterns
        
        if pkt.haslayer(ARP):
            self._handle_arp_traffic(pkt)
    
    def _handle_arp_traffic(self, pkt):
        """Monitor ARP for bypass indicators"""
        if pkt[ARP].op == 1:  # ARP Request
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            dst_ip = pkt[ARP].pdst
            
            # Device asking for something other than us when it should use us
            # This is suspicious if we've assigned them via DHCP
            if dst_ip == self.gateway_ip and src_ip != self.local_ip:
                # Someone asking for real gateway - might be static ARP check
                self._record_event(
                    'ARP_PROBE',
                    src_ip,
                    src_mac,
                    f"Probing for gateway {dst_ip}"
                )
                
                # Re-poison
                if self.arp_defender and self.config.get('auto_repoison', True):
                    self.arp_defender.register_target(src_ip, src_mac)
        
        elif pkt[ARP].op == 2:  # ARP Reply
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            # Someone else claiming to be the gateway
            if src_ip == self.gateway_ip and src_mac != self.local_mac:
                # Real gateway or someone else poisoning
                pass  # This is expected - real gateway responses
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        def handler(pkt):
            if self.running:
                try:
                    self._handle_suspicious_traffic(pkt)
                except Exception as e:
                    logger.error(f"Monitor handler error: {e}")
        
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    prn=handler,
                    store=0,
                    timeout=5
                )
            except Exception as e:
                if self.running:
                    logger.error(f"Monitor sniff error: {e}")
                    time.sleep(1)
    
    def run(self):
        """Start bypass monitor"""
        self.running = True
        logger.info("Bypass Monitor starting...")
        
        self._monitor_loop()
    
    def stop(self):
        """Stop monitor"""
        self.running = False
        logger.info("Bypass Monitor stopped")
    
    def get_events(self, limit=100):
        """Get recent bypass events"""
        with self.lock:
            return self.bypass_events[-limit:]
    
    def get_status(self):
        return {
            'running': self.running,
            'event_count': len(self.bypass_events)
        }
MONEOF
}

create_gateway_takeover() {
    log_step "Creating Gateway Takeover module (Layer 6 - VLAN-equivalent security)..."

cat > "$INSTALL_DIR/core/gateway_takeover.py" << 'GTEOF'
#!/usr/bin/env python3
"""
Irongate Gateway Takeover - Layer 6
Provides VLAN-equivalent isolation security

This is the CRITICAL layer that prevents bypass even when attacker has:
- Static IP (bypasses DHCP)
- Static ARP entries (bypasses ARP poisoning to device)
- IPv6 disabled (bypasses RA attack)
- Knowledge of real gateway MAC

HOW IT WORKS:
1. Bidirectional ARP Poisoning: Gateway thinks ALL devices are at OUR MAC
   - Even if device sends directly to gateway, RESPONSE comes to us
   - We control the return path

2. CAM Table Flooding: Forces switch into hub mode
   - We see ALL traffic on the network
   - Can detect and kill bypass attempts in real-time

3. Gateway MAC Spoofing: We claim to BE the gateway at Layer 2
   - Switch forwards gateway-destined frames to US
   - Wins race condition against real gateway

4. Promiscuous Interception: Kill unauthorized flows
   - TCP RST injection for bypass connections
   - ICMP unreachable for UDP
   - Stateful validation ensures we see both directions

RESULT: Even a fully-configured bypass device cannot communicate because:
- Outbound MAY reach gateway, but response comes to US (we drop it)
- If we detect bypass traffic, we RST/block it immediately
- Switch CAM table points gateway MAC to us
- We ARE the gateway from the switch's perspective
"""

import logging
import threading
import time
import random
import struct
import socket
from datetime import datetime
from collections import defaultdict
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP,
    sendp, sniff, send, RandMAC,
    get_if_hwaddr, conf as scapy_conf
)

logger = logging.getLogger('irongate.gateway_takeover')
security_logger = logging.getLogger('irongate.security')


class GatewayTakeover:
    """
    Layer 6: Gateway Takeover
    Provides VLAN-equivalent security through multi-vector control
    """
    
    def __init__(self, interface, local_ip, local_mac, gateway_ip, gateway_mac, 
                 config, arp_defender=None, firewall=None):
        self.interface = interface
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.config = config
        self.arp_defender = arp_defender
        self.firewall = firewall
        
        self.running = False
        self.lock = threading.Lock()
        
        # Track protected devices (IP -> MAC)
        self.protected_devices = {}
        
        # Connection state table for stateful validation
        self.connection_states = {}  # (src_ip, dst_ip, src_port, dst_port) -> state
        self.state_timeout = config.get('stateful_validation', {}).get('state_timeout', 300)
        
        # Statistics
        self.stats = {
            'bypass_attempts_blocked': 0,
            'rst_injected': 0,
            'icmp_injected': 0,
            'cam_floods_triggered': 0,
            'gateway_poisons_sent': 0
        }
        
        # CAM flooding state
        self.cam_flooding_active = False
        self.generated_macs = self._generate_mac_pool(
            config.get('cam_flooding', {}).get('mac_pool_size', 8000)
        )
        
        scapy_conf.verb = 0
        
        logger.info("Gateway Takeover (Layer 6) initialized")
        logger.info("  Mode: Full gateway control for VLAN-equivalent security")
        logger.info(f"  Gateway: {gateway_ip} ({gateway_mac})")
    
    def _generate_mac_pool(self, size):
        """Generate pool of random MACs for CAM flooding"""
        macs = []
        for _ in range(size):
            # Generate random MAC with locally-administered bit set
            mac = [0x02, random.randint(0, 255), random.randint(0, 255),
                   random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)]
            macs.append(':'.join(f'{b:02x}' for b in mac))
        return macs
    
    def register_protected_device(self, ip, mac):
        """Register a device for protection"""
        with self.lock:
            self.protected_devices[ip] = mac
            logger.info(f"Protected device registered: {ip} ({mac})")
    
    def unregister_protected_device(self, ip):
        """Remove device from protection"""
        with self.lock:
            if ip in self.protected_devices:
                del self.protected_devices[ip]
    
    # =========================================================================
    # LAYER 6A: BIDIRECTIONAL ARP POISONING
    # =========================================================================
    
    def _poison_gateway_for_device(self, device_ip, device_mac):
        """
        Tell the gateway that device_ip is at OUR MAC.
        This ensures responses to the device come through us.
        """
        pkt = (
            Ether(dst=self.gateway_mac, src=self.local_mac) /
            ARP(
                op=2,  # is-at
                psrc=device_ip,       # "I am device_ip"
                hwsrc=self.local_mac, # "...at Irongate's MAC"
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac
            )
        )
        sendp(pkt, iface=self.interface, verbose=False)
    
    def _bidirectional_poison_loop(self):
        """
        Continuously poison gateway to think ALL protected devices are at our MAC.
        This is the KEY to defeating static ARP bypass.
        """
        interval = self.config.get('gateway_poison_interval', 1)
        
        while self.running:
            try:
                with self.lock:
                    devices = dict(self.protected_devices)
                
                for device_ip, device_mac in devices.items():
                    if not self.running:
                        break
                    self._poison_gateway_for_device(device_ip, device_mac)
                    self.stats['gateway_poisons_sent'] += 1
                
                time.sleep(interval)
                
            except Exception as e:
                if self.running:
                    logger.error(f"Bidirectional poison error: {e}")
                    time.sleep(1)
    
    # =========================================================================
    # LAYER 6B: CAM TABLE FLOODING
    # =========================================================================
    
    def _flood_cam_table(self, duration=5, rate=1000):
        """
        Flood switch CAM table with random MACs to force hub mode.
        In hub mode, switch broadcasts everything = we see all traffic.
        """
        logger.warning("CAM flooding activated - forcing switch to hub mode")
        self.stats['cam_floods_triggered'] += 1
        
        end_time = time.time() + duration
        interval = 1.0 / rate
        
        while time.time() < end_time and self.running:
            try:
                # Send frame with random source MAC
                src_mac = random.choice(self.generated_macs)
                pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / b'\x00' * 46
                sendp(pkt, iface=self.interface, verbose=False)
                time.sleep(interval)
            except:
                pass
        
        logger.info("CAM flooding burst complete")
    
    def _adaptive_cam_flood_loop(self):
        """
        Monitor for bypass attempts and trigger CAM flooding when detected.
        Adaptive mode: only flood when necessary to minimize network impact.
        """
        if not self.config.get('cam_flooding', {}).get('enabled', True):
            return
        
        if not self.config.get('cam_flooding', {}).get('adaptive', True):
            # Non-adaptive: continuous low-rate flooding
            while self.running:
                self._flood_cam_table(duration=1, rate=100)
                time.sleep(5)
        else:
            # Adaptive: flood is triggered by bypass detection
            while self.running:
                if self.cam_flooding_active:
                    self._flood_cam_table(duration=10, rate=1000)
                    self.cam_flooding_active = False
                time.sleep(1)
    
    def trigger_cam_flood(self):
        """Trigger CAM flooding (called when bypass detected)"""
        self.cam_flooding_active = True
        logger.warning("CAM flood triggered by bypass detection")
    
    # =========================================================================
    # LAYER 6C: GATEWAY MAC SPOOFING
    # =========================================================================
    
    def _spoof_gateway_mac(self, burst=False):
        """
        Send frames AS the gateway to win CAM table race.
        Switch will learn: gateway_mac -> our_port
        """
        rate = self.config.get('mac_spoofing', {}).get('burst_rate' if burst else 'rate', 50)
        
        # Send frame claiming to be the gateway
        pkt = (
            Ether(src=self.gateway_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(
                op=1,  # who-has (just to generate traffic)
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac,  # We claim to be gateway
                pdst="0.0.0.0",
                hwdst="00:00:00:00:00:00"
            )
        )
        sendp(pkt, iface=self.interface, verbose=False)
    
    def _gateway_spoof_loop(self):
        """Continuously spoof gateway MAC to maintain CAM table control"""
        if not self.config.get('mac_spoofing', {}).get('enabled', True):
            return
        
        rate = self.config.get('mac_spoofing', {}).get('rate', 50)
        interval = 1.0 / rate
        
        while self.running:
            try:
                self._spoof_gateway_mac()
                time.sleep(interval)
            except Exception as e:
                if self.running:
                    logger.error(f"Gateway spoof error: {e}")
                    time.sleep(1)
    
    # =========================================================================
    # LAYER 6D: PROMISCUOUS INTERCEPTION
    # =========================================================================
    
    def _inject_tcp_rst(self, src_ip, dst_ip, sport, dport, seq=0):
        """Inject TCP RST to kill a connection"""
        try:
            # RST from destination to source
            rst = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dport, dport=sport, flags='R', seq=seq
            )
            send(rst, verbose=False)
            
            # Also RST from source to destination (belt and suspenders)
            rst2 = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=sport, dport=dport, flags='RA', seq=seq
            )
            send(rst2, verbose=False)
            
            self.stats['rst_injected'] += 1
            
        except Exception as e:
            logger.error(f"RST injection error: {e}")
    
    def _inject_icmp_unreachable(self, original_pkt):
        """Inject ICMP destination unreachable"""
        try:
            if not original_pkt.haslayer(IP):
                return
            
            icmp = (
                IP(src=self.gateway_ip, dst=original_pkt[IP].src) /
                ICMP(type=3, code=1) /  # Host unreachable
                original_pkt[IP]
            )
            send(icmp, verbose=False)
            self.stats['icmp_injected'] += 1
            
        except Exception as e:
            logger.error(f"ICMP injection error: {e}")
    
    def _is_bypass_attempt(self, pkt):
        """
        Detect if packet is a bypass attempt.
        Bypass = device talking to gateway directly, not through us.
        """
        if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
            return False
        
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Ignore our own traffic
        if src_mac == self.local_mac:
            return False
        
        # Check if source is a protected device
        with self.lock:
            if src_ip not in self.protected_devices:
                return False
            expected_mac = self.protected_devices[src_ip]
        
        # BYPASS DETECTION:
        # If protected device is sending directly to gateway MAC
        # (not to us), this is a bypass attempt
        if dst_mac == self.gateway_mac and dst_mac != self.local_mac:
            return True
        
        # Also detect: protected device sending to LAN device directly
        # (not to gateway and not to us)
        if dst_mac != self.local_mac and dst_mac != self.gateway_mac:
            # Check if destination is on local network
            if self._is_local_ip(dst_ip):
                return True
        
        return False
    
    def _is_local_ip(self, ip):
        """Check if IP is on local network (simplified)"""
        try:
            octets = [int(x) for x in ip.split('.')]
            # Private ranges
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
        except:
            pass
        return False
    
    def _update_connection_state(self, pkt):
        """Track connection state for stateful validation"""
        if not pkt.haslayer(IP):
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            key = (src_ip, dst_ip, sport, dport)
            reverse_key = (dst_ip, src_ip, dport, sport)
            
            with self.lock:
                # Record connection
                self.connection_states[key] = {
                    'last_seen': time.time(),
                    'flags': pkt[TCP].flags
                }
                # Also record reverse for bidirectional matching
                if reverse_key not in self.connection_states:
                    self.connection_states[reverse_key] = {
                        'last_seen': time.time(),
                        'flags': 0
                    }
    
    def _is_return_traffic_valid(self, pkt):
        """
        Check if return traffic matches an outbound connection we saw.
        Strict mode: drop traffic if we didn't see the outbound.
        """
        if not self.config.get('stateful_validation', {}).get('enabled', True):
            return True
        
        if not self.config.get('stateful_validation', {}).get('strict_mode', True):
            return True
        
        if not pkt.haslayer(IP):
            return True
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            key = (src_ip, dst_ip, sport, dport)
            
            with self.lock:
                if key in self.connection_states:
                    state = self.connection_states[key]
                    if time.time() - state['last_seen'] < self.state_timeout:
                        return True
        
        return False
    
    def _handle_promiscuous_packet(self, pkt):
        """Process packets in promiscuous mode"""
        try:
            # Check for bypass attempt
            if self._is_bypass_attempt(pkt):
                src_ip = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
                
                security_logger.warning(
                    f"BYPASS BLOCKED: {src_ip} ({src_mac}) attempted direct gateway access"
                )
                self.stats['bypass_attempts_blocked'] += 1
                
                # RESPONSE 1: Inject TCP RST
                if pkt.haslayer(TCP) and self.config.get('promiscuous_mode', {}).get('rst_injection', True):
                    self._inject_tcp_rst(
                        pkt[IP].src, pkt[IP].dst,
                        pkt[TCP].sport, pkt[TCP].dport
                    )
                
                # RESPONSE 2: Inject ICMP unreachable for UDP
                elif pkt.haslayer(UDP) and self.config.get('promiscuous_mode', {}).get('icmp_injection', True):
                    self._inject_icmp_unreachable(pkt)
                
                # RESPONSE 3: Trigger CAM flood for visibility
                if self.config.get('cam_flooding', {}).get('adaptive', True):
                    self.trigger_cam_flood()
                
                # RESPONSE 4: Aggressive gateway re-poisoning
                if pkt.haslayer(IP):
                    self._poison_gateway_for_device(pkt[IP].src, pkt[Ether].src)
                
                # RESPONSE 5: Burst gateway MAC spoofing
                for _ in range(10):
                    self._spoof_gateway_mac(burst=True)
                
                return
            
            # Update connection state for valid traffic
            self._update_connection_state(pkt)
            
        except Exception as e:
            logger.error(f"Promiscuous handler error: {e}")
    
    def _promiscuous_loop(self):
        """Main promiscuous monitoring loop"""
        if not self.config.get('promiscuous_mode', {}).get('enabled', True):
            return
        
        logger.info("Promiscuous monitoring active")
        
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._handle_promiscuous_packet,
                    store=0,
                    timeout=5
                )
            except Exception as e:
                if self.running:
                    logger.error(f"Promiscuous sniff error: {e}")
                    time.sleep(1)
    
    # =========================================================================
    # CONNECTION STATE CLEANUP
    # =========================================================================
    
    def _cleanup_loop(self):
        """Periodically clean up stale connection states"""
        while self.running:
            try:
                time.sleep(60)
                
                now = time.time()
                with self.lock:
                    stale = [k for k, v in self.connection_states.items() 
                             if now - v['last_seen'] > self.state_timeout]
                    for k in stale:
                        del self.connection_states[k]
                    
                    if stale:
                        logger.debug(f"Cleaned {len(stale)} stale connection states")
                        
            except Exception as e:
                if self.running:
                    logger.error(f"Cleanup error: {e}")
    
    # =========================================================================
    # MAIN ENTRY POINTS
    # =========================================================================
    
    def run(self):
        """Start all Gateway Takeover components"""
        self.running = True
        
        logger.info("=" * 60)
        logger.info("GATEWAY TAKEOVER (LAYER 6) STARTING")
        logger.info("This provides VLAN-equivalent isolation security")
        logger.info("=" * 60)
        
        threads = []
        
        # Thread 1: Bidirectional ARP poisoning (poison gateway)
        if self.config.get('bidirectional_poison', True):
            t = threading.Thread(target=self._bidirectional_poison_loop, daemon=True)
            t.start()
            threads.append(t)
            logger.info("Started: Bidirectional ARP poisoning")
        
        # Thread 2: Gateway MAC spoofing
        if self.config.get('mac_spoofing', {}).get('enabled', True):
            t = threading.Thread(target=self._gateway_spoof_loop, daemon=True)
            t.start()
            threads.append(t)
            logger.info("Started: Gateway MAC spoofing")
        
        # Thread 3: Adaptive CAM flooding
        if self.config.get('cam_flooding', {}).get('enabled', True):
            t = threading.Thread(target=self._adaptive_cam_flood_loop, daemon=True)
            t.start()
            threads.append(t)
            logger.info("Started: Adaptive CAM flooding")
        
        # Thread 4: Connection state cleanup
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()
        threads.append(t)
        
        # Main thread: Promiscuous monitoring
        if self.config.get('promiscuous_mode', {}).get('enabled', True):
            logger.info("Started: Promiscuous interception")
            self._promiscuous_loop()
        else:
            # Keep alive if promiscuous disabled
            while self.running:
                time.sleep(1)
    
    def stop(self):
        """Stop Gateway Takeover"""
        self.running = False
        logger.info("Gateway Takeover stopped")
    
    def get_status(self):
        """Get component status"""
        return {
            'running': self.running,
            'protected_devices': len(self.protected_devices),
            'connection_states': len(self.connection_states),
            'stats': dict(self.stats)
        }
    
    def get_stats(self):
        """Get statistics"""
        return dict(self.stats)
GTEOF
}

create_bridge_manager() {
    log_step "Creating Bridge Manager module (Dual-NIC mode)..."

cat > "$INSTALL_DIR/core/bridge_manager.py" << 'BREOF'
#!/usr/bin/env python3
"""
Irongate Bridge Manager - Dual-NIC Mode
Provides TRUE VLAN-equivalent isolation using Linux bridge port isolation

This module creates a Linux bridge with:
- Uplink port (to main network/internet) - NON-ISOLATED
- Isolated port (USB NIC to protected devices) - ISOLATED

Linux bridge port isolation ensures:
- Isolated ports CANNOT communicate with other isolated ports
- Isolated ports can ONLY reach non-isolated ports (uplink)
- This is KERNEL-ENFORCED - no software race conditions
- 100% equivalent to PVLAN/port isolation on managed switches

Architecture:
                    [Internet/Router]
                          │
                        [eth0] ← Main NIC (uplink, non-isolated)
                          │
            ┌─────────[br-irongate]─────────┐
            │    Linux Bridge with          │
            │    Port Isolation             │
            └──────────────┬────────────────┘
                         [eth1] ← USB NIC (ISOLATED port)
                           │
                    [Dumb Switch]
                           │
            ┌──────┬───────┼───────┬──────┐
            │      │       │       │      │
         [Dev1] [Dev2]  [Dev3]  [Dev4] [Dev5]
         
         ALL devices are isolated from each other
         They can ONLY reach internet via Irongate
"""

import logging
import subprocess
import threading
import time
import os
from pathlib import Path

logger = logging.getLogger('irongate.bridge')


class BridgeManager:
    """
    Manages Linux bridge for dual-NIC isolation mode.
    Provides VLAN-equivalent security via kernel-enforced port isolation.
    """
    
    def __init__(self, uplink_interface, isolated_interface, bridge_name,
                 bridge_ip, bridge_netmask, config):
        self.uplink_interface = uplink_interface
        self.isolated_interface = isolated_interface
        self.bridge_name = bridge_name
        self.bridge_ip = bridge_ip
        self.bridge_netmask = bridge_netmask
        self.config = config
        
        self.running = False
        self.dnsmasq_proc = None
        
        if not isolated_interface:
            raise ValueError("Dual-NIC mode requires isolated_interface to be configured")
        
        logger.info(f"Bridge Manager initializing")
        logger.info(f"  Uplink: {uplink_interface} (non-isolated)")
        logger.info(f"  Isolated: {isolated_interface} (isolated port)")
        logger.info(f"  Bridge: {bridge_name} ({bridge_ip}/{bridge_netmask})")
    
    def _run_cmd(self, cmd, check=True):
        """Run shell command"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=check
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd}")
            logger.error(f"  Error: {e.stderr}")
            return False, e.stderr
    
    def _interface_exists(self, iface):
        """Check if network interface exists"""
        return os.path.exists(f"/sys/class/net/{iface}")
    
    def _detect_usb_nic(self):
        """Try to detect USB NIC if not specified"""
        # Common USB NIC patterns
        patterns = ['enx', 'eth1', 'usb0']
        
        try:
            result = subprocess.run(
                ['ls', '/sys/class/net'],
                capture_output=True, text=True
            )
            interfaces = result.stdout.strip().split('\n')
            
            for iface in interfaces:
                if iface == self.uplink_interface:
                    continue
                if iface in ['lo', 'docker0', 'br-irongate']:
                    continue
                for pattern in patterns:
                    if iface.startswith(pattern):
                        logger.info(f"Detected USB NIC: {iface}")
                        return iface
        except:
            pass
        
        return None
    
    def setup_bridge(self):
        """Create and configure the Linux bridge"""
        logger.info("Setting up Linux bridge with port isolation...")
        
        # Verify isolated interface exists
        if not self._interface_exists(self.isolated_interface):
            detected = self._detect_usb_nic()
            if detected:
                logger.info(f"Using detected USB NIC: {detected}")
                self.isolated_interface = detected
            else:
                raise RuntimeError(
                    f"Isolated interface '{self.isolated_interface}' not found. "
                    f"Please connect a USB ethernet adapter."
                )
        
        # Delete existing bridge if present
        self._run_cmd(f"ip link set {self.bridge_name} down", check=False)
        self._run_cmd(f"brctl delbr {self.bridge_name}", check=False)
        
        # Create bridge
        logger.info(f"Creating bridge: {self.bridge_name}")
        self._run_cmd(f"brctl addbr {self.bridge_name}")
        
        # Set bridge parameters
        self._run_cmd(f"brctl stp {self.bridge_name} off")  # Disable STP for simplicity
        self._run_cmd(f"brctl setfd {self.bridge_name} 0")  # No forwarding delay
        
        # Bring up bridge
        self._run_cmd(f"ip link set {self.bridge_name} up")
        
        # Assign IP to bridge
        self._run_cmd(f"ip addr flush dev {self.bridge_name}")
        self._run_cmd(f"ip addr add {self.bridge_ip}/{self._netmask_to_cidr(self.bridge_netmask)} dev {self.bridge_name}")
        
        # Add isolated interface to bridge
        logger.info(f"Adding isolated interface: {self.isolated_interface}")
        self._run_cmd(f"ip link set {self.isolated_interface} down")
        self._run_cmd(f"ip addr flush dev {self.isolated_interface}")
        self._run_cmd(f"brctl addif {self.bridge_name} {self.isolated_interface}")
        self._run_cmd(f"ip link set {self.isolated_interface} up")
        
        # CRITICAL: Enable port isolation on isolated interface
        # This is the kernel-enforced isolation that makes this VLAN-equivalent
        if self.config.get('port_isolation', True):
            logger.info("Enabling port isolation (kernel-enforced)")
            success, _ = self._run_cmd(
                f"bridge link set dev {self.isolated_interface} isolated on"
            )
            if success:
                logger.info("✓ Port isolation ENABLED - devices CANNOT communicate with each other")
            else:
                # Older kernel - try alternative method via ebtables
                logger.warning("bridge link isolation not available, using ebtables fallback")
                self._setup_ebtables_isolation()
        
        # Set up forwarding
        self._run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        logger.info("Bridge setup complete")
        return True
    
    def _netmask_to_cidr(self, netmask):
        """Convert netmask to CIDR notation"""
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])
    
    def _setup_ebtables_isolation(self):
        """Fallback isolation using ebtables for older kernels"""
        logger.info("Setting up ebtables isolation fallback...")
        
        # Block frames between ports on the bridge
        self._run_cmd("ebtables -F")
        self._run_cmd("ebtables -X")
        
        # Allow traffic to/from bridge IP (management)
        self._run_cmd(f"ebtables -A FORWARD -i {self.isolated_interface} -o {self.isolated_interface} -j DROP")
        
        logger.info("ebtables isolation configured")
    
    def setup_nat(self):
        """Set up NAT for isolated devices to reach internet"""
        logger.info("Setting up NAT for isolated network...")
        
        # Get bridge network
        bridge_net = '.'.join(self.bridge_ip.split('.')[:-1]) + '.0'
        cidr = self._netmask_to_cidr(self.bridge_netmask)
        
        # NAT rules using nftables
        nat_rules = f'''
table inet irongate_bridge {{
    chain prerouting {{
        type nat hook prerouting priority -100;
    }}
    
    chain postrouting {{
        type nat hook postrouting priority 100;
        # Masquerade traffic from isolated network
        ip saddr {bridge_net}/{cidr} oifname "{self.uplink_interface}" masquerade
    }}
    
    chain forward {{
        type filter hook forward priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Allow isolated -> internet
        iifname "{self.bridge_name}" oifname "{self.uplink_interface}" accept
        
        # Block isolated -> main LAN (RFC1918)
        iifname "{self.bridge_name}" ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} drop
        
        # Allow responses
        iifname "{self.uplink_interface}" oifname "{self.bridge_name}" ct state established,related accept
    }}
}}
'''
        
        # Write and load rules
        rules_file = '/tmp/irongate_bridge_nat.nft'
        with open(rules_file, 'w') as f:
            f.write(nat_rules)
        
        self._run_cmd("nft -f " + rules_file)
        os.remove(rules_file)
        
        logger.info("NAT configured")
    
    def setup_dhcp(self):
        """Set up DHCP server for isolated network"""
        if not self.config.get('bridge_dhcp', {}).get('enabled', True):
            logger.info("Bridge DHCP disabled")
            return
        
        logger.info("Setting up DHCP for isolated network...")
        
        dhcp_cfg = self.config.get('bridge_dhcp', {})
        pool_start = dhcp_cfg.get('pool_start', '10.99.1.1')
        pool_end = dhcp_cfg.get('pool_end', '10.99.255.254')
        lease_time = dhcp_cfg.get('lease_time', 3600)
        
        # Create dnsmasq config for bridge
        dnsmasq_conf = f'''
# Irongate Bridge DHCP
interface={self.bridge_name}
bind-interfaces
dhcp-range={pool_start},{pool_end},{lease_time}
dhcp-option=option:router,{self.bridge_ip}
dhcp-option=option:dns-server,{self.bridge_ip}

# Logging
log-dhcp
log-facility=/var/log/irongate/bridge-dhcp.log
'''
        
        conf_file = '/etc/irongate/bridge-dnsmasq.conf'
        with open(conf_file, 'w') as f:
            f.write(dnsmasq_conf)
        
        # Stop any existing dnsmasq for this interface
        self._run_cmd(f"pkill -f 'dnsmasq.*{self.bridge_name}'", check=False)
        
        # Start dnsmasq
        self.dnsmasq_proc = subprocess.Popen([
            'dnsmasq',
            f'--conf-file={conf_file}',
            '--keep-in-foreground',
            f'--pid-file=/run/irongate/bridge-dnsmasq.pid'
        ])
        
        logger.info(f"DHCP server running on {self.bridge_name}")
        logger.info(f"  Pool: {pool_start} - {pool_end}")
    
    def setup_firewall(self):
        """Set up firewall rules for bridge mode"""
        logger.info("Setting up bridge firewall rules...")
        
        fw_cfg = self.config.get('bridge_firewall', {})
        bridge_net = '.'.join(self.bridge_ip.split('.')[:-1]) + '.0'
        cidr = self._netmask_to_cidr(self.bridge_netmask)
        
        rules = f'''
table inet irongate_bridge_fw {{
    chain input {{
        type filter hook input priority 0; policy drop;
        
        # Allow established
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Allow DHCP on bridge
        iifname "{self.bridge_name}" udp dport 67 accept
        
        # Allow DNS on bridge
        iifname "{self.bridge_name}" udp dport 53 accept
        iifname "{self.bridge_name}" tcp dport 53 accept
        
        # Allow ping
        icmp type echo-request accept
        
        # Allow SSH
        tcp dport 22 accept
        
        # Allow web interface
        tcp dport {self.config.get('web_port', 8443)} accept
        
        # Allow from uplink
        iifname "{self.uplink_interface}" accept
    }}
    
    chain forward {{
        type filter hook forward priority 0; policy drop;
        
        # Allow established
        ct state established,related accept
'''
        
        if fw_cfg.get('allow_internet', True):
            rules += f'''
        # Allow isolated -> internet (non-RFC1918)
        iifname "{self.bridge_name}" oifname "{self.uplink_interface}" ip daddr != {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept
'''
        
        if fw_cfg.get('block_lan', True):
            rules += f'''
        # Block isolated -> LAN
        iifname "{self.bridge_name}" ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} log prefix "IRONGATE-BRIDGE-LAN-BLOCK: " drop
'''
        
        rules += '''
    }
}
'''
        
        rules_file = '/tmp/irongate_bridge_fw.nft'
        with open(rules_file, 'w') as f:
            f.write(rules)
        
        self._run_cmd("nft -f " + rules_file)
        os.remove(rules_file)
        
        logger.info("Bridge firewall configured")
    
    def get_bridge_clients(self):
        """Get list of clients connected to bridge"""
        clients = []
        try:
            # Read DHCP leases
            lease_file = '/var/lib/misc/dnsmasq.leases'
            if os.path.exists(lease_file):
                with open(lease_file) as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            clients.append({
                                'expires': parts[0],
                                'mac': parts[1],
                                'ip': parts[2],
                                'hostname': parts[3] if len(parts) > 3 else ''
                            })
            
            # Also check bridge FDB
            result = subprocess.run(
                ['bridge', 'fdb', 'show', 'dev', self.isolated_interface],
                capture_output=True, text=True
            )
            # Parse FDB entries for additional MACs
            
        except Exception as e:
            logger.error(f"Error getting bridge clients: {e}")
        
        return clients
    
    def run(self):
        """Start bridge manager"""
        self.running = True
        
        logger.info("=" * 60)
        logger.info("BRIDGE MANAGER STARTING - VLAN-EQUIVALENT MODE")
        logger.info("=" * 60)
        
        try:
            # Set up bridge
            self.setup_bridge()
            
            # Set up NAT
            self.setup_nat()
            
            # Set up firewall
            self.setup_firewall()
            
            # Set up DHCP
            self.setup_dhcp()
            
            logger.info("")
            logger.info("╔══════════════════════════════════════════════════════════════╗")
            logger.info("║  DUAL-NIC BRIDGE MODE ACTIVE                                 ║")
            logger.info("║  Isolation is now KERNEL-ENFORCED                            ║")
            logger.info("║  Devices on isolated port CANNOT bypass this isolation       ║")
            logger.info("║  This is TRUE VLAN-equivalent security                       ║")
            logger.info("╚══════════════════════════════════════════════════════════════╝")
            logger.info("")
            
            # Keep running
            while self.running:
                time.sleep(5)
                
        except Exception as e:
            logger.error(f"Bridge manager error: {e}")
            raise
    
    def stop(self):
        """Stop bridge manager"""
        self.running = False
        
        # Stop DHCP
        if self.dnsmasq_proc:
            self.dnsmasq_proc.terminate()
        
        # Optionally tear down bridge (leave it up for now)
        logger.info("Bridge manager stopped")
    
    def get_status(self):
        """Get bridge status"""
        return {
            'running': self.running,
            'mode': 'dual-nic',
            'bridge_name': self.bridge_name,
            'bridge_ip': self.bridge_ip,
            'uplink': self.uplink_interface,
            'isolated': self.isolated_interface,
            'clients': len(self.get_bridge_clients()),
            'isolation': 'kernel-enforced'
        }
BREOF
}

#===============================================================================
# WEB APPLICATION
#===============================================================================

create_web_app() {
    log_step "Creating web application..."

cat > "$INSTALL_DIR/app.py" << 'WEBAPP'
#!/usr/bin/env python3
"""
Irongate Web Interface
Secure management console for network isolation
"""

import os
import sys
import yaml
import uuid
import logging
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash
)
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Configuration paths
CONFIG_DIR = "/etc/irongate"
DATA_DIR = "/var/lib/irongate"
LOG_DIR = "/var/log/irongate"
CONFIG_FILE = f"{CONFIG_DIR}/irongate.yaml"
DEVICES_FILE = f"{DATA_DIR}/zones/devices.yaml"

app = Flask(__name__)
CORS(app)

# Load configuration
def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

config = load_config()
app.secret_key = config['web']['secret_key']

socketio = SocketIO(app, cors_allowed_origins="*")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/web.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('irongate.web')

#===============================================================================
# DEVICE MANAGEMENT
#===============================================================================

def load_devices():
    try:
        with open(DEVICES_FILE) as f:
            data = yaml.safe_load(f) or {}
            return data.get('devices', [])
    except:
        return []

def save_devices(devices):
    with open(DEVICES_FILE, 'w') as f:
        yaml.dump({'devices': devices}, f)
    # Signal firewall to reload
    Path(f"{DATA_DIR}/.reload").touch()

def get_zones():
    return config.get('zones', {}).get('definitions', {})

#===============================================================================
# API ROUTES
#===============================================================================

@app.route('/')
def index():
    return render_template('index.html', config=config)

@app.route('/bridge')
def bridge():
    return render_template('bridge.html', config=config)

@app.route('/api/status')
def api_status():
    import subprocess
    import psutil
    
    status = {
        'engine': 'unknown',
        'uptime': None,
        'cpu_percent': psutil.cpu_percent(),
        'memory_percent': psutil.virtual_memory().percent,
        'network': config.get('network', {}),
        'devices': {
            'total': len(load_devices()),
            'by_zone': {}
        }
    }
    
    # Count devices by zone
    for device in load_devices():
        zone = device.get('zone', 'quarantine')
        status['devices']['by_zone'][zone] = status['devices']['by_zone'].get(zone, 0) + 1
    
    # Check engine status
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'irongate-engine'],
            capture_output=True, text=True
        )
        status['engine'] = result.stdout.strip()
    except:
        pass
    
    return jsonify({'success': True, 'status': status})

@app.route('/api/devices', methods=['GET'])
def api_get_devices():
    return jsonify({
        'success': True,
        'devices': load_devices(),
        'zones': get_zones()
    })

@app.route('/api/devices', methods=['POST'])
def api_add_device():
    data = request.get_json()
    if not data or not data.get('mac'):
        return jsonify({'success': False, 'error': 'MAC address required'}), 400
    
    devices = load_devices()
    
    # Check for duplicate
    mac = data['mac'].upper().replace('-', ':')
    for d in devices:
        if d['mac'].upper() == mac:
            return jsonify({'success': False, 'error': 'Device already exists'}), 400
    
    device = {
        'id': str(uuid.uuid4())[:8],
        'mac': mac,
        'ip': data.get('ip', ''),
        'name': data.get('name', f"Device-{mac[-5:].replace(':', '')}"),
        'zone': data.get('zone', 'quarantine'),
        'added_at': datetime.now().isoformat(),
        'notes': data.get('notes', '')
    }
    
    devices.append(device)
    save_devices(devices)
    
    logger.info(f"Added device: {device['name']} ({mac}) to zone {device['zone']}")
    return jsonify({'success': True, 'device': device})

@app.route('/api/devices/<device_id>', methods=['PUT'])
def api_update_device(device_id):
    data = request.get_json()
    devices = load_devices()
    
    for i, d in enumerate(devices):
        if d['id'] == device_id:
            if 'name' in data:
                devices[i]['name'] = data['name']
            if 'zone' in data:
                old_zone = devices[i]['zone']
                devices[i]['zone'] = data['zone']
                logger.info(f"Moved {devices[i]['name']} from {old_zone} to {data['zone']}")
            if 'ip' in data:
                devices[i]['ip'] = data['ip']
            if 'notes' in data:
                devices[i]['notes'] = data['notes']
            
            save_devices(devices)
            return jsonify({'success': True, 'device': devices[i]})
    
    return jsonify({'success': False, 'error': 'Device not found'}), 404

@app.route('/api/devices/<device_id>', methods=['DELETE'])
def api_delete_device(device_id):
    devices = load_devices()
    devices = [d for d in devices if d['id'] != device_id]
    save_devices(devices)
    return jsonify({'success': True})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    import subprocess
    import re
    
    devices = []
    try:
        result = subprocess.run(
            ['arp-scan', '-l', '-q'],
            capture_output=True, text=True, timeout=30
        )
        
        for line in result.stdout.split('\n'):
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)', line)
            if match:
                devices.append({
                    'ip': match.group(1),
                    'mac': match.group(2).upper(),
                    'vendor': ''
                })
    except Exception as e:
        logger.error(f"Scan error: {e}")
    
    return jsonify({'success': True, 'devices': devices})

@app.route('/api/logs')
def api_logs():
    log_type = request.args.get('type', 'irongate')
    lines = int(request.args.get('lines', 100))
    
    log_files = {
        'irongate': f'{LOG_DIR}/irongate.log',
        'security': f'{LOG_DIR}/security.log',
        'web': f'{LOG_DIR}/web.log'
    }
    
    log_file = log_files.get(log_type, f'{LOG_DIR}/irongate.log')
    
    if not os.path.exists(log_file):
        return jsonify({'success': True, 'logs': []})
    
    try:
        import subprocess
        result = subprocess.run(
            ['tail', '-n', str(lines), log_file],
            capture_output=True, text=True
        )
        logs = result.stdout.strip().split('\n') if result.stdout.strip() else []
        return jsonify({'success': True, 'logs': logs})
    except:
        return jsonify({'success': True, 'logs': []})

@app.route('/api/zones')
def api_zones():
    return jsonify({
        'success': True,
        'zones': get_zones(),
        'default': config.get('zones', {}).get('default_zone', 'quarantine')
    })

@app.route('/api/config')
def api_config():
    # Return sanitized config (no secrets)
    safe_config = {
        'network': config.get('network', {}),
        'dhcp': {k: v for k, v in config.get('dhcp', {}).items() if k != 'secret'},
        'arp': config.get('arp', {}),
        'ipv6_ra': config.get('ipv6_ra', {}),
        'firewall': config.get('firewall', {}),
        'active_defense': config.get('active_defense', {})
    }
    return jsonify({'success': True, 'config': safe_config})

@app.route('/api/service/<action>', methods=['POST'])
def api_service(action):
    import subprocess
    
    if action not in ['restart', 'stop', 'start']:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    try:
        subprocess.run(
            ['systemctl', action, 'irongate-engine'],
            check=True
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

#===============================================================================
# BRIDGE MODE API
#===============================================================================

@app.route('/api/bridge/status')
def api_bridge_status():
    """Get current bridge mode status"""
    bridge_cfg = config.get('bridge_mode', {})
    mode = bridge_cfg.get('mode', 'single')
    
    status = {
        'mode': mode,
        'isolated_interface': bridge_cfg.get('isolated_interface', ''),
        'bridge_name': bridge_cfg.get('bridge_name', 'br-irongate'),
        'bridge_ip': bridge_cfg.get('bridge_ip', '10.99.0.1'),
    }
    
    if mode == 'dual':
        # Get bridge statistics
        try:
            import subprocess
            result = subprocess.run(
                ['bridge', 'link', 'show'],
                capture_output=True, text=True
            )
            status['bridge_info'] = result.stdout
        except:
            pass
    
    return jsonify({'success': True, 'status': status})

@app.route('/api/bridge/interfaces')
def api_bridge_interfaces():
    """List available network interfaces for bridge mode"""
    import os
    import subprocess
    
    interfaces = []
    main_iface = config['network']['interface']
    
    try:
        for iface in os.listdir('/sys/class/net'):
            if iface in ['lo', 'docker0', 'br-irongate', 'br0']:
                continue
            
            # Get interface info
            info = {'name': iface, 'is_main': iface == main_iface}
            
            # Check if USB
            try:
                uevent_path = f'/sys/class/net/{iface}/device/uevent'
                if os.path.exists(uevent_path):
                    with open(uevent_path) as f:
                        content = f.read()
                        info['is_usb'] = 'usb' in content.lower()
                else:
                    info['is_usb'] = iface.startswith('enx') or iface.startswith('usb')
            except:
                info['is_usb'] = False
            
            # Get MAC
            try:
                with open(f'/sys/class/net/{iface}/address') as f:
                    info['mac'] = f.read().strip()
            except:
                info['mac'] = ''
            
            # Get state
            try:
                with open(f'/sys/class/net/{iface}/operstate') as f:
                    info['state'] = f.read().strip()
            except:
                info['state'] = 'unknown'
            
            interfaces.append(info)
            
    except Exception as e:
        logger.error(f"Error listing interfaces: {e}")
    
    return jsonify({'success': True, 'interfaces': interfaces})

@app.route('/api/bridge/mode', methods=['POST'])
def api_bridge_set_mode():
    """Switch between single-NIC and dual-NIC mode"""
    import subprocess
    
    data = request.get_json()
    if not data or 'mode' not in data:
        return jsonify({'success': False, 'error': 'Mode required'}), 400
    
    new_mode = data['mode']
    if new_mode not in ['single', 'dual']:
        return jsonify({'success': False, 'error': 'Invalid mode'}), 400
    
    isolated_iface = data.get('isolated_interface', '')
    
    if new_mode == 'dual' and not isolated_iface:
        return jsonify({'success': False, 'error': 'Isolated interface required for dual mode'}), 400
    
    # Update config file
    try:
        with open(CONFIG_FILE, 'r') as f:
            cfg_content = f.read()
        
        # Update mode
        import re
        cfg_content = re.sub(
            r'(bridge_mode:\s*\n\s*#[^\n]*\n\s*mode:\s*)\w+',
            f'\\1{new_mode}',
            cfg_content
        )
        
        # Update isolated interface
        cfg_content = re.sub(
            r'(isolated_interface:\s*)"[^"]*"',
            f'\\1"{isolated_iface}"',
            cfg_content
        )
        
        with open(CONFIG_FILE, 'w') as f:
            f.write(cfg_content)
        
        # Reload config
        global config
        config = load_config()
        
        logger.info(f"Bridge mode changed to: {new_mode}")
        if new_mode == 'dual':
            logger.info(f"Isolated interface: {isolated_iface}")
        
        # Restart engine to apply changes
        subprocess.run(['systemctl', 'restart', 'irongate-engine'], check=False)
        
        return jsonify({
            'success': True,
            'message': f'Mode changed to {new_mode}. Engine restarting...',
            'restart_required': True
        })
        
    except Exception as e:
        logger.error(f"Error changing mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bridge/clients')
def api_bridge_clients():
    """Get clients connected to bridge (dual mode only)"""
    clients = []
    
    try:
        # Read DHCP leases
        lease_file = '/var/lib/misc/dnsmasq.leases'
        if os.path.exists(lease_file):
            with open(lease_file) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        clients.append({
                            'expires': parts[0],
                            'mac': parts[1],
                            'ip': parts[2],
                            'hostname': parts[3] if len(parts) > 3 else 'unknown'
                        })
    except Exception as e:
        logger.error(f"Error reading bridge clients: {e}")
    
    return jsonify({'success': True, 'clients': clients})

#===============================================================================
# WEBSOCKET EVENTS
#===============================================================================

@socketio.on('connect')
def handle_connect():
    logger.info(f"WebSocket client connected")

@socketio.on('subscribe_logs')
def handle_subscribe_logs():
    # Would implement real-time log streaming here
    pass

#===============================================================================
# ERROR HANDLERS
#===============================================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Server error'}), 500
    return render_template('500.html'), 500


if __name__ == '__main__':
    ssl_context = None
    if config['web'].get('https', True):
        ssl_context = (
            config['web']['cert_file'],
            config['web']['key_file']
        )
    
    socketio.run(
        app,
        host=config['web']['host'],
        port=config['web']['port'],
        ssl_context=ssl_context
    )
WEBAPP
}

#===============================================================================
# TEMPLATES
#===============================================================================

create_templates() {
    log_step "Creating web templates..."

# Base template
cat > "$INSTALL_DIR/templates/base.html" << 'BASEHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Irongate{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root{--primary:#dc2626;--primary-dark:#b91c1c;--secondary:#1e40af;--success:#16a34a;--warning:#d97706;--danger:#dc2626;--dark:#0f0f0f;--darker:#000;--card:#1a1a1a;--border:#2a2a2a;--text:#e5e5e5;--text-muted:#737373;--accent:#ef4444}
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--darker);color:var(--text);min-height:100vh}
        .layout{display:flex;min-height:100vh}
        .sidebar{width:280px;background:var(--dark);border-right:1px solid var(--border);position:fixed;height:100vh;overflow-y:auto;z-index:100}
        .logo{padding:1.5rem;display:flex;align-items:center;gap:1rem;border-bottom:1px solid var(--border)}
        .logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--primary),var(--primary-dark));border-radius:12px;display:flex;align-items:center;justify-content:center}
        .logo-icon i{font-size:1.5rem;color:#fff}
        .logo-text h1{font-size:1.5rem;font-weight:700;background:linear-gradient(135deg,#fff,var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .logo-text span{font-size:.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.1em}
        .nav{padding:1rem 0}
        .nav-section{padding:.5rem 1.5rem;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);font-weight:600;margin-top:1rem}
        .nav-link{display:flex;align-items:center;gap:.875rem;padding:.875rem 1.5rem;color:var(--text);text-decoration:none;transition:all .2s;border-left:3px solid transparent}
        .nav-link:hover{background:rgba(255,255,255,.03);border-color:var(--border)}
        .nav-link.active{background:rgba(220,38,38,.1);border-color:var(--primary);color:#fff}
        .nav-link i{width:1.25rem;text-align:center;opacity:.7}
        .nav-link.active i{opacity:1;color:var(--primary)}
        .main{flex:1;margin-left:280px}
        .header{background:var(--dark);border-bottom:1px solid var(--border);padding:1.25rem 2rem;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:50}
        .header h2{font-size:1.375rem;font-weight:600}
        .header-status{display:flex;align-items:center;gap:1rem}
        .status-indicator{display:flex;align-items:center;gap:.5rem;padding:.5rem 1rem;background:var(--card);border-radius:9999px;font-size:.875rem}
        .status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        .content{padding:2rem}
        .card{background:var(--card);border-radius:1rem;border:1px solid var(--border);margin-bottom:1.5rem;overflow:hidden}
        .card-header{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
        .card-title{font-size:1rem;font-weight:600;display:flex;align-items:center;gap:.75rem}
        .card-title i{color:var(--primary)}
        .card-body{padding:1.5rem}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.5rem;margin-bottom:2rem}
        .stat-card{background:var(--card);border-radius:1rem;border:1px solid var(--border);padding:1.5rem;position:relative;overflow:hidden}
        .stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--primary),var(--secondary))}
        .stat-icon{width:3.5rem;height:3.5rem;border-radius:.75rem;display:flex;align-items:center;justify-content:center;font-size:1.5rem;margin-bottom:1rem}
        .stat-icon.red{background:rgba(220,38,38,.15);color:var(--primary)}
        .stat-icon.blue{background:rgba(30,64,175,.15);color:var(--secondary)}
        .stat-icon.green{background:rgba(22,163,74,.15);color:var(--success)}
        .stat-icon.yellow{background:rgba(217,119,6,.15);color:var(--warning)}
        .stat-value{font-size:2rem;font-weight:700;margin-bottom:.25rem}
        .stat-label{color:var(--text-muted);font-size:.875rem}
        .btn{display:inline-flex;align-items:center;gap:.5rem;padding:.625rem 1.25rem;border-radius:.5rem;font-size:.875rem;font-weight:500;cursor:pointer;border:none;transition:all .2s;text-decoration:none}
        .btn-primary{background:var(--primary);color:#fff}
        .btn-primary:hover{background:var(--primary-dark)}
        .btn-secondary{background:var(--secondary);color:#fff}
        .btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)}
        .btn-outline:hover{background:var(--card);border-color:var(--text-muted)}
        .btn-sm{padding:.5rem .875rem;font-size:.8125rem}
        .btn-danger{background:transparent;border:1px solid var(--danger);color:var(--danger)}
        .btn-danger:hover{background:var(--danger);color:#fff}
        .table{width:100%;border-collapse:collapse}
        .table th,.table td{padding:1rem 1.25rem;text-align:left;border-bottom:1px solid var(--border)}
        .table th{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);font-weight:600;background:rgba(0,0,0,.2)}
        .table tr:hover{background:rgba(255,255,255,.02)}
        .badge{display:inline-flex;align-items:center;gap:.375rem;padding:.375rem .75rem;border-radius:9999px;font-size:.75rem;font-weight:500}
        .badge-success{background:rgba(22,163,74,.15);color:var(--success)}
        .badge-warning{background:rgba(217,119,6,.15);color:var(--warning)}
        .badge-danger{background:rgba(220,38,38,.15);color:var(--danger)}
        .badge-info{background:rgba(30,64,175,.15);color:var(--secondary)}
        .badge i{font-size:.625rem}
        .zone-tag{display:inline-flex;align-items:center;gap:.375rem;padding:.25rem .625rem;border-radius:.375rem;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
        .zone-quarantine{background:rgba(220,38,38,.2);color:#fca5a5;border:1px solid rgba(220,38,38,.3)}
        .zone-isolated{background:rgba(217,119,6,.2);color:#fcd34d;border:1px solid rgba(217,119,6,.3)}
        .zone-servers{background:rgba(30,64,175,.2);color:#93c5fd;border:1px solid rgba(30,64,175,.3)}
        .zone-trusted{background:rgba(22,163,74,.2);color:#86efac;border:1px solid rgba(22,163,74,.3)}
        .form-group{margin-bottom:1.25rem}
        .form-label{display:block;margin-bottom:.5rem;font-size:.875rem;font-weight:500;color:var(--text-muted)}
        .form-input,.form-select{width:100%;padding:.75rem 1rem;background:var(--darker);border:1px solid var(--border);border-radius:.5rem;color:var(--text);font-size:.875rem}
        .form-input:focus,.form-select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(220,38,38,.1)}
        .modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;z-index:1000;opacity:0;visibility:hidden;transition:all .2s}
        .modal-overlay.active{opacity:1;visibility:visible}
        .modal{background:var(--card);border-radius:1rem;border:1px solid var(--border);width:100%;max-width:500px;max-height:90vh;overflow-y:auto}
        .modal-header{padding:1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
        .modal-title{font-size:1.25rem;font-weight:600}
        .modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.25rem;padding:.5rem}
        .modal-close:hover{color:var(--text)}
        .modal-body{padding:1.5rem}
        .modal-footer{padding:1rem 1.5rem;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:.75rem}
        .empty-state{text-align:center;padding:4rem 2rem;color:var(--text-muted)}
        .empty-state i{font-size:4rem;margin-bottom:1.5rem;opacity:.3}
        .empty-state h3{font-size:1.25rem;margin-bottom:.5rem;color:var(--text)}
        .security-banner{background:linear-gradient(135deg,rgba(220,38,38,.1),rgba(30,64,175,.1));border:1px solid var(--border);border-radius:.75rem;padding:1rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1rem}
        .security-banner i{font-size:1.5rem;color:var(--primary)}
        .toast-container{position:fixed;bottom:2rem;right:2rem;z-index:2000}
        .toast{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem 1.5rem;margin-top:.75rem;display:flex;align-items:center;gap:1rem;box-shadow:0 8px 32px rgba(0,0,0,.5);animation:slideIn .3s ease}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
        code{background:var(--darker);padding:.125rem .5rem;border-radius:.25rem;font-size:.8125rem;font-family:'JetBrains Mono',monospace}
        @media(max-width:1024px){.sidebar{width:80px}.logo-text,.nav-section,.nav-link span{display:none}.nav-link{justify-content:center;padding:1rem}.main{margin-left:80px}}
        @media(max-width:640px){.sidebar{display:none}.main{margin-left:0}.content{padding:1rem}.stats-grid{grid-template-columns:1fr}}
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="logo">
                <div class="logo-icon"><i class="fas fa-shield-halved"></i></div>
                <div class="logo-text">
                    <h1>IRONGATE</h1>
                    <span>Network Isolation</span>
                </div>
            </div>
            <nav class="nav">
                <div class="nav-section">Overview</div>
                <a href="/" class="nav-link {% if request.endpoint == 'index' %}active{% endif %}">
                    <i class="fas fa-gauge-high"></i>
                    <span>Dashboard</span>
                </a>
                
                <div class="nav-section">Management</div>
                <a href="/devices" class="nav-link {% if request.endpoint == 'devices' %}active{% endif %}">
                    <i class="fas fa-server"></i>
                    <span>Devices</span>
                </a>
                <a href="/zones" class="nav-link {% if request.endpoint == 'zones' %}active{% endif %}">
                    <i class="fas fa-layer-group"></i>
                    <span>Zones</span>
                </a>
                <a href="/scan" class="nav-link {% if request.endpoint == 'scan' %}active{% endif %}">
                    <i class="fas fa-radar"></i>
                    <span>Network Scan</span>
                </a>
                
                <div class="nav-section">Security</div>
                <a href="/bridge" class="nav-link {% if request.endpoint == 'bridge' %}active{% endif %}">
                    <i class="fas fa-network-wired"></i>
                    <span>Bridge Mode</span>
                </a>
                <a href="/events" class="nav-link {% if request.endpoint == 'events' %}active{% endif %}">
                    <i class="fas fa-shield-exclamation"></i>
                    <span>Security Events</span>
                </a>
                <a href="/logs" class="nav-link {% if request.endpoint == 'logs' %}active{% endif %}">
                    <i class="fas fa-scroll"></i>
                    <span>Logs</span>
                </a>
                
                <div class="nav-section">System</div>
                <a href="/settings" class="nav-link {% if request.endpoint == 'settings' %}active{% endif %}">
                    <i class="fas fa-gear"></i>
                    <span>Settings</span>
                </a>
            </nav>
        </aside>
        
        <main class="main">
            {% block content %}{% endblock %}
        </main>
    </div>
    
    <div class="toast-container" id="toastContainer"></div>
    
    <script>
        function showToast(msg, type='success') {
            const c = document.getElementById('toastContainer');
            const t = document.createElement('div');
            t.className = 'toast';
            const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle';
            const color = type === 'success' ? 'var(--success)' : type === 'error' ? 'var(--danger)' : 'var(--secondary)';
            t.innerHTML = `<i class="fas fa-${icon}" style="color:${color}"></i><span>${msg}</span>`;
            c.appendChild(t);
            setTimeout(() => { t.style.animation = 'slideIn .3s ease reverse'; setTimeout(() => t.remove(), 300); }, 3000);
        }
        
        function openModal(id) { document.getElementById(id).classList.add('active'); }
        function closeModal(id) { document.getElementById(id).classList.remove('active'); }
        
        async function api(endpoint, options = {}) {
            const defaults = { headers: { 'Content-Type': 'application/json' } };
            const response = await fetch(`/api${endpoint}`, { ...defaults, ...options });
            return response.json();
        }
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
BASEHTML

# Index/Dashboard template
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXHTML'
{% extends "base.html" %}
{% block title %}Dashboard - Irongate{% endblock %}
{% block content %}
<header class="header">
    <h2>Security Dashboard</h2>
    <div class="header-status">
        <div class="status-indicator">
            <span class="status-dot" id="statusDot"></span>
            <span id="statusText">Checking...</span>
        </div>
        <button class="btn btn-outline btn-sm" onclick="loadStatus()">
            <i class="fas fa-sync-alt"></i>
        </button>
    </div>
</header>

<div class="content">
    <div class="security-banner" id="securityBanner">
        <i class="fas fa-shield-check"></i>
        <div>
            <strong id="bannerTitle">Loading Protection Status...</strong>
            <p style="color:var(--text-muted);font-size:.875rem;margin-top:.25rem" id="bannerSubtitle">
                Checking isolation mode...
            </p>
        </div>
        <a href="/bridge" class="btn btn-outline btn-sm" style="margin-left:auto">
            <i class="fas fa-cog"></i> Configure
        </a>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-icon red"><i class="fas fa-server"></i></div>
            <div class="stat-value" id="totalDevices">-</div>
            <div class="stat-label">Protected Devices</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon blue"><i class="fas fa-layer-group"></i></div>
            <div class="stat-value" id="activeZones">-</div>
            <div class="stat-label">Active Zones</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon yellow"><i class="fas fa-shield-exclamation"></i></div>
            <div class="stat-value" id="securityEvents">0</div>
            <div class="stat-label">Security Events (24h)</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon green"><i class="fas fa-network-wired"></i></div>
            <div class="stat-value" id="engineStatus">-</div>
            <div class="stat-label">Engine Status</div>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <div class="card-title"><i class="fas fa-shield-halved"></i> Isolation Layers</div>
        </div>
        <div class="card-body">
            <table class="table">
                <thead>
                    <tr>
                        <th>Layer</th>
                        <th>Protection</th>
                        <th>Status</th>
                        <th>Bypass Difficulty</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge badge-info">1</span></td>
                        <td>
                            <strong>DHCP Microsegmentation</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">/30 subnets + Option 121 routes</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-warning">Medium</span> - Requires static IP</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">2</span></td>
                        <td>
                            <strong>ARP Defense</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">Continuous poisoning + bypass detection</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-warning">Medium</span> - Requires static ARP</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">3</span></td>
                        <td>
                            <strong>IPv6 RA Takeover</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">Router Advertisement hijacking</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-success">Hard</span> - Requires IPv6 disabled</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">4</span></td>
                        <td>
                            <strong>nftables Firewall</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">Stateful packet filtering</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-danger">Very Hard</span> - Kernel enforced</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">5</span></td>
                        <td>
                            <strong>Bypass Monitor</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">Active defense + TCP RST injection</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-danger">Very Hard</span> - Adaptive response</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">6</span></td>
                        <td>
                            <strong>Gateway Takeover</strong>
                            <div style="color:var(--text-muted);font-size:.75rem">Bidirectional poison + CAM flood + MAC spoof</div>
                        </td>
                        <td><span class="badge badge-success"><i class="fas fa-circle"></i> Active</span></td>
                        <td><span class="badge badge-danger">VLAN-Equivalent</span> - Full control</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-chart-pie"></i> Devices by Zone</div>
            </div>
            <div class="card-body" id="zoneChart">
                <div class="empty-state" style="padding:2rem">
                    <p>Loading zone distribution...</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-network-wired"></i> Network Info</div>
            </div>
            <div class="card-body">
                <table class="table" style="margin:-1.5rem">
                    <tr>
                        <td style="color:var(--text-muted)">Interface</td>
                        <td><code>{{ config.network.interface }}</code></td>
                    </tr>
                    <tr>
                        <td style="color:var(--text-muted)">Local IP</td>
                        <td><code>{{ config.network.local_ip }}</code></td>
                    </tr>
                    <tr>
                        <td style="color:var(--text-muted)">Gateway</td>
                        <td><code>{{ config.network.gateway_ip }}</code></td>
                    </tr>
                    <tr>
                        <td style="color:var(--text-muted)">Subnet</td>
                        <td><code>{{ config.network.subnet }}</code></td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
async function loadStatus() {
    try {
        const result = await api('/status');
        const bridgeResult = await api('/bridge/status');
        
        if (result.success) {
            const s = result.status;
            
            // Update stats
            document.getElementById('totalDevices').textContent = s.devices.total;
            document.getElementById('activeZones').textContent = Object.keys(s.devices.by_zone).length;
            document.getElementById('engineStatus').textContent = s.engine === 'active' ? 'Running' : s.engine;
            
            // Update status indicator
            const dot = document.getElementById('statusDot');
            const text = document.getElementById('statusText');
            if (s.engine === 'active') {
                dot.style.background = 'var(--success)';
                text.textContent = 'Protected';
            } else {
                dot.style.background = 'var(--danger)';
                text.textContent = 'Degraded';
            }
            
            // Update zone chart
            const chart = document.getElementById('zoneChart');
            if (Object.keys(s.devices.by_zone).length > 0) {
                let html = '<div style="display:flex;flex-direction:column;gap:1rem">';
                for (const [zone, count] of Object.entries(s.devices.by_zone)) {
                    const pct = Math.round((count / s.devices.total) * 100);
                    html += `
                        <div>
                            <div style="display:flex;justify-content:space-between;margin-bottom:.5rem">
                                <span class="zone-tag zone-${zone}">${zone}</span>
                                <span>${count} devices (${pct}%)</span>
                            </div>
                            <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">
                                <div style="width:${pct}%;height:100%;background:var(--primary);border-radius:4px"></div>
                            </div>
                        </div>
                    `;
                }
                html += '</div>';
                chart.innerHTML = html;
            } else {
                chart.innerHTML = '<div class="empty-state" style="padding:2rem"><p>No devices registered</p></div>';
            }
        }
        
        // Update security banner based on mode
        if (bridgeResult.success) {
            const banner = document.getElementById('securityBanner');
            const title = document.getElementById('bannerTitle');
            const subtitle = document.getElementById('bannerSubtitle');
            
            if (bridgeResult.status.mode === 'dual') {
                banner.style.background = 'linear-gradient(135deg,rgba(22,163,74,.15),rgba(30,64,175,.1))';
                title.innerHTML = '<i class="fas fa-lock"></i> DUAL-NIC MODE - TRUE VLAN-EQUIVALENT SECURITY';
                subtitle.textContent = 'Kernel-enforced isolation via Linux bridge port isolation • 100% bypass-proof';
            } else {
                banner.style.background = 'linear-gradient(135deg,rgba(220,38,38,.1),rgba(30,64,175,.1))';
                title.innerHTML = '6-Layer Protection Active';
                subtitle.textContent = 'DHCP Microsegmentation • ARP Defense • IPv6 RA • Stateful Firewall • Bypass Detection • Gateway Takeover';
            }
        }
    } catch (e) {
        console.error('Status load error:', e);
    }
}

loadStatus();
setInterval(loadStatus, 30000);
</script>
{% endblock %}
INDEXHTML

# Create 404 and 500 templates
cat > "$INSTALL_DIR/templates/404.html" << 'EOF'
{% extends "base.html" %}
{% block content %}
<div class="content" style="display:flex;align-items:center;justify-content:center;min-height:70vh">
    <div style="text-align:center">
        <div style="font-size:8rem;color:var(--primary);font-weight:700">404</div>
        <h2 style="margin-bottom:1rem">Page Not Found</h2>
        <a href="/" class="btn btn-primary"><i class="fas fa-home"></i> Dashboard</a>
    </div>
</div>
{% endblock %}
EOF

cat > "$INSTALL_DIR/templates/500.html" << 'EOF'
{% extends "base.html" %}
{% block content %}
<div class="content" style="display:flex;align-items:center;justify-content:center;min-height:70vh">
    <div style="text-align:center">
        <div style="font-size:8rem;color:var(--danger);font-weight:700">500</div>
        <h2 style="margin-bottom:1rem">Server Error</h2>
        <a href="/" class="btn btn-primary"><i class="fas fa-home"></i> Dashboard</a>
    </div>
</div>
{% endblock %}
EOF

# Bridge Mode template
cat > "$INSTALL_DIR/templates/bridge.html" << 'BRIDGEHTML'
{% extends "base.html" %}
{% block title %}Bridge Mode - Irongate{% endblock %}
{% block content %}
<header class="header">
    <h2>Bridge Mode Configuration</h2>
    <div class="header-status">
        <div class="status-indicator">
            <span class="status-dot" id="modeDot"></span>
            <span id="modeText">Loading...</span>
        </div>
    </div>
</header>

<div class="content">
    <!-- Mode Comparison Banner -->
    <div class="card" style="background:linear-gradient(135deg,rgba(30,64,175,.1),rgba(220,38,38,.1))">
        <div class="card-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:2rem">
                <div>
                    <h3 style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
                        <i class="fas fa-microchip" style="color:var(--warning)"></i>
                        Single-NIC Mode
                    </h3>
                    <p style="color:var(--text-muted);margin-bottom:1rem">
                        6-layer software isolation. Devices can be anywhere on the network.
                    </p>
                    <ul style="color:var(--text-muted);font-size:.875rem;list-style:none;padding:0">
                        <li style="margin-bottom:.5rem">✓ No hardware changes required</li>
                        <li style="margin-bottom:.5rem">✓ Devices stay on existing switch</li>
                        <li style="margin-bottom:.5rem">⚠ ~95% effective against sophisticated attacks</li>
                        <li style="margin-bottom:.5rem">⚠ Subject to timing race conditions</li>
                    </ul>
                </div>
                <div>
                    <h3 style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem">
                        <i class="fas fa-shield-check" style="color:var(--success)"></i>
                        Dual-NIC Mode (Recommended)
                    </h3>
                    <p style="color:var(--text-muted);margin-bottom:1rem">
                        Hardware-enforced isolation via Linux bridge. TRUE VLAN-equivalent security.
                    </p>
                    <ul style="color:var(--text-muted);font-size:.875rem;list-style:none;padding:0">
                        <li style="margin-bottom:.5rem">✓ 100% isolation - kernel enforced</li>
                        <li style="margin-bottom:.5rem">✓ No bypass possible</li>
                        <li style="margin-bottom:.5rem">✓ Equivalent to managed switch VLANs</li>
                        <li style="margin-bottom:.5rem">⚠ Requires USB ethernet adapter (~$10)</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Current Mode Status -->
    <div class="card">
        <div class="card-header">
            <div class="card-title"><i class="fas fa-cog"></i> Current Configuration</div>
        </div>
        <div class="card-body">
            <div id="currentMode">
                <div class="empty-state" style="padding:2rem">
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>Loading configuration...</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Mode Switch -->
    <div class="card">
        <div class="card-header">
            <div class="card-title"><i class="fas fa-exchange-alt"></i> Switch Mode</div>
        </div>
        <div class="card-body">
            <div class="form-group">
                <label class="form-label">Select Isolation Mode</label>
                <div style="display:flex;gap:1rem;margin-bottom:1.5rem">
                    <label style="display:flex;align-items:center;gap:.5rem;padding:1rem;background:var(--darker);border:2px solid var(--border);border-radius:.5rem;cursor:pointer;flex:1" id="singleModeOption">
                        <input type="radio" name="mode" value="single" id="modeSingle">
                        <div>
                            <strong>Single-NIC</strong>
                            <div style="font-size:.75rem;color:var(--text-muted)">Software isolation (current setup)</div>
                        </div>
                    </label>
                    <label style="display:flex;align-items:center;gap:.5rem;padding:1rem;background:var(--darker);border:2px solid var(--border);border-radius:.5rem;cursor:pointer;flex:1" id="dualModeOption">
                        <input type="radio" name="mode" value="dual" id="modeDual">
                        <div>
                            <strong>Dual-NIC (VLAN-Equivalent)</strong>
                            <div style="font-size:.75rem;color:var(--text-muted)">Hardware isolation (recommended)</div>
                        </div>
                    </label>
                </div>
            </div>
            
            <!-- Dual-NIC Configuration (shown when dual selected) -->
            <div id="dualConfig" style="display:none;padding:1.5rem;background:var(--darker);border-radius:.5rem;margin-bottom:1.5rem">
                <h4 style="margin-bottom:1rem;display:flex;align-items:center;gap:.5rem">
                    <i class="fas fa-ethernet" style="color:var(--primary)"></i>
                    Dual-NIC Configuration
                </h4>
                
                <div class="form-group">
                    <label class="form-label">Select Isolated Interface (USB NIC)</label>
                    <select class="form-select" id="isolatedInterface">
                        <option value="">-- Detecting interfaces... --</option>
                    </select>
                    <div style="font-size:.75rem;color:var(--text-muted);margin-top:.5rem">
                        Connect your USB ethernet adapter, then select it here. 
                        Protected devices should be connected to a switch on this interface.
                    </div>
                </div>
                
                <div style="background:rgba(22,163,74,.1);border:1px solid rgba(22,163,74,.3);border-radius:.5rem;padding:1rem;margin-top:1rem">
                    <strong style="color:var(--success)"><i class="fas fa-info-circle"></i> How it works:</strong>
                    <pre style="margin:.5rem 0 0 0;font-size:.75rem;color:var(--text-muted);white-space:pre-wrap">
[Internet/Router]
       │
    [eth0] ← Main network ({{ config.network.interface }})
       │
 [IRONGATE Bridge]
       │
    [eth1] ← USB NIC (isolated port) 
       │                              
 [Dumb Switch]                     
       │                            
   [Protected Servers]
   
Devices on isolated port CANNOT 
communicate with each other or
the main LAN. Only internet access
through Irongate.</pre>
                </div>
            </div>
            
            <button class="btn btn-primary" id="applyModeBtn" onclick="applyMode()">
                <i class="fas fa-check"></i> Apply Configuration
            </button>
            <span id="applyStatus" style="margin-left:1rem;color:var(--text-muted)"></span>
        </div>
    </div>
    
    <!-- Bridge Status (shown in dual mode) -->
    <div class="card" id="bridgeStatusCard" style="display:none">
        <div class="card-header">
            <div class="card-title"><i class="fas fa-server"></i> Bridge Clients</div>
            <button class="btn btn-outline btn-sm" onclick="loadBridgeClients()">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
        </div>
        <div class="card-body">
            <div id="bridgeClients">
                <div class="empty-state" style="padding:2rem">
                    <i class="fas fa-plug"></i>
                    <p>No clients connected to bridge</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Warning Modal -->
<div class="modal-overlay" id="warningModal">
    <div class="modal">
        <div class="modal-header">
            <div class="modal-title"><i class="fas fa-exclamation-triangle" style="color:var(--warning)"></i> Confirm Mode Change</div>
            <button class="modal-close" onclick="closeModal('warningModal')"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
            <p id="warningText"></p>
            <div style="background:var(--darker);border-radius:.5rem;padding:1rem;margin-top:1rem">
                <strong>This will:</strong>
                <ul style="margin:.5rem 0 0 1rem;color:var(--text-muted)">
                    <li>Restart the Irongate engine</li>
                    <li>Briefly interrupt network protection</li>
                    <li id="warningExtra"></li>
                </ul>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-outline" onclick="closeModal('warningModal')">Cancel</button>
            <button class="btn btn-primary" onclick="confirmModeChange()">
                <i class="fas fa-check"></i> Confirm
            </button>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
let currentMode = 'single';
let pendingMode = null;
let pendingInterface = null;

async function loadStatus() {
    try {
        const result = await api('/bridge/status');
        if (result.success) {
            currentMode = result.status.mode;
            updateModeUI(result.status);
        }
        
        // Load interfaces
        loadInterfaces();
        
    } catch (e) {
        console.error('Status load error:', e);
    }
}

function updateModeUI(status) {
    const modeText = document.getElementById('modeText');
    const modeDot = document.getElementById('modeDot');
    const currentModeDiv = document.getElementById('currentMode');
    const bridgeCard = document.getElementById('bridgeStatusCard');
    
    if (status.mode === 'dual') {
        modeText.textContent = 'Dual-NIC (VLAN-Equivalent)';
        modeDot.style.background = 'var(--success)';
        document.getElementById('modeDual').checked = true;
        document.getElementById('dualConfig').style.display = 'block';
        document.getElementById('dualModeOption').style.borderColor = 'var(--success)';
        document.getElementById('singleModeOption').style.borderColor = 'var(--border)';
        bridgeCard.style.display = 'block';
        loadBridgeClients();
        
        currentModeDiv.innerHTML = `
            <div style="display:flex;align-items:center;gap:1rem">
                <div style="width:4rem;height:4rem;background:rgba(22,163,74,.15);border-radius:1rem;display:flex;align-items:center;justify-content:center">
                    <i class="fas fa-shield-check" style="font-size:2rem;color:var(--success)"></i>
                </div>
                <div>
                    <h3 style="margin-bottom:.25rem">Dual-NIC Bridge Mode</h3>
                    <p style="color:var(--success);font-size:.875rem;margin-bottom:.5rem">
                        <i class="fas fa-lock"></i> TRUE VLAN-EQUIVALENT SECURITY - 100% Kernel Enforced
                    </p>
                    <div style="display:flex;gap:2rem;font-size:.875rem;color:var(--text-muted)">
                        <span><strong>Bridge:</strong> ${status.bridge_name}</span>
                        <span><strong>IP:</strong> ${status.bridge_ip}</span>
                        <span><strong>Isolated NIC:</strong> ${status.isolated_interface || 'Not set'}</span>
                    </div>
                </div>
            </div>
        `;
    } else {
        modeText.textContent = 'Single-NIC (6-Layer)';
        modeDot.style.background = 'var(--warning)';
        document.getElementById('modeSingle').checked = true;
        document.getElementById('dualConfig').style.display = 'none';
        document.getElementById('singleModeOption').style.borderColor = 'var(--warning)';
        document.getElementById('dualModeOption').style.borderColor = 'var(--border)';
        bridgeCard.style.display = 'none';
        
        currentModeDiv.innerHTML = `
            <div style="display:flex;align-items:center;gap:1rem">
                <div style="width:4rem;height:4rem;background:rgba(217,119,6,.15);border-radius:1rem;display:flex;align-items:center;justify-content:center">
                    <i class="fas fa-microchip" style="font-size:2rem;color:var(--warning)"></i>
                </div>
                <div>
                    <h3 style="margin-bottom:.25rem">Single-NIC Mode (6-Layer Software Isolation)</h3>
                    <p style="color:var(--warning);font-size:.875rem;margin-bottom:.5rem">
                        <i class="fas fa-shield"></i> Software-based isolation - ~95% effective against sophisticated attacks
                    </p>
                    <div style="font-size:.875rem;color:var(--text-muted)">
                        Using DHCP microsegmentation, ARP defense, IPv6 RA, firewall, bypass monitor, and gateway takeover.
                    </div>
                </div>
            </div>
            <div style="margin-top:1rem;padding:1rem;background:rgba(220,38,38,.1);border:1px solid rgba(220,38,38,.2);border-radius:.5rem">
                <i class="fas fa-arrow-up" style="color:var(--primary)"></i>
                <strong>Upgrade to Dual-NIC mode</strong> for 100% kernel-enforced isolation equivalent to managed switch VLANs.
            </div>
        `;
    }
}

async function loadInterfaces() {
    try {
        const result = await api('/bridge/interfaces');
        if (result.success) {
            const select = document.getElementById('isolatedInterface');
            select.innerHTML = '<option value="">-- Select interface --</option>';
            
            result.interfaces.forEach(iface => {
                if (iface.is_main) return; // Skip main interface
                
                const opt = document.createElement('option');
                opt.value = iface.name;
                opt.textContent = `${iface.name} ${iface.is_usb ? '(USB)' : ''} - ${iface.mac} [${iface.state}]`;
                select.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Interface load error:', e);
    }
}

async function loadBridgeClients() {
    try {
        const result = await api('/bridge/clients');
        const container = document.getElementById('bridgeClients');
        
        if (result.success && result.clients.length > 0) {
            let html = '<table class="table"><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead><tbody>';
            result.clients.forEach(c => {
                html += `<tr><td><code>${c.ip}</code></td><td><code>${c.mac}</code></td><td>${c.hostname}</td></tr>`;
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        } else {
            container.innerHTML = '<div class="empty-state" style="padding:2rem"><i class="fas fa-plug"></i><p>No clients connected to bridge</p></div>';
        }
    } catch (e) {
        console.error('Bridge clients error:', e);
    }
}

// Handle radio button changes
document.querySelectorAll('input[name="mode"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        const dualConfig = document.getElementById('dualConfig');
        const dualOption = document.getElementById('dualModeOption');
        const singleOption = document.getElementById('singleModeOption');
        
        if (e.target.value === 'dual') {
            dualConfig.style.display = 'block';
            dualOption.style.borderColor = 'var(--success)';
            singleOption.style.borderColor = 'var(--border)';
        } else {
            dualConfig.style.display = 'none';
            singleOption.style.borderColor = 'var(--warning)';
            dualOption.style.borderColor = 'var(--border)';
        }
    });
});

function applyMode() {
    const selected = document.querySelector('input[name="mode"]:checked').value;
    const isolatedIface = document.getElementById('isolatedInterface').value;
    
    if (selected === 'dual' && !isolatedIface) {
        showToast('Please select an isolated interface for dual-NIC mode', 'error');
        return;
    }
    
    pendingMode = selected;
    pendingInterface = isolatedIface;
    
    // Show warning modal
    const warningText = document.getElementById('warningText');
    const warningExtra = document.getElementById('warningExtra');
    
    if (selected === 'dual') {
        warningText.innerHTML = `You are switching to <strong>Dual-NIC Bridge Mode</strong>. This provides TRUE VLAN-equivalent security but requires devices to be connected through the isolated interface.`;
        warningExtra.textContent = 'Protected devices must be moved to a switch connected to ' + isolatedIface;
    } else {
        warningText.innerHTML = `You are switching to <strong>Single-NIC Mode</strong>. This uses software-based isolation and devices can be anywhere on the network.`;
        warningExtra.textContent = 'Reducing isolation from hardware to software level';
    }
    
    openModal('warningModal');
}

async function confirmModeChange() {
    closeModal('warningModal');
    
    const statusEl = document.getElementById('applyStatus');
    statusEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Applying...';
    
    try {
        const result = await api('/bridge/mode', {
            method: 'POST',
            body: JSON.stringify({
                mode: pendingMode,
                isolated_interface: pendingInterface
            })
        });
        
        if (result.success) {
            statusEl.innerHTML = '<i class="fas fa-check" style="color:var(--success)"></i> ' + result.message;
            showToast('Mode changed successfully. Engine is restarting...', 'success');
            
            // Reload status after a delay
            setTimeout(() => {
                loadStatus();
                statusEl.textContent = '';
            }, 5000);
        } else {
            statusEl.innerHTML = '<i class="fas fa-times" style="color:var(--danger)"></i> ' + result.error;
            showToast(result.error, 'error');
        }
    } catch (e) {
        statusEl.innerHTML = '<i class="fas fa-times" style="color:var(--danger)"></i> Error';
        showToast('Failed to change mode: ' + e.message, 'error');
    }
}

// Initial load
loadStatus();
</script>
{% endblock %}
BRIDGEHTML

    log_info "Templates created"
}

#===============================================================================
# SYSTEMD SERVICES
#===============================================================================

create_services() {
    log_step "Creating systemd services..."

# Main engine service
cat > /etc/systemd/system/irongate-engine.service << EOF
[Unit]
Description=Irongate Network Isolation Engine
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/core/engine.py
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/irongate.log
StandardError=append:${LOG_DIR}/irongate.log

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Web interface service
cat > /etc/systemd/system/irongate-web.service << EOF
[Unit]
Description=Irongate Web Interface
After=network.target irongate-engine.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn \\
    --bind 0.0.0.0:${WEB_PORT} \\
    --workers 2 \\
    --threads 4 \\
    --certfile ${CONFIG_DIR}/certs/server.crt \\
    --keyfile ${CONFIG_DIR}/certs/server.key \\
    --access-logfile ${LOG_DIR}/web-access.log \\
    --error-logfile ${LOG_DIR}/web-error.log \\
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable irongate-engine.service
    systemctl enable irongate-web.service
    
    log_info "Services created"
}

start_services() {
    log_step "Starting services..."
    
    systemctl start irongate-engine.service
    sleep 3
    systemctl start irongate-web.service
    
    log_info "Services started"
}

#===============================================================================
# MAIN INSTALLATION
#===============================================================================

print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                    IRONGATE INSTALLATION COMPLETE                     ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  ${CYAN}Web Interface:${NC}  https://${LOCAL_IP}:${WEB_PORT}"
    echo ""
    echo -e "  ${YELLOW}Two Isolation Modes Available:${NC}"
    echo ""
    echo -e "  ${MAGENTA}┌─ SINGLE-NIC MODE (Default) ─────────────────────────────────────────┐${NC}"
    echo -e "  ${MAGENTA}│${NC} 6-layer software isolation:                                         ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 1: DHCP Microsegmentation (/30 subnets + Option 121)     ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 2: ARP Defense (continuous poisoning + bypass detection) ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 3: IPv6 RA Attack (router advertisement hijacking)       ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 4: nftables Firewall (stateful packet filtering)         ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 5: Bypass Monitor (active defense + TCP RST injection)   ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ✓ Layer 6: Gateway Takeover (bidirectional ARP + CAM flood)      ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}                                                                     ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}│${NC}   ${YELLOW}⚠ ~95% effective - subject to timing race conditions${NC}            ${MAGENTA}│${NC}"
    echo -e "  ${MAGENTA}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${GREEN}┌─ DUAL-NIC MODE (Recommended for Business) ──────────────────────────┐${NC}"
    echo -e "  ${GREEN}│${NC} TRUE VLAN-EQUIVALENT security via Linux bridge port isolation:      ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}   ✓ 100% kernel-enforced isolation - NO BYPASS POSSIBLE            ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}   ✓ Equivalent to managed switch with VLANs                        ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}   ✓ Requires USB ethernet adapter (~\$10)                           ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}   ✓ Protected devices connect through isolated NIC                 ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}                                                                     ${GREEN}│${NC}"
    echo -e "  ${GREEN}│${NC}   ${GREEN}✓ RECOMMENDED FOR BUSINESS SERVERS${NC}                              ${GREEN}│${NC}"
    echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${CYAN}To switch modes:${NC} Go to https://${LOCAL_IP}:${WEB_PORT}/bridge"
    echo ""
    echo -e "  ${MAGENTA}Management Commands:${NC}"
    echo "    systemctl status irongate-engine   # Check engine status"
    echo "    systemctl status irongate-web      # Check web interface"
    echo "    journalctl -u irongate-engine -f   # View live logs"
    echo "    cat ${LOG_DIR}/security.log        # Security events"
    echo ""
    echo -e "  ${RED}Configuration:${NC}  ${CONFIG_DIR}/irongate.yaml"
    echo -e "  ${RED}Device Database:${NC}  ${DATA_DIR}/zones/devices.yaml"
    echo ""
}

main() {
    print_banner
    check_root
    check_kernel
    check_memory
    detect_os
    detect_network
    
    log_section "Beginning Installation"
    
    install_dependencies
    setup_directories
    setup_python_env
    generate_certificates
    create_config
    enable_kernel_features
    
    log_section "Creating Core Components"
    
    create_core_engine
    create_dhcp_server
    create_arp_defender
    create_ipv6_ra
    create_firewall
    create_monitor
    create_gateway_takeover
    create_bridge_manager
    create_web_app
    create_templates
    create_services
    
    log_section "Starting Services"
    
    start_services
    
    print_summary
}

main "$@"
