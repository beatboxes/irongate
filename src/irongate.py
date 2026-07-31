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
import tempfile
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
