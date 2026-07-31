# Irongate

**Enterprise-Grade Multi-Layer Network Isolation System**

Irongate is a sophisticated network security tool that enforces strict device separation on standard network infrastructure—without requiring managed switches or VLANs. It implements eight layers of defense-in-depth isolation to prevent unauthorized device communication on your network.

## Overview

Many organizations need to isolate critical devices (servers, medical equipment, IoT devices, etc.) but lack access to managed switches with VLAN capabilities. Irongate solves this by becoming a software-based network intermediary that controls all traffic through multiple overlapping security layers.

### Key Features

- **8 Layers of Protection** - Defense-in-depth approach ensures isolation even if one layer is bypassed
- **No Special Hardware Required** - Works on standard unmanaged network infrastructure
- **Two Isolation Modes** - Single-NIC (software-based) or Dual-NIC (hardware-enforced) isolation
- **Web-Based Management** - Web dashboard for real-time monitoring and device management
- **Zone-Based Security** - Classify devices into isolated, servers, or trusted zones, plus custom device groups
- **Active Threat Detection** - Real-time monitoring for bypass attempts with automatic response

## How It Works

Irongate implements eight complementary layers of network isolation:

### Layer 1: DHCP Microsegmentation
- Assigns /30 subnets to isolated devices, forcing all traffic through Irongate
- Uses DHCP Option 121 (Classless Static Routes) to capture all traffic
- Short lease times ensure continuous control over device network configuration
- Separate isolated DHCP pool (10.55.0.0/16) for managed devices

### Layer 2: ARP Defense
- Continuous ARP cache management to claim device gateway MACs
- Immediate response to ARP requests prevents spoofing
- Detects bypass attempts using static ARP entries
- Aggressive re-poisoning when bypass detected (500ms intervals)

### Layer 3: IPv6 Router Advertisement Control
- Controls IPv6 router advertisements in dual-stack networks
- Pushes custom IPv6 prefix (fd00:iron:gate::/64)
- Leverages IPv6 preference in modern systems to route traffic through Irongate

### Layer 4: nftables Stateful Firewall
- Kernel-level packet filtering with connection tracking
- Per-device zone classification with customizable policies
- Rate limiting for new connections
- Comprehensive logging of dropped packets

### Layer 5: Active Bypass Detection & Response
- Real-time monitoring for unauthorized connection attempts
- TCP RST injection to terminate bypass connections
- ICMP unreachable responses for UDP bypass attempts
- Security event logging for auditing

### Layer 6: Gateway Takeover
- Bidirectional ARP management (gateway sees all devices at Irongate's MAC)
- CAM table management to control switch forwarding behavior
- Gateway MAC coordination to win Layer 2 arbitration
- Promiscuous packet interception for stateful validation

### Layer 7: ARP Reply Interception
- Real-time monitoring of all ARP traffic on the network
- Intercepts ARP replies from protected devices announcing their real MAC addresses
- Immediately counters with spoofed replies to maintain isolation
- Prevents Layer 2 bypass attempts by untrusted devices
- Selective enforcement: allows trusted devices, gateway, and servers to communicate normally

### Layer 8: Algorand Blockchain Verification (Optional)
- Provides 100% VLAN-equivalent protection via cryptographic device authentication
- Stores authorized devices in an immutable on-chain registry on Algorand blockchain
- Verifies device identity via cryptographic signatures before allowing access
- Devices must be registered on-chain to access protected resources
- Integrates with Layers 1-7 for defense-in-depth (falls back to standard protection if blockchain unavailable)
- Configurable caching for performance optimization
- Optional audit logging for compliance and security forensics
- Requires deploying a smart contract and configuring the app_id in config

## System Requirements

| Requirement | Specification |
|-------------|--------------|
| Operating System | Linux (Debian/Ubuntu, Fedora/CentOS/RHEL) |
| Kernel Version | 4.18+ (for nftables and bridge port isolation) |
| Memory | Minimum 512MB RAM |
| Privileges | Root/sudo access required |
| Network | At least one network interface (two for Dual-NIC mode) |

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/beatboxes/irongate.git
cd irongate

# Make installer executable
chmod +x irongate_installer.sh

# Run installation (requires root)
sudo ./irongate_installer.sh
```

### Post-Installation

After installation, Irongate creates:
- Configuration: `/etc/irongate/config.yaml` (generated from the device database)
- Logs: the systemd journal (`journalctl -u irongate`)
- Device database: `/var/www/irongate/dhcp.db` (SQLite)
- Web interface: `http://localhost`

## Configuration

The engine reads `/etc/irongate/config.yaml`. It is generated from the device database by the web
API, so edit devices through the dashboard rather than by hand — a manual edit is overwritten on the
next apply.

```yaml
network:
  interface: eth0              # Primary network interface
  gateway_ip: 192.168.1.1      # Network gateway IP
  isolated_network: 10.55.0.0/16

devices:
  - mac: "aa:bb:cc:dd:ee:ff"
    ip: "10.0.0.50"
    zone: "isolated"    # isolated | servers | trusted
```

### Isolation Modes

**Single-NIC Mode (Default)**
- Software-based multi-vector isolation
- ~95% effective (subject to timing race conditions)
- Suitable for most use cases

**Dual-NIC Mode**
- Hardware-equivalent VLAN isolation via Linux bridge port isolation
- 100% kernel-enforced isolation
- Requires additional USB ethernet adapter

### Layer 8 Blockchain (Optional)

To enable Layer 8 Algorand blockchain verification for 100% VLAN-equivalent protection:

1. Install the Algorand SDK: `pip install py-algorand-sdk`
2. Deploy the smart contract: `python3 /opt/irongate/smart_contract.py`
3. Configure blockchain in `/etc/irongate/irongate.yaml`:

```yaml
blockchain:
  enabled: true
  network: "mainnet"       # mainnet, testnet, or betanet
  app_id: YOUR_APP_ID      # From smart contract deployment
  cache_ttl: 60            # Cache duration in seconds
  fallback_allow: true     # Allow access if blockchain unavailable
  audit_logging: false     # Enable for compliance logging
```

4. Register devices using the CLI: `irongate-blockchain register`

## Usage

### Starting/Stopping Services

```bash
# Start Irongate
sudo systemctl start irongate-engine
sudo systemctl start irongate-web

# Stop Irongate
sudo systemctl stop irongate-engine
sudo systemctl stop irongate-web

# Check status
sudo systemctl status irongate-engine
```

### Web Interface

Access the management dashboard at `http://localhost`

Features:
- Real-time system status monitoring
- Device inventory and zone management
- Live security event logs
- Network configuration panels
- Zone policy management

### Logs

```bash
# Main operational log
tail -f /var/log/irongate/irongate.log

# Security events and detected bypasses
tail -f /var/log/irongate/security.log

# Web interface access logs
tail -f /var/log/irongate/web.log
```

## Architecture

```
/opt/irongate/
├── core/
│   ├── engine.py           # Main orchestrator
│   ├── dhcp_server.py      # Layer 1: DHCP Microsegmentation
│   ├── arp_defender.py     # Layer 2: ARP Defense
│   ├── ipv6_ra.py          # Layer 3: IPv6 RA Control
│   ├── firewall.py         # Layer 4: nftables Firewall
│   ├── monitor.py          # Layer 5: Bypass Detection
│   ├── gateway_takeover.py # Layer 6: Gateway Takeover
│   ├── arp_interceptor.py  # Layer 7: ARP Reply Interception
│   ├── blockchain.py       # Layer 8: Algorand Blockchain (optional)
│   └── bridge_manager.py   # Dual-NIC bridge management
├── templates/              # Flask HTML templates
└── static/                 # CSS/JS assets

/etc/irongate/
├── irongate.yaml           # Main configuration
├── certs/                  # TLS certificates
└── rules/                  # nftables rules
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Python | 3.8+ | Core runtime |
| Flask | 3.0.0 | Web framework |
| Scapy | 2.5.0 | Packet manipulation |
| nftables | - | Kernel firewall |
| gunicorn | 21.2.0 | WSGI server |
| pyroute2 | 0.7.9 | Network interface management |
| cryptography | 41.0.0 | TLS/SSL handling |
| py-algorand-sdk | - | Layer 8 blockchain (optional) |

## Security Considerations

- **Root Access Required**: Irongate requires root privileges for network manipulation
- **Network Disruption**: Misconfiguration can disrupt network connectivity
- **Testing Recommended**: Test in a lab environment before production deployment
- **Backup Configuration**: Always backup network settings before installation
- **Firewall Rules**: Irongate modifies nftables rules; existing rules may be affected

## Use Cases

- **Medical Device Isolation**: Protect sensitive medical equipment from network threats
- **IoT Segmentation**: Isolate IoT devices from critical infrastructure
- **Server Protection**: Create isolated zones for sensitive servers
- **Guest Network Isolation**: Separate guest devices from internal resources
- **Legacy System Protection**: Isolate legacy systems that cannot be patched

## Troubleshooting

### Common Issues

**Devices not receiving DHCP leases**
- Verify the network interface is correct in `/etc/irongate/irongate.yaml`
- Check that Irongate services are running: `systemctl status irongate-engine`

**Web interface not accessible**
- Ensure port 8443 is not blocked by external firewall
- Check web service status: `systemctl status irongate-web`

**Isolation not working**
- Review security logs: `tail -f /var/log/irongate/security.log`
- Verify all layers are enabled in configuration
- Consider switching to Dual-NIC mode for complete isolation
- Enable Layer 8 blockchain verification for 100% VLAN-equivalent protection

## License

This project is provided for network security and isolation purposes. Please review the license file for terms of use.

## Contributing

Contributions are welcome! Please submit issues and pull requests to help improve Irongate.

---

**Disclaimer**: Irongate is a powerful network manipulation tool. Use responsibly and only on networks you own or have explicit permission to manage. Unauthorized use on networks you do not control may violate laws and regulations.

## Layer 8: Midnight blockchain verification (optional)

Irongate can verify device identity against a registry contract on the
[Midnight](https://midnight.network) blockchain, a privacy-focused chain with zero-knowledge proofs
and selective disclosure.

The **read path is implemented and tested**. It queries Midnight's public indexer over HTTPS GraphQL
using only the Python standard library — there is no SDK dependency, no wallet, and no key material
of any kind stored on the host. Networks are config-driven across `preprod`, `preview`, `mainnet`
and `undeployed` (a local node).

The **write path is not implemented**. Submitting a Midnight transaction requires a funded wallet
and a ZK proof server, and the published proof-server image has no confirmed `aarch64` build, so it
cannot run on a Raspberry Pi. `register_device`, `revoke_device` and `log_access` raise
`NotImplementedError` with an explanatory message rather than silently reporting success.

Layer 8 is **disabled by default** and entirely optional — Irongate's network isolation works with
no blockchain involvement at all. When enabled but the chain cannot be reached, verification returns
"undecided" and enforcement falls through to the standard layers; an unreachable chain is never
treated as proof that a device is trustworthy.

```yaml
blockchain:
  enabled: false
  network: "preprod"        # preprod | preview | mainnet | undeployed
  contract_address: null    # required when enabled
  indexer_url: null         # null uses the preset for the chosen network
  fallback_allow: true      # true = undecided, defer to the other layers
```

## Testing

```bash
IRONGATE_DIR=/opt/irongate /opt/irongate/venv/bin/python tests/test_blockchain.py
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
