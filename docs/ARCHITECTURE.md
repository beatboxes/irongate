# IronGate Architecture

## The problem it solves

Segmenting a network normally means VLANs, which means managed switches and a configuration
skill most small networks do not have. IronGate reaches the same outcome by inserting itself into
the network's address-resolution and address-assignment layers on hardware that costs under $100,
without touching the switching fabric.

Two consequences follow from that choice and shape everything below:

1. Enforcement happens at **layer 2/3 by manipulating what devices believe**, not by physically
   separating traffic. It is defence in depth on a flat network, not a hardware guarantee.
2. IronGate must be **the DHCP server**, because that is how it learns about devices the moment they
   appear and how it keeps its own view of the network current.

## Components

```
                        ┌──────────────────────────────────┐
   Web browser ───────► │ nginx (HTTP, localhost/private)  │
                        │   └── php-fpm ── web/api.php     │
                        └───────────────┬──────────────────┘
                                        │ reads/writes
                                        ▼
                        ┌──────────────────────────────────┐
                        │ dhcp.db (SQLite)                 │  device inventory,
                        │   irongate_devices, settings,    │  zones, groups
                        │   device_groups, leases          │
                        └───────────────┬──────────────────┘
                                        │ api.php generates
                                        ▼
                        ┌──────────────────────────────────┐
                        │ /etc/irongate/config.yaml        │  GENERATED - do not hand-edit
                        └───────────────┬──────────────────┘
                                        │ read at startup
                                        ▼
   dnsmasq ──lease event──► dhcp-notify.sh ──► ┌─────────────────────┐
   (DHCP + DNS)                                │ irongate.py engine  │
                                               │  - nftables rules   │
                                               │  - ARP spoof loop   │
                                               │  - ARP defense loop │
                                               │  - Layer 8 (opt.)   │
                                               └──────────┬──────────┘
                                                          │ optional
                                                          ▼
                                               Midnight public indexer
                                               (HTTPS GraphQL, read-only)
```

## Configuration flow

This is the part that surprises people:

**`config.yaml` is generated, not authored.** The device database is the real state. `api.php`
renders `config.yaml` from it and restarts the engine. A hand edit survives only until the next
apply.

The engine loads its device list **once at startup**. Zone changes therefore require a restart,
which the web API performs automatically. Only the LAN victim list is refreshed while running.

## Zone model

| Zone | Spoofed by IronGate? | Others spoofed to protect it? | Firewall |
|---|---|---|---|
| `trusted` | No | No | Accepted both directions |
| `servers` | No | Yes | Restricted from reaching the general LAN |
| `isolated` | Yes | No | Dropped cross-zone |

`isolated` is the default for unknown devices, so a newly-appearing device is contained until
someone classifies it. Custom device groups layer additional policies on top with their own
LAN-access rules.

## Packet flow — single-NIC mode

Single-NIC is the default and needs no special hardware. The engine runs three loops as threads:

1. **LAN device refresh** — periodically re-reads the neighbour table to keep the victim list
   current, excluding trusted devices.
2. **Gateway takeover / spoof loop** — sends unicast ARP replies so isolated devices resolve the
   gateway (and each other) to IronGate's MAC, pulling their traffic through the box.
3. **ARP defense loop** — sniffs ARP with scapy. For a request targeting a protected IP from a
   device that is not allowed to reach it, it answers with a burst of forged replies to win the race
   against the genuine host.

The defense loop has a **DHCP grace period**: devices mid-DHCP-negotiation are skipped, so a new
client can complete its handshake instead of being isolated before it has an address.

Dual-NIC mode exists for hardware-enforced separation using a second interface and a bridge, and is
the stronger configuration where a second NIC is available.

## Layer 8 — Midnight verification

Optional, disabled by default, and deliberately constrained.

**Read path (implemented).** `src/blockchain.py` posts GraphQL to the public Midnight indexer using
`urllib` from the standard library — `block { hash height timestamp }` as a liveness probe and
`contractAction(address:)` for registry state. No SDK, no wallet, no key material on the device.

**Write path (not implemented).** On-chain registration needs a funded wallet plus a ZK proof
server, and the published proof-server image has no confirmed `aarch64` build. Those methods raise
`NotImplementedError` rather than returning a fake success.

**Three-valued result.** `verify_device` returns `True` (allow), `False` (block) or `None`
(undecided). Undecided falls through to layers 1–7. This matters: verification is called from
inside the per-packet ARP callback, so the module carries a hard request timeout and a circuit
breaker that stops calling a failing indexer for a cooldown period. An earlier version returned
`True` on chain error, which meant an outage silently disabled the other layers — the reason the
three-valued contract exists.

## Trust boundaries

Worth being explicit about, because several are uncomfortable:

- **The engine runs as root** and needs `CAP_NET_RAW` for scapy. It is not privilege-separated.
- **The web API has no authentication.** It is bound to localhost and a private management
  interface rather than the LAN, which is mitigation, not a fix.
- **`www-data` can restart the engine** through a NOPASSWD sudoers entry.
- **DHCP-supplied values are attacker-controlled.** Hostnames and MAC addresses come from untrusted
  devices and reach shell commands, SQL and generated YAML. Escaping at those boundaries is
  load-bearing, not stylistic.
- **The updater fetches and runs code from GitHub as root** with no signature verification. A repo
  compromise is a root compromise on every deployed instance.

## Not implemented

`ipv6_ra` and `bypass_detection` are configuration flags that are read and reported but perform no
enforcement. They are named here so nobody mistakes the log line for protection.
