# IronGate

**Network isolation for networks that cannot segment themselves — with optional privacy-preserving
device verification on the Midnight blockchain.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-24%20passing-brightgreen.svg)](tests/)

---

## What it does

VLANs require managed switches and someone who knows how to configure them. Most homes, clinics,
workshops and small offices have neither, so a compromised smart plug ends up sharing a flat
broadcast domain with a NAS full of personal data.

IronGate enforces device separation on ordinary, unmanaged network hardware. It classifies every
device on the LAN into a security zone and enforces that classification at the protocol level —
using ARP, nftables and DHCP — with no changes to the existing switching infrastructure. It runs on
a Raspberry Pi 4.

It optionally verifies device identity against the [Midnight](https://midnight.network) blockchain,
so a network can prove a device is registered and correctly zoned without publishing what the
device is. That property is the reason for choosing a privacy chain rather than a transparent one:
a device registry on a public ledger is a permanent map of the hardware inside someone's home.

## Enforcement layers

**Implemented and active:**

| Layer | What it does |
|---|---|
| **nftables firewall** | Zone-based rules generated from the device database; drops cross-zone traffic |
| **Gateway takeover** | ARP-level interception so isolated devices route through IronGate |
| **ARP defense** | Answers and counters ARP traffic to keep isolated devices from resolving each other |
| **DHCP segmentation** | dnsmasq assigns addresses and notifies the engine on every lease event |

**Optional:**

| Layer | Status |
|---|---|
| **Layer 8 — Midnight verification** | Read path implemented, write path not. Disabled by default. See below. |

**Configured but NOT implemented — do not rely on these:**

| Layer | Reality |
|---|---|
| **IPv6 RA Guard** | The `ipv6_ra` config flag is read and reported, but no router-advertisement guarding is performed anywhere in the engine. |
| **Bypass Detection** | The `bypass_detection` flag is reported only. No active probing is performed. |

Both flags exist in `config.yaml` and appear in the startup log, which previously printed `ACTIVE`
for them. That was misleading, so they now report `ENABLED IN CONFIG, NOT IMPLEMENTED`. They are
listed here rather than quietly dropped because an operator needs to know which protections are
real.

## Zones

Devices are classified into one of three zones, plus optional custom device groups:

- **`trusted`** — full access, never spoofed, exempt from isolation in both directions.
- **`servers`** — protected: IronGate actively poisons other devices' ARP caches to shield them,
  and firewall rules restrict their reach into the general LAN.
- **`isolated`** — the default for unknown devices. Cannot reach other devices on the LAN.

Custom device groups allow finer-grained policies with their own LAN-access rules.

There is no `quarantine` zone. Earlier documentation claimed one; the engine has never implemented
it.

## Layer 8 — Midnight integration

**The read path is implemented and tested.** It queries the public Midnight indexer over HTTPS
GraphQL using nothing but the Python standard library. There is no Python SDK for Midnight, and
consequently no dependency, no wallet, and **no key material of any kind stored on the device** —
which matters a great deal for software installed at a network's chokepoint.

```yaml
blockchain:
  enabled: false            # off by default; isolation works with no blockchain at all
  network: "preprod"        # preprod | preview | mainnet | undeployed
  contract_address: null    # required when enabled
  indexer_url: null         # null uses the preset for the chosen network
  cache_ttl: 60
  fallback_allow: true      # true = undecided, defer to the other layers
  audit_logging: false
  allow_rogue_devices: false
```

**The write path is not implemented.** Registering a device on-chain requires a funded wallet and a
ZK proof server, and the published proof-server image has no confirmed `aarch64` build, so it
cannot run on a Raspberry Pi. `register_device`, `revoke_device` and `log_access` raise
`NotImplementedError` with an explanatory message rather than returning a fake success.

**Failure behaviour matters here.** Verification is three-valued: allow, block, or *undecided*. When
the chain cannot be reached the result is undecided and enforcement falls through to the other
layers. An unreachable chain is never treated as proof that a device is trustworthy. Verification
runs inside a per-packet ARP callback, so calls are bounded by a timeout and a circuit breaker.

### Migration note

Layer 8 targeted Algorand until July 2026. The legacy Algorand contract is retained at
`src/smart_contract.py` for reference and is not used by the engine; its optional build
dependencies live in `requirements-legacy.txt`.

## Security

IronGate has been through a structured security audit. It produced 41 verified findings
(13 critical, 15 high, 10 medium, 3 low), of which 15 were fixed and verified with none rolled
back. Fixes included:

- unauthenticated command injection reaching root via the web API
- PHP source and the SQLite device database being served over HTTP
- a credential path that would have written a wallet mnemonic in plaintext to a world-readable
  config file — removed entirely rather than guarded
- a fail-open in the blockchain layer where an unreachable chain returned "verified" and silently
  bypassed the other layers
- YAML injection into the generated engine config
- unlogged exceptions in the ARP callback that could break isolation silently

Known remaining gaps are tracked honestly: the web API has no authentication and is bound to
localhost and a private interface rather than the LAN; the auto-updater has no signature
verification. Both are documented rather than hidden.

## Quick start

Requires a Debian-based system (tested on Armbian and Debian Bookworm) with root access:

```bash
sudo bash irongate-install.sh
```

The installer provisions dnsmasq, nginx, php-fpm, nftables, a Python virtualenv, the systemd units
and the web dashboard.

**Do not rename `irongate-install.sh`.** The updater and the web UI's update action both fetch it
from this repository by that exact name.

## Requirements

- Debian-based Linux, root access
- Python 3.11+ with `venv`
- `dnsmasq`, `nginx`, `php-fpm`, `php-sqlite3`, `nftables`, `sqlite3`
- Python packages: see [requirements.txt](requirements.txt) — `PyYAML`, `scapy`, `netifaces`
- Hardware: developed and running on a Raspberry Pi 4 (aarch64, 4 GB)

## Configuration

The engine reads `/etc/irongate/config.yaml`. **That file is generated** from the device database by
the web API — a hand edit is overwritten the next time configuration is applied. Manage devices and
zones through the dashboard, or via the API, not by editing YAML.

The templates the installer expands are committed under [`templates/`](templates/) for review.

## Dashboard

A web dashboard provides device management, zone assignment, DHCP lease inspection and diagnostics.

It is served over **plain HTTP**, not HTTPS, and **has no authentication**. The installer binds it
to localhost and a private management interface rather than the LAN. Do not expose it to an
untrusted network.

## Testing

Unit and regression tests (24 tests, standard library `unittest` — no pytest required):

```bash
IRONGATE_DIR=/opt/irongate /opt/irongate/venv/bin/python tests/test_blockchain.py
```

End-to-end tests run in Docker on a network created with `internal: true`, so the test DHCP server
has no path to any real network:

```bash
bash docker/run-e2e.sh
```

See [docker/README.md](docker/README.md) for what the harness covers and how isolation is verified
before dnsmasq is allowed to start.

## Repository layout

```
irongate-install.sh   Self-contained installer; source of truth (carries all code in heredocs)
src/                  Engine, Midnight module, CLI, helper scripts
web/                  Dashboard and management API
config/               Literal config files
templates/            Installer templates containing shell variables (not directly usable)
tests/                Unit tests and E2E checks
docker/               Isolated end-to-end test harness
tools/                heredoc_sync.py / check-sync.sh - keep src/ and the installer in agreement
docs/                 Architecture notes
```

The installer and the extracted tree are two copies of the same code. `bash tools/check-sync.sh`
fails if they drift, so the duplication is checkable rather than assumed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The important rule: edit the heredoc in
`irongate-install.sh`, then run `python3 tools/heredoc_sync.py --extract`, so both copies stay in
agreement.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
