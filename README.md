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

## Security audit

IronGate went through a structured security audit in July 2026. 50 candidate findings were raised;
each was then put through an adversarial verification pass that tried to refute it, which rejected 9
as unreachable or duplicated. **41 findings survived verification** — 13 critical, 15 high,
10 medium, 3 low.

Disposition of those 41:

| | Count |
|---|---|
| Fixed and verified | **22** |
| Partially fixed | **2** |
| Deferred with a stated reason | **17** |

15 code changes closed those 22 findings, because several changes each closed more than one: a
single YAML-escaping helper closed 7 injection findings, and rewriting the blockchain module closed
6 at once. Nothing was rolled back.

One finding is worth calling out because it cuts against the process: the verification pass
**rejected** the blockchain fail-open, judging it unreachable. It was fixed anyway, because a
reproduction test demonstrated the failure on the pre-fix code — an unreachable chain really did
return "verified" and skip every other layer. Evidence outranked the judgement call.

### Fixed (22)

- **Command injection** into shell commands from unauthenticated, user-settable values — the two
  entry points are now argument-escaped.
- **Source and database disclosure** — PHP source backups and the SQLite device database were
  served in full over HTTP; now blocked at the web server.
- **Credential storage path removed entirely** rather than guarded. A wallet recovery phrase could
  previously be persisted and written in plaintext into a world-readable config file. The field is
  gone, and secret-bearing keys are now refused on write.
- **Blockchain fail-open** — an unreachable chain returned "verified", silently bypassing the other
  layers. Verification is now three-valued, and an unreachable chain yields *undecided*.
- **YAML injection** into the generated engine config from stored settings (7 findings) — all
  interpolated values now go through an escaping emitter.
- **Root code execution reachable by a plain GET** — the update action now requires POST.
- **Blockchain module hardening** (6 findings) — request timeouts, a circuit breaker, a bounded and
  lock-protected cache, and removal of exception-swallowing bare handlers. Relevant because
  verification is called from inside a per-packet callback.
- **Silent ARP callback failures** — a bare handler hid `sendp()` errors, so isolation could break
  with nothing in the log.
- **Shutdown ARP restoration** aborted entirely on the first failure, leaving later devices holding
  a forged MAC after the daemon exited. Each device is now restored independently.
- **Database lock handling** — no busy timeout, so concurrent writes silently lost settings.

### Partially fixed (2)

| Component | Finding | What was done, what remains |
|---|---|---|
| Updater / web API | Root code execution through the update path | The method restriction is in place, closing drive-by triggering. The downloaded installer is still executed **without signature verification** — see D6. |
| Web API | Full configuration returned without authentication | The credential field was removed entirely, so it can no longer be disclosed. The remainder of the configuration is still returned unauthenticated — see D1. |

### Deferred (17)

These were identified and verified, then deliberately deferred — not missed. Each carries the
specific reason. They are described by category and component; exact locations are omitted
deliberately, since this repository is public and several remain live.

**Critical**

| # | Component | Finding | Why deferred |
|---|---|---|---|
| D1 | Web API | No authentication of any kind. Every action, including privileged ones, is accepted from any requester. | **Architectural** — needs a session/token system and a matching dashboard rework. Not patchable in isolation. Mitigated by binding the service to localhost and a private management interface rather than the LAN. |
| D2 | Web API | State-changing operations are reachable by simple request with no CSRF protection. | **Architectural** — depends on D1; tokens are meaningless without an identity to bind them to. |
| D3 | Web API | User-controlled settings are embedded into DHCP server configuration without escaping, allowing injected directives. | **DHCP risk** — the generator writes the config for the DHCP service the network depends on. A validation bug here takes DHCP down for every device. Requires a staged rollout with rollback. |
| D4 | Web API | The generated DHCP configuration is written with no pre-write syntax check or rollback path. | **DHCP risk** — same blast radius as D3, and out of the audit's permitted change surface. |
| D5 | Host configuration | The web user holds passwordless sudo for service control, so an unauthenticated request can restart services as root. | **Out of scope** — system-level privilege configuration was outside the audit's change surface, and the grant is load-bearing for normal operation. Meaningful only once D1 exists. |
| D6 | Updater | The installer is downloaded and executed as root with no checksum or signature verification. A repository compromise is a root compromise on every deployment. | **Requires external dependency** — needs a signing key, a publishing process and verification logic. Cannot be fixed by a code change alone. |

**High**

| # | Component | Finding | Why deferred |
|---|---|---|---|
| D7 | Web API | The automatic repair routine can forcibly kill the DHCP service, with no rate limiting. | **DHCP risk** — already partially mitigated by a guard that only kills a service that is not running. Removing the kill path entirely needs testing against real failure modes. |
| D8 | Web API | The service restart is backgrounded and success is reported before it has completed or been validated. | **Operator decision required** — changes the apply semantics the dashboard depends on; a synchronous restart alters timeout behaviour visible to users. |
| D9 | Web API | Settings writes are not error-checked, so a failed write is silently ignored. | **Architectural** — a correct fix is a transactional settings layer with surfaced errors, not a return-value check bolted onto the loop. |
| D10 | Engine | Shutdown ARP restoration is O(protected × LAN devices) and can exceed the service stop timeout on a large network. | **Operator decision required** — the fix is either a tuned stop timeout or a reduced restoration burst, and both are deployment-specific trade-offs against restoration completeness. |
| D11 | Engine | Firewall rules are staged through a predictable path in a world-writable directory before being applied, giving a time-of-check/time-of-use window. | **Out of scope** — the firewall application path was frozen during the audit; changing where rules are staged risks the enforcement path itself. |
| D12 | Engine | In dual-NIC mode the DHCP service is launched without any success check, so the mode can run believing DHCP is up when it is not. | **Not deployed** — dual-NIC mode is not in use; single-NIC is the deployed configuration. Fix alongside any dual-NIC work. |

**Medium**

| # | Component | Finding | Why deferred |
|---|---|---|---|
| D13 | Engine | Duplicate of D12 — the same unchecked DHCP launch, reported independently by a second reviewer. Listed rather than silently dropped, so the count reconciles. | **Duplicate** — resolved by D12. |
| D14 | Engine | The DHCP grace-period file is parsed without validating MAC address format; malformed entries are accepted. | **Operator decision required** — rejecting malformed entries changes which devices receive grace-period treatment, and a too-strict rule could isolate legitimate devices mid-DHCP. |
| D15 | Engine | Device MAC addresses from configuration are used without format validation. Command execution uses argument lists, so this is not injection, but invalid values propagate. | **Operator decision required** — same policy question as D14: validation strictness determines which real devices stop being protected. |

**Low**

| # | Component | Finding | Why deferred |
|---|---|---|---|
| D16 | Web API | The installed version identifier is returned without authentication, allowing deployed patch levels to be enumerated. | **Low risk — next cycle.** Depends on D1; the repository is public, so the value discloses little that is not already inferable. |
| D17 | CLI | The registration command accepts unvalidated MAC and IP input. | **Now largely moot** — the on-chain write path raises `NotImplementedError`, so no invalid data can reach a chain. Worth fixing whenever writes are implemented. |

### Additional findings since the audit (3)

Found after the audit concluded, so outside the 41 above:

| Severity | Component | Finding |
|---|---|---|
| High | Dashboard | The Layer 8 panel still presents a **wallet recovery-phrase field** and submits it over unauthenticated plain HTTP. The API now refuses to store it, so a real phrase entered here is silently discarded *after* already being transmitted. **Do not enter a real recovery phrase.** The field is stale UI from the pre-migration integration and should be removed. |
| Medium | Dashboard | The Layer 8 panel still describes the previous Algorand integration — application ID, SDK installation, funding a wallet — none of which apply to the current Midnight integration. Misleading to anyone configuring it. |
| Low | Installer | The Algorand SDK is still installed at setup. The Midnight layer needs no third-party package; only the retained legacy contract does. |

### Reporting

If you find something not listed here, please open an issue. Known gaps are documented rather than
hidden — a security tool that misrepresents its own coverage is worse than one that does less.

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
