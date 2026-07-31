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
import threading
import time
import urllib.error
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

        # An explicit indexer_url overrides the network preset.
        self.indexer_url = (
            self.config.get('indexer_url')
            or self.NETWORKS[self.network]['indexer']
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
