#!/usr/bin/env python3
"""
Irongate Layer 8 regression tests.

Runs against whichever blockchain.py is on the import path, so the same file
can be executed against the pre-fix (Algorand) module and the post-fix
(Midnight) module to demonstrate the behaviour change.

    IRONGATE_DIR=/opt/irongate /opt/irongate/venv/bin/python test_blockchain.py

Network-dependent tests are separated into LiveIndexerTests and are skipped
(not failed) when the host has no route to the indexer, so the deterministic
suite stays meaningful offline.
"""

import os
import sys
import unittest

sys.path.insert(0, os.environ.get('IRONGATE_DIR', '/opt/irongate'))

import blockchain  # noqa: E402

IS_MIDNIGHT = hasattr(blockchain, 'MIDNIGHT_AVAILABLE')


def _force_chain_error(bc):
    """
    Put an instance into the 'enabled, but the chain cannot be consulted' state
    without touching the network, for whichever implementation is loaded.
    """
    bc.enabled = True
    if IS_MIDNIGHT:
        bc.contract_address = '0x' + '00' * 32
        bc._get_contract_state = lambda: None
    else:
        def _boom():
            raise RuntimeError('simulated chain outage')
        bc._get_global_state = _boom
    return bc


class ChainOutageTests(unittest.TestCase):
    """
    The core security property. An unreachable chain is not evidence that a
    device is trustworthy, so it must never produce verified=True.

    In irongate.py's ARP handler, verified == True causes an early `return`
    that skips the Layer 1-7 config-based protection entirely. A chain outage
    that yields True therefore disables network isolation for every device
    that asks about a protected IP.
    """

    def test_chain_outage_is_not_a_pass(self):
        bc = _force_chain_error(blockchain.IrongateBlockchain(
            {'enabled': False, 'fallback_allow': True}))
        result = bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100')
        self.assertIsNot(
            result['verified'], True,
            "chain outage returned verified=True -> ARP handler treats an "
            "unreachable blockchain as cryptographic proof and bypasses Layers 1-7")

    def test_chain_outage_defers_to_lower_layers(self):
        bc = _force_chain_error(blockchain.IrongateBlockchain(
            {'enabled': False, 'fallback_allow': True}))
        result = bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100')
        self.assertIsNone(
            result['verified'],
            "fallback_allow=true must mean 'undecided, defer to Layers 1-7', "
            "not 'allow'")

    def test_fail_closed_blocks_on_outage(self):
        bc = _force_chain_error(blockchain.IrongateBlockchain(
            {'enabled': False, 'fallback_allow': False}))
        result = bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100')
        self.assertIs(result['verified'], False,
                      "fallback_allow=false must hard-block on a chain outage")

    def test_outage_result_is_blockchain_error(self):
        bc = _force_chain_error(blockchain.IrongateBlockchain(
            {'enabled': False, 'fallback_allow': True}))
        result = bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100')
        self.assertEqual(result['result'], blockchain.VerificationResult.BLOCKCHAIN_ERROR)


class DisabledLayerTests(unittest.TestCase):
    """Characterization of the shipped default: blockchain.enabled is false."""

    def setUp(self):
        self.bc = blockchain.IrongateBlockchain({'enabled': False})

    def test_disabled_instance_is_not_enabled(self):
        self.assertFalse(self.bc.enabled)

    def test_disabled_verify_returns_none(self):
        result = self.bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100')
        self.assertIsNone(result['verified'])
        self.assertEqual(result['result'], blockchain.VerificationResult.DISABLED)

    def test_disabled_log_access_is_silent_noop(self):
        self.assertIsNone(self.bc.log_access('aa:bb:cc:dd:ee:ff', '1.2.3.4', 'arp', 'ok'))

    def test_disabled_get_all_devices_is_empty(self):
        self.assertEqual(self.bc.get_all_devices(), [])

    def test_attributes_readable_while_disabled(self):
        # _last_sync was only assigned on the enabled path in the Algorand
        # module, so reading it on a disabled instance raised AttributeError.
        for attr in ('_last_sync', 'cache_ttl', 'fallback_allow',
                     'audit_logging', 'allow_rogue_devices', 'network'):
            getattr(self.bc, attr)


class CacheTests(unittest.TestCase):

    def test_cache_is_bounded(self):
        if not IS_MIDNIGHT:
            self.skipTest('bounded cache is a Midnight-module behaviour')
        bc = blockchain.IrongateBlockchain({'enabled': False})
        limit = blockchain.MAX_CACHE_ENTRIES
        for i in range(limit + 250):
            bc._set_cached('aa:bb:cc:%02x:%02x:%02x' % (i >> 16 & 255, i >> 8 & 255, i & 255),
                           {'ip': '10.0.0.1', 'zone': 'isolated', 'hostname': 'h', 'timestamp': 0})
        self.assertLessEqual(len(bc._cache), limit,
                             'device cache grew past its bound')
        self.assertEqual(len(bc._cache), len(bc._cache_time),
                         'cache and cache_time drifted out of sync')

    def test_clear_cache_empties_both_maps(self):
        bc = blockchain.IrongateBlockchain({'enabled': False})
        bc._set_cached('aa:bb:cc:dd:ee:ff', {'ip': '1.2.3.4', 'zone': 'z',
                                             'hostname': 'h', 'timestamp': 0})
        bc.clear_cache()
        self.assertEqual(len(bc._cache), 0)
        self.assertEqual(len(bc._cache_time), 0)

    def test_expired_entry_is_evicted(self):
        bc = blockchain.IrongateBlockchain({'enabled': False, 'cache_ttl': 0})
        bc._set_cached('aa:bb:cc:dd:ee:ff', {'ip': '1.2.3.4', 'zone': 'z',
                                             'hostname': 'h', 'timestamp': 0})
        self.assertIsNone(bc._get_cached('aa:bb:cc:dd:ee:ff'))


class WritePathTests(unittest.TestCase):
    """
    Writes need a wallet plus a ZK proof server, neither of which exists on
    this host. They must raise, never return a success-shaped dict.
    """

    def setUp(self):
        if not IS_MIDNIGHT:
            self.skipTest('write-path contract applies to the Midnight module')
        self.bc = blockchain.IrongateBlockchain({'enabled': False})

    def test_register_device_raises(self):
        with self.assertRaises(NotImplementedError):
            self.bc.register_device('aa:bb:cc:dd:ee:ff', '1.2.3.4', 'isolated', 'h')

    def test_revoke_device_raises(self):
        with self.assertRaises(NotImplementedError):
            self.bc.revoke_device('aa:bb:cc:dd:ee:ff')

    def test_log_access_raises_only_when_audit_enabled(self):
        self.bc.enabled = True
        self.bc.audit_logging = True
        with self.assertRaises(NotImplementedError):
            self.bc.log_access('aa:bb:cc:dd:ee:ff', '1.2.3.4', 'arp', 'ok')

    def test_error_message_explains_the_gap(self):
        try:
            self.bc.register_device('aa:bb:cc:dd:ee:ff', '1.2.3.4', 'isolated', 'h')
        except NotImplementedError as exc:
            msg = str(exc).lower()
            self.assertIn('proof server', msg)
            self.assertIn('wallet', msg)


class ParsingTests(unittest.TestCase):

    def setUp(self):
        self.bc = blockchain.IrongateBlockchain({'enabled': False})

    def test_parses_full_record(self):
        if not IS_MIDNIGHT:
            self.skipTest('value parser signature differs in the Algorand module')
        got = self.bc._parse_device_value('192.168.1.50|trusted|nas|1700000000')
        self.assertEqual(got, {'ip': '192.168.1.50', 'zone': 'trusted',
                               'hostname': 'nas', 'timestamp': 1700000000})

    def test_rejects_short_record(self):
        if not IS_MIDNIGHT:
            self.skipTest('value parser signature differs in the Algorand module')
        self.assertIsNone(self.bc._parse_device_value('192.168.1.50|trusted'))

    def test_non_numeric_timestamp_does_not_raise(self):
        if not IS_MIDNIGHT:
            self.skipTest('value parser signature differs in the Algorand module')
        got = self.bc._parse_device_value('192.168.1.50|trusted|nas|not-a-number')
        self.assertEqual(got['timestamp'], 0)

    def test_registry_ignores_garbage_lines(self):
        if not IS_MIDNIGHT:
            self.skipTest('registry parser is a Midnight-module behaviour')
        raw = (b'\x00\x01garbage\n'
               b'aa:bb:cc:dd:ee:ff=192.168.1.50|trusted|nas|1700000000\n'
               b'not-a-mac=1.2.3.4|z|h|0\n')
        reg = self.bc._parse_registry(raw)
        self.assertIn('aa:bb:cc:dd:ee:ff', reg)
        self.assertNotIn('not-a-mac', reg)


class NoCredentialTests(unittest.TestCase):
    """The Midnight read path must not introduce any on-disk secret."""

    def test_module_has_no_mnemonic_or_key_handling(self):
        if not IS_MIDNIGHT:
            self.skipTest('applies to the Midnight module')
        src = open(blockchain.__file__).read().lower()
        for token in ('mnemonic', 'private_key', 'to_private_key', 'admin_key'):
            self.assertNotIn(
                token + ' =', src,
                'Midnight module must not handle %s' % token)


class LiveIndexerTests(unittest.TestCase):
    """Real network calls against the public Midnight indexer."""

    def setUp(self):
        if not IS_MIDNIGHT:
            self.skipTest('applies to the Midnight module')
        self.bc = blockchain.IrongateBlockchain({'enabled': False, 'network': 'preprod'})

    def test_indexer_returns_a_real_chain_head(self):
        head = self.bc._query_block()
        if head is None:
            self.skipTest('no route to the Midnight preprod indexer')
        self.assertIn('hash', head)
        self.assertGreater(head['height'], 0)

    def test_get_stats_reports_connectivity(self):
        stats = self.bc.get_stats()
        self.assertEqual(stats['chain'], 'midnight')
        self.assertFalse(stats['write_supported'])
        if not stats['connected']:
            self.skipTest('no route to the Midnight preprod indexer')
        self.assertGreater(stats['chain_height'], 0)

    def test_unreachable_indexer_degrades_quietly(self):
        bc = blockchain.IrongateBlockchain({
            'enabled': False,
            'indexer_url': 'http://127.0.0.1:9/graphql',  # discard port
            'timeout': 2,
        })
        self.assertIsNone(bc._query_block())


if __name__ == '__main__':
    print('module   : %s' % blockchain.__file__)
    print('flavour  : %s' % ('MIDNIGHT' if IS_MIDNIGHT else 'ALGORAND (pre-fix)'))
    print('-' * 70)
    unittest.main(verbosity=2)
