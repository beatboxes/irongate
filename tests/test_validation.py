#!/usr/bin/env python3
"""
Irongate input-validation regression tests (V1 nft injection, V2 indexer SSRF).

The root engine interpolates zone/group names and device IPs into the nftables
ruleset it loads, and it sends HTTP requests to blockchain.indexer_url. Both
values come from /etc/irongate/config.yaml, which the web tier can write. These
tests drive the real irongate.py / blockchain.py and assert on what actually
reaches the rendered ruleset text and on the URL the HTTP layer is asked to open.

Runs under pytest or plain unittest, against whichever sources are on the path:

    python -m pytest tests/test_validation.py
    IRONGATE_DIR=/opt/irongate python -m unittest tests/test_validation.py

No network, no root, no nft: os.system and urllib.request.urlopen are replaced.
scapy is blocked from importing so the module loads the same everywhere.
"""

import logging
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('IRONGATE_DIR') or os.path.join(os.path.dirname(HERE), 'src')
sys.path.insert(0, SRC)

# irongate.py treats scapy as optional (ImportError -> warning later); make sure
# the optional import never touches raw sockets or the network in a test run.
sys.modules.setdefault('scapy', None)
sys.modules.setdefault('scapy.all', None)

try:
    import yaml  # noqa: F401  (irongate.py imports it at module level)
except ImportError:  # pragma: no cover - only for hosts without PyYAML
    sys.modules['yaml'] = mock.MagicMock()

import blockchain  # noqa: E402
import irongate  # noqa: E402

logging.disable(logging.CRITICAL)

PREPROD = 'https://indexer.preprod.midnight.network/api/v4/graphql'
MAINNET = 'https://indexer.mainnet.midnight.network/api/v4/graphql'
UNDEPLOYED = 'http://127.0.0.1:8088/api/v4/graphql'

INJECTED_IP = '1.2.3.4 } ; flush ruleset ; {'


def render_ruleset(config):
    """Run Irongate._setup_firewall(config) and return the nft text it would load."""
    captured = {}
    commands = []

    def fake_system(cmd):
        commands.append(cmd)
        if cmd.startswith('nft -f '):
            with open(cmd[len('nft -f '):]) as fh:
                captured['rules'] = fh.read()
        return 0

    engine = irongate.Irongate.__new__(irongate.Irongate)
    engine.config = config
    with mock.patch.object(irongate.os, 'system', fake_system):
        engine._setup_firewall()
    return captured.get('rules', ''), commands


def make_config(devices=None, groups=None):
    return {'devices': devices or [], 'custom_groups': groups or []}


class FirewallInjectionTests(unittest.TestCase):
    """V1: attacker-controlled ip / zone / group values must never reach nft text."""

    def assertAbsent(self, needle, rules):
        if needle in rules:
            first = needle.split('\n')[0]
            hits = [ln for ln in rules.split('\n') if first in ln][:2]
            self.fail('attacker value %r reached the nft ruleset, e.g. %r' % (needle, hits))

    def assertSafe(self, rules, *forbidden):
        self.assertTrue(rules, 'no ruleset was rendered')
        for needle in forbidden:
            self.assertAbsent(needle, rules)
        self.assertAbsent('flush ruleset', rules)

    def test_injected_device_ip_not_interpolated(self):
        rules, _ = render_ruleset(make_config(devices=[
            {'mac': 'aa:bb:cc:dd:ee:01', 'ip': INJECTED_IP, 'zone': 'isolated'},
            {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '192.168.1.10', 'zone': 'isolated'},
        ]))
        self.assertSafe(rules, INJECTED_IP, '} ;')
        self.assertIn('192.168.1.10', rules)  # the legitimate device is still enforced

    def test_injected_zone_name_not_interpolated(self):
        rules, _ = render_ruleset(make_config(devices=[
            {'mac': 'aa:bb:cc:dd:ee:03', 'ip': '192.168.1.11', 'zone': 'lan; drop'},
        ]))
        self.assertSafe(rules, 'lan; drop', 'lan;')

    def test_zone_name_with_newline_not_interpolated(self):
        rules, _ = render_ruleset(make_config(devices=[
            {'mac': 'aa:bb:cc:dd:ee:04', 'ip': '192.168.1.12', 'zone': 'lan\nflush ruleset'},
            {'mac': 'aa:bb:cc:dd:ee:05', 'ip': '192.168.1.13', 'zone': 'lan\n'},
        ]))
        self.assertSafe(rules, 'lan\n')

    def test_injected_custom_group_name_not_interpolated(self):
        payload = 'x_devices { } ; flush ruleset ; table inet evil {'
        rules, _ = render_ruleset(make_config(
            devices=[{'mac': 'aa:bb:cc:dd:ee:06', 'ip': '192.168.1.14', 'zone': 'cams'}],
            groups=[{'name': payload, 'lan_access': 'full', 'can_access_groups': []},
                    {'name': 'cams', 'lan_access': 'none', 'can_access_groups': []}]))
        self.assertSafe(rules, payload, 'table inet evil')
        self.assertIn('set cams_devices', rules)

    def test_injected_group_name_with_newline_rejected(self):
        rules, _ = render_ruleset(make_config(
            groups=[{'name': 'ok\nflush ruleset', 'lan_access': 'none'}]))
        self.assertSafe(rules, 'ok\n')

    def test_injected_can_access_target_not_interpolated(self):
        payload = 'b } ; flush ruleset ; {'
        rules, _ = render_ruleset(make_config(
            devices=[{'mac': 'aa:bb:cc:dd:ee:07', 'ip': '192.168.1.15', 'zone': 'a'},
                     {'mac': 'aa:bb:cc:dd:ee:08', 'ip': '192.168.1.16', 'zone': payload}],
            groups=[{'name': 'a', 'lan_access': 'selected', 'can_access_groups': [payload]}]))
        self.assertSafe(rules, payload)

    def test_overlong_zone_name_rejected(self):
        rules, _ = render_ruleset(make_config(devices=[
            {'mac': 'aa:bb:cc:dd:ee:09', 'ip': '192.168.1.17', 'zone': 'z' * 33}]))
        self.assertSafe(rules, 'z' * 33)

    def test_non_ipv4_and_malformed_ips_rejected(self):
        bad_ips = ['::1', 'fe80::1', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.4/24',
                   '1.2.3.4\n', ' 1.2.3.4', '1.2.3.4 ', '01.2.3.4', 'a.b.c.d', 12345, ['1.2.3.4']]
        for bad in bad_ips:
            with self.subTest(ip=bad):
                rules, _ = render_ruleset(make_config(devices=[
                    {'mac': 'aa:bb:cc:dd:ee:0a', 'ip': bad, 'zone': 'isolated'},
                    {'mac': 'aa:bb:cc:dd:ee:0b', 'ip': '192.168.1.18', 'zone': 'isolated'}]))
                self.assertTrue(rules)
                self.assertIn('192.168.1.18', rules)
                self.assertAbsent(str(bad), rules)

    def test_valid_configuration_still_renders(self):
        """Characterization: valid zones/groups/IPs produce the same rules as before."""
        rules, commands = render_ruleset(make_config(
            devices=[{'mac': 'aa:bb:cc:dd:ee:10', 'ip': '192.168.1.20', 'zone': 'isolated'},
                     {'mac': 'aa:bb:cc:dd:ee:11', 'ip': '192.168.1.21', 'zone': 'servers'},
                     {'mac': 'aa:bb:cc:dd:ee:12', 'ip': '192.168.1.22', 'zone': 'iot-cams_1'},
                     {'mac': 'aa:bb:cc:dd:ee:13', 'ip': '192.168.1.23', 'zone': 'trusted'}],
            groups=[{'name': 'iot-cams_1', 'lan_access': 'same', 'can_access_groups': ['iot-cams_1']},
                    {'name': 'other', 'lan_access': 'selected', 'can_access_groups': ['servers']}]))
        self.assertIn('table inet irongate {', rules)
        self.assertIn('set isolated_devices', rules)
        self.assertIn('elements = { 192.168.1.20 }', rules)
        self.assertIn('elements = { 192.168.1.21 }', rules)
        self.assertIn('set iot-cams_1_devices', rules)
        self.assertIn('ip saddr @iot-cams_1_devices ip daddr @iot-cams_1_devices accept', rules)
        self.assertIn('ip saddr @other_devices ip daddr @servers_devices accept', rules)
        self.assertEqual(commands[0], 'nft delete table inet irongate 2>/dev/null')
        self.assertTrue(commands[1].startswith('nft -f '))


@unittest.skipUnless(hasattr(irongate, '_valid_zone_name'), 'pre-fix irongate.py has no validators')
class ValidatorHelperTests(unittest.TestCase):
    def test_zone_names(self):
        for ok in ['a', 'isolated', 'iot-cams_1', 'A' * 32, '0', '_', '-']:
            self.assertTrue(irongate._valid_zone_name(ok), ok)
        for bad in ['', 'a' * 33, 'lan; drop', 'a b', 'a\n', '\na', 'a.b', 'a/b', 'é', 'a\x00', None, 5, ['a']]:
            self.assertFalse(irongate._valid_zone_name(bad), repr(bad))

    def test_ipv4(self):
        self.assertEqual(irongate._valid_ipv4('192.168.1.1'), '192.168.1.1')
        for bad in ['', INJECTED_IP, '::1', '1.2.3', '1.2.3.4\n', None, 3232235777]:
            self.assertIsNone(irongate._valid_ipv4(bad), repr(bad))


class IndexerSSRFTests(unittest.TestCase):
    """V2: the engine may only talk to https Midnight indexer hosts from the presets."""

    MALICIOUS = [
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/shadow',
        'http://127.0.0.1:8088/api/v4/graphql',
        'http://localhost/',
        'ftp://indexer.preprod.midnight.network/',
        'http://indexer.preprod.midnight.network/api/v4/graphql',
        'https://evil.example/',
        'https://127.0.0.1/',
        'https://169.254.169.254/latest/meta-data/',
        'https://indexer.preprod.midnight.network.evil.example/',
        'https://indexer.preprod.midnight.network@evil.example/',
        'https://indexer.preprod.midnight.network:443@evil.example/',
        'https://evil.example\\@indexer.preprod.midnight.network/',
        'https://evil.example#@indexer.preprod.midnight.network/',
        'https://indexer.preprod.midnight.network:8443/api/v4/graphql',
        ' https://indexer.preprod.midnight.network/api/v4/graphql',
        'https://indexer.preprod.midnight.network/api\r\nHost: evil.example',
        'gopher://127.0.0.1:6379/_FLUSHALL',
    ]

    @staticmethod
    def requested_url(config):
        """Build the client and return the URL its HTTP layer is asked to open."""
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(req.full_url if hasattr(req, 'full_url') else req)
            raise blockchain.urllib.error.URLError('blocked in test')

        bc = blockchain.IrongateBlockchain(config)
        with mock.patch.object(blockchain.urllib.request, 'urlopen', fake_urlopen):
            bc._graphql('query { block { height } }')
        assert len(seen) == 1, seen
        return bc, seen[0]

    def test_malicious_indexer_urls_fall_back_to_preset(self):
        for url in self.MALICIOUS:
            with self.subTest(indexer_url=url):
                bc, used = self.requested_url({'enabled': False, 'network': 'preprod', 'indexer_url': url})
                self.assertEqual(used, PREPROD)
                self.assertEqual(bc.indexer_url, PREPROD)

    def test_rejection_is_logged(self):
        logging.disable(logging.NOTSET)
        try:
            with self.assertLogs('irongate.blockchain', level='WARNING') as cm:
                blockchain.IrongateBlockchain(
                    {'enabled': False, 'network': 'preprod', 'indexer_url': 'http://169.254.169.254/'})
        finally:
            logging.disable(logging.CRITICAL)
        self.assertTrue(any('169.254.169.254' in line for line in cm.output), cm.output)

    def test_enabled_startup_probe_never_touches_malicious_host(self):
        """The constructor itself probes the indexer when enabled; it must use the preset."""
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(req.full_url)
            raise blockchain.urllib.error.URLError('blocked in test')

        with mock.patch.object(blockchain.urllib.request, 'urlopen', fake_urlopen):
            blockchain.IrongateBlockchain({
                'enabled': True, 'network': 'preprod', 'contract_address': '0x' + '00' * 32,
                'indexer_url': 'http://169.254.169.254/latest/meta-data/'})
        self.assertEqual(seen, [PREPROD])

    def test_custom_url_on_known_indexer_host_is_honoured(self):
        for url in [MAINNET, PREPROD, 'https://indexer.preview.midnight.network/api/v4/graphql',
                    'https://INDEXER.mainnet.midnight.network:443/api/v4/graphql?x=1']:
            with self.subTest(indexer_url=url):
                bc, used = self.requested_url({'enabled': False, 'network': 'preprod', 'indexer_url': url})
                self.assertEqual(used, url)

    def test_presets_unchanged(self):
        for network, expected in [('preprod', PREPROD), ('mainnet', MAINNET), ('undeployed', UNDEPLOYED)]:
            with self.subTest(network=network):
                bc, used = self.requested_url({'enabled': False, 'network': network})
                self.assertEqual(used, expected)

    def test_undeployed_network_ignores_malicious_custom_url(self):
        bc, used = self.requested_url(
            {'enabled': False, 'network': 'undeployed', 'indexer_url': 'http://169.254.169.254/'})
        self.assertEqual(used, UNDEPLOYED)

    def test_undeployed_own_preset_url_is_accepted_silently(self):
        logging.disable(logging.NOTSET)
        try:
            with self.assertNoLogs('irongate.blockchain', level='WARNING'):
                bc, used = self.requested_url(
                    {'enabled': False, 'network': 'undeployed', 'indexer_url': UNDEPLOYED})
        finally:
            logging.disable(logging.CRITICAL)
        self.assertEqual(used, UNDEPLOYED)

    @unittest.skipUnless(hasattr(blockchain.IrongateBlockchain, 'allowed_indexer_hosts'),
                         'pre-fix blockchain.py has no allowlist')
    def test_allowed_hosts_derived_from_https_presets(self):
        self.assertEqual(
            blockchain.IrongateBlockchain.allowed_indexer_hosts(),
            frozenset({'indexer.preprod.midnight.network',
                       'indexer.preview.midnight.network',
                       'indexer.mainnet.midnight.network'}))


if __name__ == '__main__':
    unittest.main()
