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

No internet, no root, no nft: os.system and urllib.request.urlopen are replaced
(only the redirect tests open real sockets, on 127.0.0.1). scapy is blocked from
importing so the module loads the same everywhere.
"""

import http.server
import logging
import os
import sys
import tempfile
import threading
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

    def test_zone_names_with_leading_digit_or_hyphen_not_rendered(self):
        rules, _ = render_ruleset(make_config(
            devices=[{'mac': 'aa:bb:cc:dd:ee:0c', 'ip': '192.168.1.19', 'zone': '0'},
                     {'mac': 'aa:bb:cc:dd:ee:0d', 'ip': '192.168.1.24', 'zone': '-x'},
                     {'mac': 'aa:bb:cc:dd:ee:0e', 'ip': '192.168.1.25', 'zone': '9lives'},
                     {'mac': 'aa:bb:cc:dd:ee:0f', 'ip': '192.168.1.26', 'zone': '_ok'}],
            groups=[{'name': '9lives', 'lan_access': 'none', 'can_access_groups': []},
                    {'name': '_ok', 'lan_access': 'none', 'can_access_groups': []}]))
        self.assertTrue(rules)
        for needle in ('set 0_devices', 'set -x_devices', 'set 9lives_devices', '192.168.1.19',
                       '192.168.1.24', '192.168.1.25'):
            self.assertAbsent(needle, rules)
        self.assertIn('set _ok_devices', rules)
        self.assertIn('192.168.1.26', rules)

    def test_non_string_can_access_targets_are_ignored(self):
        """A hand-edited can_access_groups may hold lists/dicts/numbers; they must be skipped, not crash the firewall."""
        rules, _ = render_ruleset(make_config(
            devices=[{'mac': 'aa:bb:cc:dd:ee:14', 'ip': '192.168.1.27', 'zone': 'a'},
                     {'mac': 'aa:bb:cc:dd:ee:15', 'ip': '192.168.1.28', 'zone': 'b'}],
            groups=[{'name': 'a', 'lan_access': 'selected', 'can_access_groups': [['b'], {'b': 1}, 5, None, 'b']}]))
        self.assertIn('ip saddr @a_devices ip daddr @b_devices accept', rules)
        self.assertNotIn("['b']", rules)

    def test_canonical_ip_is_what_gets_interpolated(self):
        """Older interpreters accept '010.001.001.001' as 10.1.1.1: whatever the parser returns is rendered, never the raw text."""
        real = irongate.ipaddress.ip_address

        def lenient(value):
            return real('10.1.1.1') if value == '010.001.001.001' else real(value)

        with mock.patch.object(irongate.ipaddress, 'ip_address', lenient):
            rules, _ = render_ruleset(make_config(devices=[
                {'mac': 'aa:bb:cc:dd:ee:16', 'ip': '010.001.001.001', 'zone': 'isolated'}]))
        self.assertIn('10.1.1.1', rules)
        self.assertAbsent('010.001.001.001', rules)

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
        for ok in ['a', 'isolated', 'iot-cams_1', 'A' * 32, '_', '_0', 'a-', 'a0-_', 'Z9']:
            self.assertTrue(irongate._valid_zone_name(ok), ok)
        for bad in ['', 'a' * 33, 'lan; drop', 'a b', 'a\n', '\na', 'a.b', 'a/b', 'é', 'a\x00', None, 5, ['a']]:
            self.assertFalse(irongate._valid_zone_name(bad), repr(bad))

    def test_zone_names_must_start_with_a_letter_or_underscore(self):
        # The name becomes the nft set identifier "<name>_devices"; nft identifiers cannot
        # begin with a digit or '-' ('-x' would even be read as an option).
        for bad in ['0', '-', '9lives', '0_x', '-a', '-_', '1' + 'a' * 31]:
            self.assertFalse(irongate._valid_zone_name(bad), repr(bad))

    def test_ipv4(self):
        self.assertEqual(irongate._valid_ipv4('192.168.1.1'), '192.168.1.1')
        for bad in ['', INJECTED_IP, '::1', '1.2.3', '1.2.3.4\n', None, 3232235777]:
            self.assertIsNone(irongate._valid_ipv4(bad), repr(bad))


HEAD_JSON = b'{"data": {"block": {"hash": "0xabc", "height": 7, "timestamp": 1}}}'


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ReachableEverywhere:
    """Stand-in for urllib.request.urlopen where EVERY host answers like a healthy indexer.

    It records the URL of each request. A test that expects "no request at all" is
    therefore meaningful even on a machine that can reach the real Midnight indexers:
    a fallback to a preset would show up in .seen and would be answered with a valid
    chain head.
    """

    def __init__(self):
        self.seen = []

    def __call__(self, req, timeout=None):
        self.seen.append(req.full_url if hasattr(req, 'full_url') else req)
        return FakeResponse(HEAD_JSON)


class IndexerSSRFTests(unittest.TestCase):
    """V2: the engine may only talk to https Midnight indexer hosts from the presets.

    A configured indexer_url that fails validation fails CLOSED: the layer makes no
    request at all and reports 'undecided'. It is never replaced by a preset, because
    that would silently send queries to a host the operator did not configure.
    """

    MALICIOUS = [
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/shadow',
        'http://127.0.0.1:8088/api/v4/graphql',
        'http://127.0.0.1:9/graphql',
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

    @staticmethod
    def run_with_reachable_net(config, call):
        """Build the client and run call(bc) while every host would answer like a healthy indexer."""
        net = ReachableEverywhere()
        with mock.patch.object(blockchain.urllib.request, 'urlopen', net):
            bc = blockchain.IrongateBlockchain(config)
            result = call(bc)
        return bc, net.seen, result

    def test_malicious_indexer_urls_fail_closed(self):
        for url in self.MALICIOUS:
            for network in ('preprod', 'undeployed'):
                if url == UNDEPLOYED and network == 'undeployed':
                    continue  # the selected network's own preset is the one non-https URL that is fine
                with self.subTest(indexer_url=url, network=network):
                    bc, seen, result = self.run_with_reachable_net(
                        {'enabled': False, 'network': network, 'indexer_url': url},
                        lambda bc: (bc._graphql('query { block { height } }'), bc._query_block()))
                    self.assertIsNone(bc.indexer_url)
                    self.assertEqual(result, (None, None))
                    self.assertEqual(seen, [], 'a rejected indexer_url must not cause any request')

    def test_rejected_url_never_falls_back_to_the_preset(self):
        """The shape of tests/test_blockchain.py::test_unreachable_indexer_degrades_quietly."""
        bc, seen, head = self.run_with_reachable_net(
            {'enabled': False, 'indexer_url': 'http://127.0.0.1:9/graphql', 'timeout': 2},
            lambda bc: bc._query_block())
        self.assertIsNone(head)
        self.assertEqual(seen, [], 'preprod (or any host) was queried although the configured URL was rejected')

    def test_rejection_is_logged(self):
        logging.disable(logging.NOTSET)
        try:
            with self.assertLogs('irongate.blockchain', level='WARNING') as cm:
                blockchain.IrongateBlockchain(
                    {'enabled': False, 'network': 'preprod', 'indexer_url': 'http://169.254.169.254/'})
        finally:
            logging.disable(logging.CRITICAL)
        self.assertTrue(any('169.254.169.254' in line for line in cm.output), cm.output)
        self.assertTrue(any('no queries' in line for line in cm.output), cm.output)

    def test_enabled_with_rejected_url_makes_no_request_and_stays_undecided(self):
        """The constructor probes the indexer when enabled; with a rejected URL it must not probe anything."""
        bc, seen, verdict = self.run_with_reachable_net(
            {'enabled': True, 'network': 'preprod', 'contract_address': '0x' + '00' * 32,
             'indexer_url': 'http://169.254.169.254/latest/meta-data/'},
            lambda bc: bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100'))
        self.assertEqual(seen, [])
        self.assertIsNone(verdict['verified'])  # undecided: defer to Layers 1-7, never "verified"
        self.assertIsNone(bc.get_stats()['indexer_url'])

    def test_rejected_url_undecided_depends_on_fallback_allow(self):
        """README: a rejected URL is 'undecided' only while fallback_allow is true; with false the layer fails closed."""
        for fallback_allow, expected in [(True, None), (False, False)]:
            with self.subTest(fallback_allow=fallback_allow):
                bc, seen, verdict = self.run_with_reachable_net(
                    {'enabled': True, 'network': 'preprod', 'contract_address': '0x' + '00' * 32,
                     'indexer_url': 'http://169.254.169.254/latest/meta-data/', 'fallback_allow': fallback_allow},
                    lambda bc: bc.verify_device('aa:bb:cc:dd:ee:ff', '192.168.1.100'))
                self.assertEqual(seen, [])
                self.assertIs(verdict['verified'], expected)

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

    def test_blank_indexer_url_means_preset(self):
        for blank in (None, ''):
            with self.subTest(indexer_url=blank):
                bc, used = self.requested_url({'enabled': False, 'network': 'preprod', 'indexer_url': blank})
                self.assertEqual(used, PREPROD)

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


@unittest.skipUnless(hasattr(blockchain.IrongateBlockchain, 'validate_indexer_url'),
                     'pre-fix blockchain.py has no validator')
class ValidateIndexerUrlTests(unittest.TestCase):
    """validate_indexer_url(): each rule is pinned by an input that ONLY that rule rejects
    (the host is on the allowlist, scheme and port are fine), so removing a single rule fails a test."""

    HOST = 'indexer.preprod.midnight.network'

    def check(self, template, expected_ok):
        url = template.replace('HOST', self.HOST)
        got = blockchain.IrongateBlockchain.validate_indexer_url(url)
        if expected_ok:
            self.assertEqual(got, url, url)
        else:
            self.assertIsNone(got, url)

    def test_userinfo_on_an_allowed_host_is_rejected(self):
        for t in ['https://user:pw@HOST/api/v4/graphql', 'https://user@HOST/api/v4/graphql',
                  'https://:@HOST/api/v4/graphql', 'https://@HOST/api/v4/graphql']:
            with self.subTest(url=t):
                self.check(t, False)

    def test_backslash_anywhere_is_rejected(self):
        for t in ['https://HOST/api\\v4/graphql', 'https://HOST/?q=\\', 'https://HOST/#\\', 'https://HOST/\\']:
            with self.subTest(url=t):
                self.check(t, False)

    def test_non_printable_or_non_ascii_characters_are_rejected(self):
        for t in ['https://HOST/api v4', 'https://HOST/api\tv4', 'https://HOST/api\x7fv4',
                  'https://HOST/apié', 'https://HOST/api\r\nX: y', 'https://HOST/api\n']:
            with self.subTest(url=t):
                self.check(t, False)

    def test_scheme_and_port_rules(self):
        self.check('http://HOST/api/v4/graphql', False)
        self.check('https://HOST:8443/api/v4/graphql', False)
        self.check('https://HOST:443/api/v4/graphql', True)

    def test_plain_urls_on_allowed_hosts_are_accepted(self):
        for t in ['https://HOST/api/v4/graphql', 'https://HOST', 'https://HOST/api/v4/graphql?x=1']:
            with self.subTest(url=t):
                self.check(t, True)

    def test_non_string_values_are_rejected(self):
        for bad in (None, 5, ['https://%s/' % self.HOST], b'https://%s/' % self.HOST.encode()):
            self.assertIsNone(blockchain.IrongateBlockchain.validate_indexer_url(bad), repr(bad))


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Loopback HTTP server: records every request; answers 200 + chain head, or a redirect."""

    def log_message(self, *args):
        pass

    def _any(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        self.server.hits.append((self.command, self.path))
        if self.server.redirect_to:
            self.send_response(self.server.code)
            self.send_header('Location', self.server.redirect_to)
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(HEAD_JSON)))
            self.end_headers()
            self.wfile.write(HEAD_JSON)

    do_GET = do_POST = do_PUT = _any


class IndexerRedirectTests(unittest.TestCase):
    """V2: an indexer that answers 3xx must not be able to bounce the root engine to another URL.

    Real loopback sockets and the real urllib stack (urlopen is NOT mocked): the redirect
    policy lives in the opener that urlopen uses.
    """

    def serve(self, redirect_to=None, code=302):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Recorder)
        srv.hits, srv.redirect_to, srv.code = [], redirect_to, code
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        def stop():
            srv.shutdown()
            srv.server_close()
        self.addCleanup(stop)
        return srv

    @staticmethod
    def client(port):
        bc = blockchain.IrongateBlockchain({'enabled': False, 'network': 'undeployed', 'timeout': 5})
        # Transport-level test: point the client at the loopback server, bypassing the config validator.
        bc.indexer_url = 'http://127.0.0.1:%d/api/v4/graphql' % port
        return bc

    def test_redirects_are_not_followed(self):
        internal = self.serve()
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                front = self.serve(redirect_to='http://127.0.0.1:%d/internal' % internal.server_port, code=code)
                self.assertIsNone(self.client(front.server_port)._graphql('query { block { height } }'))
                self.assertEqual(len(front.hits), 1)
                self.assertEqual(internal.hits, [], 'the redirect target was requested')

    def test_plain_200_still_works(self):
        front = self.serve()
        data = self.client(front.server_port)._graphql('query { block { height } }')
        self.assertEqual(data, {'block': {'hash': '0xabc', 'height': 7, 'timestamp': 1}})


class OpenerScopeTests(unittest.TestCase):
    """blockchain.py installs its no-redirect opener process-wide (urllib.request.install_opener).

    That is only safe while it is the one urllib user in the engine process; the tests above mock
    urllib.request.urlopen, which is why a module-local opener's .open() is not used. If another
    module of the engine starts using urllib, this test fails: give blockchain.py a module-local
    opener at that point (and point the urlopen mocks at it) instead of widening the global one.
    """

    def test_blockchain_is_the_only_urllib_user_in_the_engine(self):
        users = []
        for name in sorted(os.listdir(SRC)):
            if name.endswith('.py') and name != 'blockchain.py':
                with open(os.path.join(SRC, name), encoding='utf-8') as fh:
                    if 'urllib' in fh.read():
                        users.append(name)
        self.assertEqual(users, [], 'urllib is used outside blockchain.py: %s' % users)


import shutil  # noqa: E402  (only the O3 tests below use it)

FAKE_TOOLS = ('ip', 'brctl', 'bridge', 'ebtables', 'nft', 'pkill', 'dnsmasq')

# What run_dual_nic() has always run for the default settings (eth1 isolated behind br-irongate, eth0 uplink).
EXPECTED_DUAL_COMMANDS = [
    ['ip', 'link', 'set', 'br-irongate', 'down'],
    ['brctl', 'delbr', 'br-irongate'],
    ['brctl', 'addbr', 'br-irongate'],
    ['brctl', 'stp', 'br-irongate', 'off'],
    ['ip', 'link', 'set', 'eth1', 'down'],
    ['ip', 'addr', 'flush', 'dev', 'eth1'],
    ['brctl', 'addif', 'br-irongate', 'eth1'],
    ['ip', 'link', 'set', 'eth1', 'up'],
    ['ip', 'addr', 'add', '10.99.0.1/16', 'dev', 'br-irongate'],
    ['ip', 'link', 'set', 'br-irongate', 'up'],
    ['bridge', 'link', 'set', 'dev', 'eth1', 'isolated', 'on'],
    ['nft', 'add', 'table', 'nat'],
    ['nft', 'add', 'chain', 'nat', 'postrouting', '{', 'type', 'nat', 'hook', 'postrouting', 'priority', '100', ';', '}'],
    ['nft', 'add', 'rule', 'nat', 'postrouting', 'oifname', 'eth0', 'masquerade'],
    ['pkill', '-f', 'dnsmasq.*bridge-dnsmasq'],
    ['dnsmasq', '--conf-file=/etc/irongate/bridge-dnsmasq.conf'],
]
EXPECTED_DUAL_CONF = ('\ninterface=br-irongate\nbind-interfaces\ndhcp-range=10.99.1.1,10.99.255.254,24h\n'
                      'dhcp-option=option:router,10.99.0.1\ndhcp-option=option:dns-server,10.99.0.1,8.8.8.8\n')


class DualNicInjectionTests(unittest.TestCase):
    """O3: the dual-NIC settings (config.yaml, which the web tier can write) never reach a shell, a command
    argument or the dnsmasq file unchecked.

    run_dual_nic() really runs here, against recording stand-ins for ip, brctl, bridge, ebtables, nft, pkill and
    dnsmasq that sit first on PATH (nothing needs root, nothing touches the network or the real /etc), and the
    dnsmasq file is redirected into a scratch directory. The payloads try to run `touch <scratch>/PWNED`: with a
    shell in the way (os.system with the value pasted into the command) that file appears.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ig-dual-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, 'bin')
        os.mkdir(self.bin)
        self.log = os.path.join(self.tmp, 'calls.log')
        self.conf = os.path.join(self.tmp, 'bridge-dnsmasq.conf')
        self.pwned = os.path.join(self.tmp, 'PWNED')
        for tool in FAKE_TOOLS:
            path = os.path.join(self.bin, tool)
            with open(path, 'w') as fh:
                fh.write('#!/bin/sh\n'
                         'printf "%s" "${0##*/}" >> "$IG_FAKE_LOG"\n'
                         'for a in "$@"; do printf "\\037%s" "$a" >> "$IG_FAKE_LOG"; done\n'
                         'printf "\\n" >> "$IG_FAKE_LOG"\n'
                         '[ "${IG_FAKE_FAIL:-}" = "${0##*/}" ] && exit 1\n'
                         'exit 0\n')
            os.chmod(path, 0o755)

    def run_dual(self, bridge=None, network='eth0', fail=''):
        net = {} if network is None else {'interface': network}
        cfg = {'mode': 'dual', 'network': net,
               'bridge': dict({'isolated_interface': 'eth1', 'bridge_name': 'br-irongate', 'bridge_ip': '10.99.0.1',
                               'dhcp_start': '10.99.1.1', 'dhcp_end': '10.99.255.254'}, **(bridge or {}))}
        engine = irongate.Irongate.__new__(irongate.Irongate)
        engine.config = cfg
        real_open, real_exists, conf = open, os.path.exists, self.conf

        def fake_open(path, *a, **k):
            return real_open(conf if path == '/etc/irongate/bridge-dnsmasq.conf' else path, *a, **k)

        def fake_exists(path):
            return True if str(path).startswith('/sys/class/net/') else real_exists(path)

        env = {'PATH': self.bin + os.pathsep + os.environ.get('PATH', ''), 'IG_FAKE_LOG': self.log, 'IG_FAKE_FAIL': fail}
        with mock.patch.dict(os.environ, env), mock.patch.object(irongate, 'open', fake_open, create=True), \
                mock.patch.object(irongate.os.path, 'exists', fake_exists):
            return engine.run_dual_nic()

    def calls(self, wait_for=None):
        """The recorded commands; wait_for names a tool that is started in the background (dnsmasq)."""
        import time
        end = time.time() + 5
        while True:
            rows = []
            if os.path.exists(self.log):
                with open(self.log) as fh:
                    rows = [line.rstrip('\n').split('\x1f') for line in fh]
            if wait_for is None or any(r[0] == wait_for for r in rows) or time.time() > end:
                return rows
            time.sleep(0.05)

    def test_valid_settings_run_the_same_commands_as_before(self):
        self.assertTrue(self.run_dual())
        self.assertEqual(self.calls(wait_for='dnsmasq'), EXPECTED_DUAL_COMMANDS)
        with open(self.conf) as fh:
            self.assertEqual(fh.read(), EXPECTED_DUAL_CONF)

    def test_failed_port_isolation_falls_back_to_ebtables(self):
        self.assertTrue(self.run_dual(fail='bridge'))
        rows = self.calls(wait_for='dnsmasq')
        self.assertIn(['ebtables', '-A', 'FORWARD', '-i', 'eth1', '-o', 'eth1', '-j', 'DROP'], rows)

    def test_a_missing_tool_does_not_stop_the_bridge_setup(self):
        for tool in ('ebtables', 'brctl', 'pkill', 'dnsmasq'):
            os.unlink(os.path.join(self.bin, tool))
        with mock.patch.dict(os.environ, {'PATH': self.bin}):          # no brctl anywhere on PATH
            self.assertTrue(self.run_dual(fail='bridge'))

    def test_an_empty_uplink_only_skips_the_nat_rule(self):
        self.assertTrue(self.run_dual(network=''))
        rows = self.calls(wait_for='dnsmasq')
        self.assertIn(['nft', 'add', 'table', 'nat'], rows)
        self.assertFalse([r for r in rows if r[:4] == ['nft', 'add', 'rule', 'nat']], rows)

    def payloads(self):
        p = self.pwned
        return [
            # the reviewer's payload, and its cousins
            ('bridge_ip', '10.99.0.1/32 dev lo; touch %s #' % p),
            ('bridge_ip', '10.99.0.1; touch %s' % p),
            ('bridge_ip', '10.99.0.1 && touch %s' % p),
            ('bridge_ip', '$(touch %s)' % p),
            ('bridge_ip', '`touch %s`' % p),
            ('bridge_ip', '10.99.0.1\ntouch %s' % p),
            ('bridge_ip', '10.99.0.1/16'),
            ('bridge_ip', '10.99.0.1 '),
            ('bridge_ip', '10.99.0.1\n'),
            ('bridge_ip', 'fe80::1'),
            ('bridge_ip', ''),
            ('bridge_ip', None),
            ('bridge_ip', ['10.99.0.1']),
            ('bridge_ip', 167837697),
            # dnsmasq file: a newline would add a directive of its own (dhcp-script= runs a program as root)
            ('dhcp_start', '10.99.1.1,10.99.255.254,24h\ndhcp-script=%s\n#' % p),
            ('dhcp_start', '10.99.1.1; touch %s' % p),
            ('dhcp_start', '10.99.1.1\n'),
            ('dhcp_end', '10.99.255.254,24h\nconf-file=/etc/shadow\n#'),
            ('dhcp_end', '10.99.255.254 ; touch %s' % p),
            ('dhcp_end', 'dhcp'),
            # interface names
            ('isolated_interface', 'eth1; touch %s' % p),
            ('isolated_interface', 'eth1 && touch %s' % p),
            ('isolated_interface', '$(touch %s)' % p),
            ('isolated_interface', 'eth1\n'),
            ('isolated_interface', '-x'),
            ('isolated_interface', '..'),
            ('isolated_interface', 'a' * 16),
            ('isolated_interface', ['eth1']),
            ('bridge_name', 'br0; touch %s' % p),
            ('bridge_name', 'br-irongate\ninterface=eth0'),
            ('bridge_name', '-batch'),
            ('network.interface', 'eth0 masquerade ; flush ruleset ; #'),
            ('network.interface', 'eth0; touch %s' % p),
            ('network.interface', 'eth0\n'),
            ('network.interface', ['eth0']),
        ]

    def test_injected_values_are_rejected_before_anything_runs(self):
        for field, value in self.payloads():
            with self.subTest(field=field, value=value):
                self.setUp()                                  # fresh scratch directory for every payload
                if field == 'network.interface':
                    ok = self.run_dual(network=value)
                else:
                    ok = self.run_dual(bridge={field: value})
                self.assertFalse(ok, 'a hostile %s was accepted' % field)
                self.assertFalse(os.path.exists(self.pwned), 'the payload ran a command: %s was created' % self.pwned)
                self.assertEqual(self.calls(), [], 'commands ran although %s is invalid' % field)
                self.assertFalse(os.path.exists(self.conf), 'the dnsmasq file was written although %s is invalid' % field)

    def test_no_shell_is_used_and_every_command_is_an_argument_list(self):
        started = []

        def no_system(cmd):
            raise AssertionError('os.system() called with %r' % (cmd,))

        def fake_run(argv, **kw):
            started.append((argv, kw))
            return mock.Mock(returncode=0)

        def fake_popen(argv, **kw):
            started.append((argv, kw))
            return mock.Mock()

        real_open = open
        conf = self.conf
        engine = irongate.Irongate.__new__(irongate.Irongate)
        engine.config = {'mode': 'dual', 'network': {'interface': 'eth0'},
                         'bridge': {'isolated_interface': 'eth1', 'bridge_name': 'br-irongate', 'bridge_ip': '10.99.0.1',
                                    'dhcp_start': '10.99.1.1', 'dhcp_end': '10.99.255.254'}}
        real_exists = os.path.exists
        with mock.patch.object(irongate.os, 'system', no_system), mock.patch.object(irongate.subprocess, 'run', fake_run), \
                mock.patch.object(irongate.subprocess, 'Popen', fake_popen), \
                mock.patch.object(irongate, 'open', lambda p, *a, **k: real_open(conf if p == '/etc/irongate/bridge-dnsmasq.conf' else p, *a, **k), create=True), \
                mock.patch.object(irongate.os.path, 'exists', lambda p: True if str(p).startswith('/sys/class/net/') else real_exists(p)):
            self.assertTrue(engine.run_dual_nic())
        self.assertEqual([a for a, _ in started], EXPECTED_DUAL_COMMANDS)
        for argv, kw in started:
            self.assertIsInstance(argv, list)
            self.assertTrue(all(isinstance(a, str) for a in argv), argv)
            self.assertFalse(kw.get('shell'), 'shell=True for %r' % (argv,))


class IfaceNameTests(unittest.TestCase):
    def test_valid_interface_names(self):
        for name in ('eth0', 'br-irongate', 'eth0.100', 'enx001122334455', '_x', 'a', 'a' * 15, 'wlan0', 'end0'):
            self.assertTrue(irongate._valid_iface(name), name)

    def test_invalid_interface_names(self):
        for name in ('', 'a' * 16, '-x', '.x', '..', '.', 'a b', 'a;b', 'a\n', 'eth0\n', 'a/b', 'a:1', 'a$b', 'a`b', 'é',
                     None, 5, ['eth0'], b'eth0'):
            self.assertFalse(irongate._valid_iface(name), repr(name))


if __name__ == '__main__':
    unittest.main()
