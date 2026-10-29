#!/usr/bin/env python3
"""
irongate web tier root helper: tests for src/irongate-webwrite (the only writer of /etc/irongate/config.yaml
and /etc/irongate/auth.json now that the web tier owns neither).

The helper is exercised for real, as root, at its real paths, so this refuses to run outside a throw-away
container:

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IRONGATE_DIR=/w/src \
        -v "$PWD":/w:ro -w /w python:3.12-slim python3 -I tests/test_webwrite.py

systemctl is a stand-in that records what it was asked and can be told to fail or to be slow; /dev/log is a
unix datagram socket this test binds so the helper's syslog audit line can be inspected.

The rendering parity case compares the helper's output for the fixture with tests/fixtures/
webwrite-parity-config.yaml, which is the seam generator's output for the same fixture (produced and checked
by tests/test_webwrite_php.php); the Generated line is normalised on both sides.
"""

import copy
import errno
import fcntl
import glob
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('IRONGATE_DIR') or os.path.join(os.path.dirname(HERE), 'src')
HELPER_SRC = os.path.join(SRC, 'irongate-webwrite')
HELPER = '/usr/local/sbin/irongate-webwrite'
ETC = '/etc/irongate'
CONFIG = os.path.join(ETC, 'config.yaml')
AUTH = os.path.join(ETC, 'auth.json')
LOCK = '/run/irongate-webwrite.lock'
SYSLOG = '/dev/log'
CTL_LOG = '/tmp/webwrite-systemctl.log'
CTL_SLEEP = '/tmp/webwrite-systemctl.sleep'
CTL_RC = '/tmp/webwrite-systemctl.rc'
WEB = 33
FIXTURE = os.path.join(HERE, 'fixtures', 'webwrite-parity-config.yaml')

OLD_CONFIG = b'# Irongate Configuration\n# Generated: 2026-01-01 00:00:00\n\nold: true\n'
HASH_A = '$2y$10$' + 'a' * 53
HASH_B = '$2y$10$' + 'a' * 25 + '/' + 'b' * 27
GOOD_HASH = '$2y$10$' + 'c' * 53


class SyslogCapture:
    def __init__(self, path=SYSLOG):
        self.path = path
        self.sock = None
        self.thread = None
        self.messages = []
        self.lock = threading.Lock()

    def start(self):
        if os.path.exists(self.path):
            return False
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(self.path)
            os.chmod(self.path, 0o666)
        except OSError:
            return False
        self.sock = sock
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def _run(self):
        while True:
            try:
                data, _ = self.sock.recvfrom(65536)
            except OSError:
                return
            with self.lock:
                self.messages.append(data.decode('utf-8', 'replace'))

    def clear(self):
        with self.lock:
            self.messages = []

    def snapshot(self):
        with self.lock:
            return list(self.messages)

    def wait_for(self, count, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            if len(self.snapshot()) >= count:
                return self.snapshot()
            time.sleep(0.05)
        return self.snapshot()


CAPTURE = SyslogCapture()


def write(path, data, uid=0, gid=0, mode=0o644):
    if isinstance(data, str):
        data = data.encode()
    with open(path, 'wb') as fh:
        fh.write(data)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def read(path):
    with open(path, 'rb') as fh:
        return fh.read()


def st(path):
    s = os.lstat(path)
    return '%d:%d:%o' % (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def setup_module_env():
    if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
        raise RuntimeError('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
    if os.geteuid() != 0:
        raise RuntimeError('must run as root')
    if not os.path.isfile(HELPER_SRC):
        raise AssertionError('src/irongate-webwrite does not exist: the root helper is missing')
    os.makedirs('/usr/bin', exist_ok=True)
    if not os.path.exists('/usr/bin/python3'):
        os.symlink(sys.executable, '/usr/bin/python3')
    write('/usr/bin/systemctl', '''#!/bin/sh
echo "$*" >> /tmp/webwrite-systemctl.log
if [ -f /tmp/webwrite-systemctl.sleep ]; then sleep "$(cat /tmp/webwrite-systemctl.sleep)"; fi
if [ -f /tmp/webwrite-systemctl.rc ]; then exit "$(cat /tmp/webwrite-systemctl.rc)"; fi
exit 0
''', mode=0o755)
    os.makedirs(ETC, exist_ok=True)
    if not CAPTURE.start():
        raise RuntimeError('cannot bind %s for the syslog audit check' % SYSLOG)
    probe = subprocess.run([sys.executable, '-I', '-c',
                            "import syslog; syslog.openlog('webwrite-probe'); syslog.syslog('probe')"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if probe.returncode != 0 or not CAPTURE.wait_for(1, 2.0):
        raise RuntimeError('the syslog capture does not receive messages: %s' % probe.stdout.decode())


def fresh():
    shutil.rmtree(ETC, ignore_errors=True)
    os.makedirs(ETC)
    os.chown(ETC, 0, WEB)
    os.chmod(ETC, 0o750)
    for path in (CTL_LOG, CTL_SLEEP, CTL_RC, LOCK):
        if os.path.lexists(path):
            os.unlink(path)
    os.makedirs(os.path.dirname(HELPER), exist_ok=True)
    shutil.copyfile(HELPER_SRC, HELPER)
    os.chown(HELPER, 0, 0)
    os.chmod(HELPER, 0o755)
    CAPTURE.clear()


def settings_dual():
    return {
        'network': {'interface': 'eth0', 'local_ip': '192.168.1.50', 'local_mac': 'aa:bb:cc:dd:ee:ff',
                    'gateway_ip': '192.168.1.1', 'gateway_mac': '11:22:33:44:55:66'},
        'mode': 'dual',
        'bridge': {'enabled': True, 'isolated_interface': 'eth1', 'bridge_name': 'br-irongate',
                   'bridge_ip': '10.99.0.1', 'bridge_netmask': '255.255.0.0',
                   'dhcp_start': '10.99.1.1', 'dhcp_end': '10.99.255.254', 'port_isolation': True},
        'layers': {'arp_defense': True, 'ipv6_ra': True, 'gateway_takeover': True,
                   'bypass_detection': True, 'firewall': True},
        'blockchain': {'enabled': True, 'network': 'preprod',
                       'contract_address': '0x' + 'ab' * 32,
                       'indexer_url': 'https://indexer.preprod.midnight.network/api/v4/graphql',
                       'cache_ttl': 60, 'fallback_allow': True, 'audit_logging': False,
                       'allow_rogue_devices': False},
        'custom_groups': [{'name': 'cams', 'color': '#6c757d', 'icon': '\U0001F4C1',
                           'description': 'front cameras', 'lan_access': 'selected',
                           'can_access_groups': ['servers', 'trusted']}],
        'devices': [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '192.168.1.10', 'zone': 'cams'},
                    {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '', 'zone': 'isolated'}],
    }


def config_payload(settings=None):
    return {'settings': settings if settings is not None else settings_dual()}


def run_helper(verb=None, payload=None, raw=None, extra=()):
    args = [HELPER] + ([verb] if verb is not None else []) + list(extra)
    if raw is None:
        raw = b'' if payload is None else json.dumps(payload).encode('utf-8')
    proc = subprocess.run(args, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    out = proc.stdout.decode('utf-8', 'replace')
    try:
        body = json.loads(out.strip().splitlines()[-1]) if out.strip() else None
    except ValueError:
        body = None
    return proc.returncode, body, out, proc.stderr.decode()


def systemctl_log():
    return read(CTL_LOG).decode().splitlines() if os.path.exists(CTL_LOG) else []


def leftovers():
    return glob.glob(os.path.join(ETC, '.config.yaml.new.*')) + glob.glob(os.path.join(ETC, '.auth.json.new.*'))


def normalize_generated(data):
    return re.sub(rb'^# Generated: .*$', b'# Generated: X', data, flags=re.M)


class Base(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(HELPER_SRC):
            self.fail('src/irongate-webwrite does not exist: the root helper is missing')
        fresh()

    def seed_config(self, data=OLD_CONFIG):
        write(CONFIG, data, 0, WEB, 0o640)

    def seed_auth(self):
        body = json.dumps({
            'username': 'admin', 'password_hash': HASH_A,
            'created_at': '2026-01-01T00:00:00+00:00', 'updated_at': '2026-01-01T00:00:00+00:00',
            'failed_attempts': 3, 'first_failed_at': 1800000000, 'locked_until': 0,
        }, indent=4) + '\n'
        write(AUTH, body, 0, WEB, 0o640)


class HelperPresent(Base):
    def test_helper_file_is_in_the_tree(self):
        self.assertTrue(os.path.isfile(HELPER_SRC))

    def test_shebang_and_python_syntax(self):
        text = read(HELPER_SRC).decode('utf-8')
        self.assertTrue(text.startswith('#!/usr/bin/python3 -I\n'), text[:40])
        compile(text, HELPER_SRC, 'exec')


class Arguments(Base):
    def test_no_verb_is_refused(self):
        rc, body, out, err = run_helper(None, raw=b'{}')
        self.assertEqual(rc, 2, out + err)
        self.assertFalse(body['success'])

    def test_unknown_verb_is_refused(self):
        rc, body, out, err = run_helper('config-write-everything', raw=b'{}')
        self.assertEqual(rc, 2, out + err)

    def test_extra_argument_is_refused(self):
        rc, body, out, err = run_helper('config-apply', config_payload(), extra=('/etc/irongate/config.yaml',))
        self.assertEqual(rc, 2, out + err)
        self.assertEqual(body['error'].endswith('refused: usage: irongate-webwrite <verb>'), True, body)

    def test_oversize_stdin_is_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'x' * 65537)
        self.assertEqual(rc, 2, out + err)

    def test_stdin_at_the_limit_is_still_parsed(self):
        rc, body, out, err = run_helper('config-apply', raw=b' ' * 65536)
        self.assertEqual(rc, 2, out + err)
        self.assertIn('refused', body['error'])

    def test_non_ascii_bytes_are_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'{"settings": {"network": {"interface": "\xff"}}}')
        self.assertEqual(rc, 2, out + err)

    def test_duplicate_keys_are_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'{"settings": {}, "settings": {}}')
        self.assertEqual(rc, 2, out + err)

    def test_nesting_beyond_four_levels_is_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'{"a": {"b": {"c": {"d": {"e": {}}}}}}')
        self.assertEqual(rc, 2, out + err)
        self.assertIn('nested too deeply', body['error'])

    def test_non_object_is_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'[]')
        self.assertEqual(rc, 2, out + err)

    def test_empty_input_is_refused(self):
        rc, body, out, err = run_helper('config-apply', raw=b'')
        self.assertEqual(rc, 2, out + err)


class ConfigRefusals(Base):
    def setUp(self):
        Base.setUp(self)
        self.seed_config()

    def refused(self, payload, label):
        before = read(CONFIG)
        rc, body, out, err = run_helper('config-apply', payload)
        self.assertEqual(rc, 2, '%s: %s%s' % (label, out, err))
        self.assertIsInstance(body, dict, label)
        self.assertFalse(body['success'], label)
        self.assertEqual(read(CONFIG), before, label)
        self.assertEqual(systemctl_log(), [], label)
        self.assertEqual(leftovers(), [], label)

    def test_unknown_settings_key(self):
        p = config_payload()
        p['settings']['extra'] = True
        self.refused(p, 'unknown settings key')

    def test_unknown_top_level_key(self):
        p = config_payload()
        p['verb'] = 'config-apply'
        self.refused(p, 'unknown top-level key')

    def test_missing_settings_key(self):
        p = config_payload()
        del p['settings']['layers']
        self.refused(p, 'missing layers')

    def test_wrong_type(self):
        p = config_payload()
        p['settings']['layers']['arp_defense'] = 'true'
        self.refused(p, 'string where a boolean belongs')

    def test_bridge_missing_in_dual_mode(self):
        p = config_payload()
        del p['settings']['bridge']
        self.refused(p, 'dual without bridge')

    def test_bridge_present_in_single_mode(self):
        p = config_payload()
        p['settings']['mode'] = 'single'
        self.refused(p, 'single with bridge')

    def test_bridge_constants(self):
        p = config_payload()
        p['settings']['bridge']['enabled'] = False
        self.refused(p, 'bridge enabled not true')

    def test_unknown_network(self):
        for value in ('bogus', 'Undeployed', 'testnet', ''):
            p = config_payload()
            p['settings']['blockchain']['network'] = value
            self.refused(p, 'network %r' % value)

    def test_undeployed_with_a_non_preset_loopback_url_is_refused(self):
        p = config_payload()
        p['settings']['blockchain']['network'] = 'undeployed'
        p['settings']['blockchain']['indexer_url'] = 'http://127.0.0.1:9000/x'
        self.refused(p, 'a loopback URL that is not the undeployed preset')

    def test_preprod_with_the_undeployed_preset_url_is_refused(self):
        p = config_payload()
        p['settings']['blockchain']['network'] = 'preprod'
        p['settings']['blockchain']['indexer_url'] = 'http://127.0.0.1:8088/api/v4/graphql'
        self.refused(p, "another network's preset URL")

    def test_malformed_contract_address(self):
        for value in ('0x1234', 'ab' * 32, '0x' + 'zz' * 32, ' 0x' + 'ab' * 32):
            p = config_payload()
            p['settings']['blockchain']['contract_address'] = value
            self.refused(p, 'contract %r' % value)

    def test_hostile_indexer_urls(self):
        for value in ('http://169.254.169.254/latest/meta-data/',
                      'http://127.0.0.1:8080/api',
                      'file:///etc/irongate/auth.json',
                      'HTTPS://indexer.preprod.midnight.network/api/v4/graphql',
                      'https://user@indexer.preprod.midnight.network/api',
                      'https://indexer.preprod.midnight.network:8443/api',
                      'https://indexer.preprod.midnight.network/api\\',
                      'https://evil.example.com/api'):
            p = config_payload()
            p['settings']['blockchain']['indexer_url'] = value
            self.refused(p, 'indexer %r' % value)

    def test_empty_indexer_and_contract_mean_default(self):
        p = config_payload()
        p['settings']['blockchain']['indexer_url'] = ''
        p['settings']['blockchain']['contract_address'] = None
        rc, body, out, err = run_helper('config-apply', p)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(body['success'])
        text = read(CONFIG).decode('utf-8')
        self.assertIn('  indexer_url: null\n', text)
        self.assertIn('  contract_address: null\n', text)

    def test_bad_group_name_and_access_entry(self):
        p = config_payload()
        p['settings']['custom_groups'][0]['name'] = '1bad'
        self.refused(p, 'group name with a leading digit')
        p = config_payload()
        p['settings']['custom_groups'][0]['can_access_groups'] = ['a b']
        self.refused(p, 'injected can_access_groups entry')
        p = config_payload()
        p['settings']['custom_groups'][0]['extra'] = 'x'
        self.refused(p, 'unknown group key')

    def test_bad_isolated_interface(self):
        for value in ('eth1; touch /tmp/x', 'eth1 && id', 'a' * 16, '-eth1'):
            p = config_payload()
            p['settings']['bridge']['isolated_interface'] = value
            self.refused(p, 'isolated_interface %r' % value)

    def test_lone_surrogate_is_refused_cleanly(self):
        p = config_payload()
        p['settings']['custom_groups'][0]['description'] = '\ud800'
        self.refused(p, 'lone surrogate in a description')

    def test_bad_device(self):
        p = config_payload()
        p['settings']['devices'][0]['mac'] = 'aa:bb:cc:dd:ee'
        self.refused(p, 'short mac')
        p = config_payload()
        p['settings']['devices'][0]['zone'] = 'x; flush ruleset'
        self.refused(p, 'nft-injection zone')
        p = config_payload()
        p['settings']['devices'][1]['ip'] = '192.168.001.2'
        self.refused(p, 'non-canonical ip')


class ConfigApply(Base):
    def test_changed_apply_writes_root_www_data_0640_and_restarts_once(self):
        self.seed_config()
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(body, {'success': True, 'error': '', 'changed': True})
        self.assertEqual(st(CONFIG), '0:33:640')
        text = read(CONFIG).decode('utf-8')
        self.assertTrue(text.startswith('# Irongate Configuration\n'))
        self.assertIn('  bridge_name: "br-irongate"\n', text)
        self.assertIn('  icon: "\U0001F4C1"\n', text)
        self.assertIn('    can_access_groups: ["servers", "trusted"]\n', text)
        self.assertEqual(systemctl_log(), ['restart irongate'])
        self.assertEqual(leftovers(), [])

    def test_undeployed_network_is_accepted(self):
        self.seed_config()
        p = config_payload()
        p['settings']['blockchain']['network'] = 'undeployed'
        p['settings']['blockchain']['indexer_url'] = ''
        rc, body, out, err = run_helper('config-apply', p)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(body['success'])
        text = read(CONFIG).decode('utf-8')
        self.assertIn('  network: "undeployed"\n', text)
        self.assertIn('  indexer_url: null\n', text)

    def test_undeployed_network_accepts_its_own_preset_url(self):
        self.seed_config()
        p = config_payload()
        p['settings']['blockchain']['network'] = 'undeployed'
        p['settings']['blockchain']['indexer_url'] = 'http://127.0.0.1:8088/api/v4/graphql'
        rc, body, out, err = run_helper('config-apply', p)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(body['success'])
        text = read(CONFIG).decode('utf-8')
        self.assertIn('  network: "undeployed"\n', text)
        self.assertIn('  indexer_url: "http://127.0.0.1:8088/api/v4/graphql"\n', text)

    def test_unchanged_apply_writes_nothing_and_does_not_restart(self):
        self.seed_config()
        rc, _, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        before_bytes = read(CONFIG)
        before_stat = os.stat(CONFIG)
        os.unlink(CTL_LOG)
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(body, {'success': True, 'error': '', 'changed': False})
        self.assertEqual(read(CONFIG), before_bytes)
        self.assertEqual(os.stat(CONFIG).st_mtime_ns, before_stat.st_mtime_ns)
        self.assertEqual(systemctl_log(), [])
        self.assertEqual(leftovers(), [])

    def test_restart_failure_exits_4(self):
        self.seed_config()
        write(CTL_RC, '1\n')
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 4, out + err)
        self.assertFalse(body['success'])
        self.assertTrue(body['changed'])
        self.assertEqual(systemctl_log(), ['restart irongate'])

    def test_symlink_target_is_refused(self):
        target = '/tmp/webwrite-symlink-target'
        write(target, b'do not touch\n')
        os.symlink(target, CONFIG)
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 2, out + err)
        self.assertEqual(read(target), b'do not touch\n')
        self.assertEqual(leftovers(), [])

    def test_directory_target_is_refused(self):
        if os.path.lexists(CONFIG):
            os.unlink(CONFIG)
        os.mkdir(CONFIG)
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 2, out + err)
        self.assertEqual(leftovers(), [])


class Locking(Base):
    def test_flock_blocks_a_second_call_until_the_first_finishes(self):
        self.seed_config()
        hold = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(hold, fcntl.LOCK_EX)
            proc = subprocess.Popen([HELPER, 'config-apply'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            proc.stdin.write(json.dumps(config_payload()).encode())
            proc.stdin.close()
            time.sleep(0.6)
            self.assertIsNone(proc.poll(), 'the helper did not wait for the lock')
            self.assertEqual(read(CONFIG), OLD_CONFIG, 'the helper wrote while the lock was held')
        finally:
            fcntl.flock(hold, fcntl.LOCK_UN)
            os.close(hold)
        out, err = proc.stdout.read(), proc.stderr.read()
        rc = proc.wait(timeout=60)
        proc.stdout.close()
        proc.stderr.close()
        self.assertEqual(rc, 0, out.decode() + err.decode())

    def test_two_concurrent_changed_applies_serialise(self):
        self.seed_config()
        write(CTL_SLEEP, '0.4\n')
        first = config_payload()
        second = config_payload()
        second['settings']['bridge']['bridge_ip'] = '10.99.0.2'
        procs = []
        for payload in (first, second):
            p = subprocess.Popen([HELPER, 'config-apply'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            p.stdin.write(json.dumps(payload).encode())
            p.stdin.close()
            procs.append(p)
        for p in procs:
            out, err = p.stdout.read(), p.stderr.read()
            rc = p.wait(timeout=120)
            p.stdout.close()
            p.stderr.close()
            self.assertEqual(rc, 0, out.decode() + err.decode())
        self.assertEqual(systemctl_log(), ['restart irongate', 'restart irongate'])
        text = read(CONFIG).decode('utf-8')
        self.assertTrue('  bridge_ip: "10.99.0.1"\n' in text or '  bridge_ip: "10.99.0.2"\n' in text, text[:400])
        self.assertEqual(leftovers(), [])


class Audit(Base):
    def test_one_line_per_call_and_no_values(self):
        self.seed_config()
        rc, _, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        lines = CAPTURE.wait_for(1)
        self.assertEqual(len(lines), 1, lines)
        line = lines[0]
        self.assertIn('irongate-webwrite', line)
        self.assertIn('verb=config-apply', line)
        self.assertIn('uid=', line)
        self.assertIn('rc=0', line)
        for value in ('front cameras', '192.168.1.50', 'aa:bb:cc:dd:ee:ff', 'indexer.preprod'):
            self.assertNotIn(value, line, 'the audit line leaked a value: %r' % line)

    def test_a_refused_value_is_not_logged(self):
        self.seed_config()
        p = config_payload()
        p['settings']['blockchain']['indexer_url'] = 'http://169.254.169.254/secret-marker'
        rc, _, out, err = run_helper('config-apply', p)
        self.assertEqual(rc, 2, out + err)
        lines = CAPTURE.wait_for(1)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn('verb=config-apply', lines[0])
        self.assertIn('rc=2', lines[0])
        self.assertNotIn('169.254', lines[0])
        self.assertNotIn('secret-marker', lines[0])


class Auth(Base):
    def test_credentials_merge_and_preserve_other_keys(self):
        self.seed_auth()
        rc, body, out, err = run_helper('auth-set-credentials', {'password_hash': HASH_B})
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(body, {'success': True, 'error': '', 'changed': True})
        self.assertEqual(st(AUTH), '0:33:640')
        data = json.loads(read(AUTH).decode('utf-8'))
        self.assertEqual(data['password_hash'], HASH_B)
        self.assertEqual(data['username'], 'admin')
        self.assertEqual(data['created_at'], '2026-01-01T00:00:00+00:00')
        self.assertEqual(data['failed_attempts'], 3)
        self.assertEqual(data['first_failed_at'], 1800000000)
        self.assertEqual(data['locked_until'], 0)
        self.assertIn('updated_at', data)
        # PHP's json_encode(JSON_PRETTY_PRINT) escaped "/" in the old file; so does this encoder.
        self.assertIn(b'\\/', read(AUTH))
        self.assertNotIn(b'systemctl', b''.join(x.encode() for x in systemctl_log()))
        self.assertEqual(leftovers(), [])

    def test_plaintext_is_refused(self):
        self.seed_auth()
        before = read(AUTH)
        for value in ('hunter2', '$2y$10$short', '$1$aaaa$' + 'a' * 53, HASH_B + 'x'):
            rc, body, out, err = run_helper('auth-set-credentials', {'password_hash': value})
            self.assertEqual(rc, 2, '%r: %s' % (value, out + err))
            self.assertEqual(read(AUTH), before)

    def test_extra_key_is_refused(self):
        self.seed_auth()
        rc, body, out, err = run_helper('auth-set-credentials', {'password_hash': HASH_B, 'username': 'x'})
        self.assertEqual(rc, 2, out + err)

    def test_missing_auth_file_exits_3(self):
        if os.path.exists(AUTH):
            os.unlink(AUTH)
        rc, body, out, err = run_helper('auth-set-credentials', {'password_hash': HASH_B})
        self.assertEqual(rc, 3, out + err)

    def test_unparsable_auth_file_exits_3(self):
        write(AUTH, b'not json\n', 0, WEB, 0o640)
        rc, body, out, err = run_helper('auth-set-username', {'username': 'newadmin'})
        self.assertEqual(rc, 3, out + err)

    def test_symlink_auth_file_is_refused(self):
        target = '/tmp/webwrite-auth-target'
        write(target, b'{"username": "admin"}\n')
        os.symlink(target, AUTH)
        rc, body, out, err = run_helper('auth-set-username', {'username': 'newadmin'})
        self.assertEqual(rc, 2, out + err)
        self.assertEqual(read(target), b'{"username": "admin"}\n')

    def test_username_merge(self):
        self.seed_auth()
        rc, body, out, err = run_helper('auth-set-username', {'username': 'new.admin-1_x'})
        self.assertEqual(rc, 0, out + err)
        data = json.loads(read(AUTH).decode('utf-8'))
        self.assertEqual(data['username'], 'new.admin-1_x')
        self.assertEqual(data['password_hash'], HASH_A)
        self.assertEqual(st(AUTH), '0:33:640')

    def test_invalid_usernames_are_refused(self):
        self.seed_auth()
        before = read(AUTH)
        for value in ('', 'a b', 'a' * 33, 'admin\n', 'admin;id'):
            rc, body, out, err = run_helper('auth-set-username', {'username': value})
            self.assertEqual(rc, 2, '%r: %s' % (value, out + err))
            self.assertEqual(read(AUTH), before)


class Parity(Base):
    def test_helper_rendering_equals_the_php_generator_output(self):
        self.assertTrue(os.path.isfile(FIXTURE),
                        'tests/fixtures/webwrite-parity-config.yaml is missing (it is produced by tests/test_webwrite_php.php)')
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        rendered = normalize_generated(read(CONFIG))
        expected = normalize_generated(read(FIXTURE))
        self.assertEqual(rendered, expected)

    def test_output_is_one_json_object(self):
        self.seed_config()
        rc, body, out, err = run_helper('config-apply', config_payload())
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(len(out.strip().splitlines()), 1, out)
        self.assertIsInstance(body, dict)


def setUpModule():
    setup_module_env()


if __name__ == '__main__':
    unittest.main(verbosity=2)
