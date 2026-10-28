#!/usr/bin/env python3
"""
irongate-audit O4: tests for the root helper src/dnsmasq-apply (the only writer of /etc/dnsmasq.conf and
/etc/dnsmasq.d/reservations.conf now that www-data owns neither).

The helper is exercised for real, as root, at its real paths, so this refuses to run outside a throw-away
container:

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IRONGATE_DIR=/w/src -e IG_CHAR_DIR=/chars \
        -v "$PWD":/w:ro -v <php-step output>:/chars:ro \
        -v /usr/sbin/dnsmasq:/host-dnsmasq:ro -v /lib/x86_64-linux-gnu:/hostlib:ro \
        -w /w python:3.12-slim python -m pytest tests/test_dnsmasq_apply.py

dnsmasq is the real binary (mounted from the host, run through its own loader); systemctl and ip are small
stand-ins that record what they were asked and can be told to fail. IG_CHAR_DIR holds the characterization data
written by tests/test_dnsmasq_phpside.php (the request api.php staged for each settings vector, and what the old
PHP generator of 18e5177 produced for the same database).
"""

import contextlib
import ctypes
import errno
import glob
import io
import json
import os
import random
import re
import shutil
import stat
import struct
import subprocess
import sys
import unittest
import unittest.mock
import importlib.machinery
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('IRONGATE_DIR') or os.path.join(os.path.dirname(HERE), 'src')
HELPER_SRC = os.path.join(SRC, 'dnsmasq-apply')
CHAR_DIR = os.environ.get('IG_CHAR_DIR', '/chars')

HELPER = '/opt/irongate/dnsmasq-apply'
CONF = '/etc/dnsmasq.conf'
CONFD = '/etc/dnsmasq.d'
RES = CONFD + '/reservations.conf'
OPERATOR = CONFD + '/operator-local.conf'
STAGE = '/var/lib/irongate/dnsmasq-staged'
WEB = 33  # www-data

OLD_MAIN = b'# OLD MAIN\nport=0\n'
OLD_RES = b'# OLD RES\n'
OPERATOR_TEXT = b'# operator file, root-owned\ndhcp-option=option:ntp-server,192.168.1.2\n'

# the directives named in the O4 brief, plus every other option that runs a program or reads or writes a file
BRIEF_FORBIDDEN = ['dhcp-script', 'dhcp-luascript', 'conf-file', 'conf-dir', 'addn-hosts', 'dhcp-hostsfile',
                   'dhcp-optsfile', 'servers-file', 'script-arp']
FORBIDDEN_EXTRA = ['conf-script', 'dhcp-scriptuser', 'dnssec-timestamp', 'hostsdir', 'dhcp-hostsdir', 'dhcp-optsdir', 'resolv-file', 'pid-file',
                   'dhcp-leasefile', 'dhcp-lease', 'leasefile-ro', 'log-facility', 'dumpfile', 'dumpmask', 'tftp-root', 'enable-tftp',
                   'dhcp-boot', 'pxe-service', 'user', 'group', 'read-ethers', 'dhcp-relay', 'dhcp-proxy', 'ipset',
                   'nftset', 'trust-anchor', 'connmark-allowlist']
ALL_FORBIDDEN = BRIEF_FORBIDDEN + FORBIDDEN_EXTRA

GOOD = {'dhcp_enabled': 'true', 'interface': 'eth0', 'cidr': '24', 'range_start': '192.168.1.100',
        'range_end': '192.168.1.200', 'gateway': '192.168.1.1', 'dns_primary': '8.8.8.8',
        'dns_secondary': '1.1.1.1', 'lease_time': '24h', 'domain': 'local'}
GOOD_RES = [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '192.168.1.10', 'hostname': 'printer'},
            {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '192.168.1.11', 'hostname': ''}]


def request(settings=None, reservations=None, action='apply', **extra):
    body = {'version': 1, 'action': action, 'settings': GOOD if settings is None else settings,
            'reservations': GOOD_RES if reservations is None else reservations}
    body.update(extra)
    return body


def load_module():
    if not os.path.isfile(HELPER_SRC):
        raise AssertionError('src/dnsmasq-apply does not exist: the root helper of the O4 design is missing')
    loader = importlib.machinery.SourceFileLoader('dnsmasq_apply_under_test', HELPER_SRC)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(module)
    return module


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


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
    """Stand-ins and the real dnsmasq, in this disposable container."""
    if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
        raise RuntimeError('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
    if os.geteuid() != 0:
        raise RuntimeError('must run as root')
    os.makedirs('/usr/bin', exist_ok=True)
    if not os.path.exists('/usr/bin/python3'):
        os.symlink(sys.executable, '/usr/bin/python3')
    if os.path.exists('/host-dnsmasq'):
        write('/usr/sbin/dnsmasq', '#!/bin/sh\nexec /hostlib/ld-linux-x86-64.so.2 --library-path /hostlib /host-dnsmasq "$@"\n', mode=0o755)
    elif os.environ.get('IG_ALLOW_STUB_DNSMASQ') == '1':
        write('/usr/sbin/dnsmasq', '#!/bin/sh\necho "dnsmasq: syntax check OK." >&2\nexit 0\n', mode=0o755)
    else:
        raise RuntimeError('the real dnsmasq is not mounted at /host-dnsmasq')
    write('/usr/bin/systemctl', '''#!/bin/sh
echo "$*" >> /tmp/systemctl.log
case "$1" in start) f=/tmp/systemctl.start.rcs;; stop) f=/tmp/systemctl.stop.rcs;; *) exit 0;; esac
if [ -s "$f" ]; then rc=$(head -n1 "$f"); sed -i 1d "$f"; echo "systemctl: simulated failure ($rc)" >&2; exit "$rc"; fi
exit 0
''', mode=0o755)
    write('/usr/sbin/ip', '#!/bin/sh\n[ "$1" = route ] && printf "default via 192.168.1.1 dev eth9 proto static\\n192.168.1.0/24 dev eth9 scope link\\n"\n', mode=0o755)
    os.makedirs('/opt/irongate', exist_ok=True)


def fresh_env():
    """The state the installer / apply.sh leaves: root-owned config, operator file, empty staging dir."""
    for p in (CONF, '/tmp/systemctl.log', '/tmp/systemctl.start.rcs', '/tmp/systemctl.stop.rcs', '/run/irongate-dnsmasq-apply.lock'):
        if os.path.lexists(p):
            os.unlink(p)
    shutil.rmtree(CONFD, ignore_errors=True)
    shutil.rmtree('/var/lib/irongate', ignore_errors=True)
    os.makedirs(CONFD, mode=0o755)
    os.chmod(CONFD, 0o755)
    os.makedirs('/var/lib/irongate', mode=0o755)
    os.makedirs(STAGE)
    os.chown(STAGE, 0, WEB)
    os.chmod(STAGE, 0o770)
    write(CONF, OLD_MAIN)
    write(RES, OLD_RES)
    write(OPERATOR, OPERATOR_TEXT)
    shutil.copyfile(HELPER_SRC, HELPER)
    os.chown(HELPER, 0, 0)
    os.chmod(HELPER, 0o755)


def stage(body, uid=WEB, gid=WEB, mode=0o600, name='request.json'):
    data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    path = os.path.join(STAGE, name)
    write(path, data, uid, gid, mode)
    return path


def run_helper(args=()):
    proc = subprocess.run([HELPER] + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    out = proc.stdout.decode()
    try:
        body = json.loads(out.strip().splitlines()[-1]) if out.strip() else None
    except ValueError:
        body = None
    return proc.returncode, body, out, proc.stderr.decode()


def as_web(code, stdin=None):
    """Run python code as www-data (no supplementary groups)."""
    def drop():
        os.setgroups([])
        os.setgid(WEB)
        os.setuid(WEB)
    return subprocess.run([sys.executable, '-I', '-c', code], preexec_fn=drop, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          input=stdin)


def systemctl_log():
    return read('/tmp/systemctl.log').decode().splitlines() if os.path.exists('/tmp/systemctl.log') else []


def left_over():
    """Temp files the helper must never leave behind."""
    found = []
    for d in ('/etc', CONFD, STAGE):
        found += [os.path.join(d, n) for n in os.listdir(d) if re.search(r'\.(new|test|lock)\.\d+(\.\d+)*$', n)]
    return found


def dnsmasq_option_table(path='/host-dnsmasq'):
    """dnsmasq's long-option table [(name, has_arg, val)] read out of the dnsmasq ELF binary (option.c: opts[] = {name, has_arg, flag, val};
    the name pointers are relative relocations in .data.rel.ro: x86_64 and aarch64). The table starts at "version" and ends at the entry
    without a name. Reads the file only."""
    if not os.path.exists(path):
        raise unittest.SkipTest('the real dnsmasq binary is not mounted at %s (IG_ALLOW_STUB_DNSMASQ)' % path)
    data = read(path)
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise AssertionError('%s is not an ELF64 little-endian file' % path)
    machine, = struct.unpack_from('<H', data, 0x12)
    rel_type = {62: 8, 183: 1027}[machine]  # R_X86_64_RELATIVE, R_AARCH64_RELATIVE
    e_shoff, = struct.unpack_from('<Q', data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    e_phoff, = struct.unpack_from('<Q', data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    names = sections[e_shstrndx]
    by_name = dict((data[names[4] + sec[0]:names[4] + sec[0] + 64].split(b'\0', 1)[0].decode(), sec) for sec in sections)
    loads = []
    for i in range(e_phnum):
        p_type, _flags, p_off, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from('<IIQQQQQQ', data, e_phoff + i * e_phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_off, p_filesz))

    def offset(vaddr):
        for va, fo, size in loads:
            if va <= vaddr < va + size:
                return fo + vaddr - va
        return None

    rela = by_name['.rela.dyn']
    relative = {}
    for i in range(rela[5] // 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, rela[4] + i * 24)
        if r_info & 0xffffffff == rel_type:
            relative[r_offset] = r_addend

    def cstring(vaddr):
        o = offset(vaddr)
        return None if o is None else data[o:data.index(b'\0', o)].decode('latin-1')

    section = by_name['.data.rel.ro']
    start = None
    for slot in sorted(a for a in relative if section[3] <= a < section[3] + section[5]):
        o = offset(slot)
        if cstring(relative[slot]) == 'version' and struct.unpack_from('<i', data, o + 8)[0] == 0 and struct.unpack_from('<i', data, o + 24)[0] == ord('v'):
            start = slot
            break
    if start is None:
        raise AssertionError('no option table in %s' % path)
    table, slot = [], start
    while slot in relative:
        o = offset(slot)
        table.append((cstring(relative[slot]), struct.unpack_from('<i', data, o + 8)[0], struct.unpack_from('<i', data, o + 24)[0]))
        slot += 32
    return table


def setUpModule():
    setup_module_env()


class Base(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(HELPER_SRC):
            self.fail('src/dnsmasq-apply does not exist: the root helper of the O4 design is missing')
        fresh_env()

    def untouched(self):
        self.assertEqual(read(CONF), OLD_MAIN)
        self.assertEqual(read(RES), OLD_RES)
        self.assertEqual(read(OPERATOR), OPERATOR_TEXT)
        self.assertEqual(left_over(), [])


# ================================================================ the helper exists and is installed the way the brief says
class HelperPresent(Base):
    def test_helper_file_is_in_the_tree(self):
        self.assertTrue(os.path.isfile(HELPER_SRC), 'src/dnsmasq-apply does not exist: the root helper of the O4 design is missing')

    def test_python_syntax_and_shebang(self):
        text = read(HELPER_SRC).decode()
        self.assertTrue(text.startswith('#!/usr/bin/python3 -I\n'), text[:40])
        compile(text, HELPER_SRC, 'exec')


# ================================================================ (a) crafted settings are rejected and never rendered
INJECTIONS = ['x\ndhcp-script=/tmp/x', 'x\r\ndhcp-script=/tmp/x', '\ndhcp-script=/tmp/x', 'x\ndhcp-luascript=/tmp/x',
              'x\nconf-file=/tmp/x', 'x\nconf-dir=/tmp/x', 'x\ndhcp-hostsfile=/tmp/x', 'x\x00y', 'x=y', 'a\tb', 'a b',
              'x\u0430', 'x' * 300, 'x\n', 'dhcp-script=/tmp/x']
NON_STRINGS = [123, None, True, ['a'], {'a': 1}, 1.5]


class CraftedValues(Base):
    FIELDS_ALLOWING_EMPTY = {'interface', 'cidr', 'range_start', 'range_end', 'gateway', 'dns_primary', 'dns_secondary',
                             'lease_time', 'domain'}

    def setUp(self):
        Base.setUp(self)
        self.mod = load_module()

    def check_rejected(self, body, label):
        rc, resp, out, err = run_helper_with(body)
        self.assertEqual(rc, 2, '%s: exit %s %s %s' % (label, rc, out[:200], err[:200]))
        self.assertIsNotNone(resp, label)
        self.assertFalse(resp['success'], label)
        self.assertNotIn('/tmp/x', out + err, '%s: the payload is echoed back' % label)
        self.untouched()
        self.assertFalse(os.path.exists('/tmp/x'))
        self.assertFalse(os.path.exists(os.path.join(STAGE, 'request.json')), '%s: the request must be consumed' % label)

    def test_every_injection_in_every_setting_is_refused_end_to_end(self):
        for key in GOOD:
            for payload in INJECTIONS:
                with self.subTest(field=key, payload=payload[:20]):
                    s = dict(GOOD)
                    s[key] = payload
                    self.check_rejected(request(settings=s), '%s=%r' % (key, payload[:30]))

    def test_every_injection_in_every_reservation_field_is_refused_end_to_end(self):
        for key in ('mac', 'ip', 'hostname'):
            for payload in INJECTIONS:
                with self.subTest(field=key, payload=payload[:20]):
                    res = [dict(GOOD_RES[0])]
                    res[0][key] = payload
                    self.check_rejected(request(reservations=res), 'reservation %s=%r' % (key, payload[:30]))

    def test_non_string_values_are_refused(self):
        for key in GOOD:
            for payload in NON_STRINGS:
                with self.subTest(field=key, payload=repr(payload)):
                    s = dict(GOOD)
                    s[key] = payload
                    self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=s)).encode())

    def test_the_quoted_attack_from_the_brief_is_absent_from_every_rendering(self):
        """\\ndhcp-script=/tmp/x in the domain, in the lease time, in a hostname: nothing that is accepted may carry it."""
        for key in ('domain', 'lease_time', 'dns_primary', 'gateway'):
            s = dict(GOOD)
            s[key] = '\ndhcp-script=/tmp/x'
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=s)).encode())
        # and the one dhcp-script line of a genuine rendering is the constant
        action, settings, reservations = self.mod.parse_request(json.dumps(request()).encode())
        text = self.mod.render_main(settings) + self.mod.render_reservations(reservations)
        self.assertEqual(text.count('dhcp-script'), 1)
        self.assertIn('\ndhcp-script=/opt/irongate/dhcp-notify.sh\n', text)
        self.assertNotIn('/tmp/x', text)

    def test_limits(self):
        many = [{'mac': 'aa:bb:cc:%02x:%02x:01' % (i // 256, i % 256), 'ip': '10.0.%d.%d' % (i // 250, i % 250 + 1), 'hostname': ''}
                for i in range(self.mod.MAX_RESERVATIONS + 1)]
        self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(reservations=many)).encode())
        deep = b'[' * 5000 + b']' * 5000
        self.assertRaises(self.mod.Reject, self.mod.parse_request, deep)
        self.assertRaises(self.mod.Reject, self.mod.parse_request, b'{"version": 1, "version": 1}')
        self.assertRaises(self.mod.Reject, self.mod.parse_request, b'{"version": NaN}')
        self.assertRaises(self.mod.Reject, self.mod.parse_request, b'\xff\xfe')
        self.assertRaises(self.mod.Reject, self.mod.parse_request, b'{"version": true, "action": "apply"}')

    def test_the_generic_scan_holds_even_when_a_field_check_is_loose(self):
        """Defence in depth: a newline, NUL, '=' or non-ASCII character anywhere in the request is refused by a scan that
        does not depend on the per-field checks (simulated by replacing them with checks that accept anything)."""
        mod = load_module()
        mod.normalize_settings = lambda s: {}
        mod.normalize_reservations = lambda r: []
        for payload in ['x\ndhcp-script=/tmp/x', 'x\r', 'x\x00', 'x=y', 'x\ty', 'x\x7f', '\u00e9']:
            for body in (request(settings={'domain': payload}), request(reservations=[{'hostname': payload}])):
                with self.subTest(payload=payload):
                    self.assertRaises(mod.Reject, mod.parse_request, json.dumps(body).encode())
        self.assertEqual(mod.parse_request(json.dumps(request(settings={'domain': 'ok'})).encode())[0], 'apply')

    def test_the_rendered_text_is_checked_again_so_a_renderer_bug_cannot_reach_the_disk(self):
        """verify_main/verify_reservations run on the output; simulate a renderer that emits a stray directive."""
        action, settings, reservations = load_module().parse_request(json.dumps(request()).encode())
        mod = load_module()
        mod.HEADER_FMT = '# %s\ndhcp-script=/tmp/pwn\n'
        self.assertRaises(mod.Reject, mod.render_main, settings)
        mod = load_module()
        mod.HEADER_FMT = '# %s\nuser=root\n'
        self.assertRaises(mod.Reject, mod.render_main, settings)
        mod = load_module()
        mod.FIXED_CONFDIR = 'conf-dir=/tmp/evil,*.conf'
        text = '# a\ninterface=eth0\nport=0\n%s\n%s\n%s\n%s\n' % (mod.FIXED_LEASEFILE, mod.FIXED_LOGFACILITY, mod.FIXED_SCRIPT, 'conf-dir=/etc/dnsmasq.d/,*.conf')
        self.assertRaises(mod.Reject, mod.verify_main, text)
        mod = load_module()
        mod.RES_HEADER = 'user=root\n'
        self.assertRaises(mod.Reject, mod.render_reservations, reservations)
        mod = load_module()
        self.assertRaises(mod.Reject, mod.verify_main, '# a\ninterface=eth0\nport=0\ndhcp-script=/opt/irongate/dhcp-notify.sh\n')

    def test_valid_controls_are_accepted(self):
        """Every field with a genuine value (and the empty value where the dashboard sends one) passes."""
        action, s, r = self.mod.parse_request(json.dumps(request()).encode())
        self.assertEqual(action, 'apply')
        self.assertEqual(s['range_start'], '192.168.1.100')
        self.assertEqual(len(r), 2)
        for key in self.FIELDS_ALLOWING_EMPTY:
            with self.subTest(empty=key):
                t = dict(GOOD)
                t[key] = ''
                self.mod.parse_request(json.dumps(request(settings=t)).encode())
        for lease in ('30m', '24H', '7d', '1w', 'infinite', 'INFINITE', '3600', '90s'):
            t = dict(GOOD, lease_time=lease)
            self.mod.parse_request(json.dumps(request(settings=t)).encode())
        for iface in ('eth0', 'enp3s0', 'wlan0.100', 'br_lan', 'bond-0', 'a' * 15):
            self.mod.parse_request(json.dumps(request(settings=dict(GOOD, interface=iface))).encode())
        for bad in ('a' * 16, 'eth 0', 'eth0/x', ''):
            if bad:
                self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=dict(GOOD, interface=bad))).encode())
        for bad in ('192.168.1', '192.168.01.1', '192.168.1.256', '::1', '192.168.1.1/24', '1.2.3. 4', 'host.example'):
            with self.subTest(bad_ip=bad):
                self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=dict(GOOD, gateway=bad))).encode())
        for bad in ('-1', '33', 'x', '24.0'):
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=dict(GOOD, cidr=bad))).encode())
        for bad in ('24 h', '24hh', 'forever', '-5', '24h,5'):
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=dict(GOOD, lease_time=bad))).encode())
        for bad in ('-a.b', 'a..b', '.a', 'a.', 'a,b', 'a b'):
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(settings=dict(GOOD, domain=bad))).encode())
        for bad in ('aa:bb:cc:dd:ee', 'aa-bb-cc-dd-ee-ff', 'aabbccddeeff', 'aa:bb:cc:dd:ee:gg', '*:*:*:*:*:*'):
            res = [dict(GOOD_RES[0], mac=bad)]
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(reservations=res)).encode())
        for bad in ('-x', 'x-', 'a_b', 'a' * 64, 'x y'):
            res = [dict(GOOD_RES[0], hostname=bad)]
            self.assertRaises(self.mod.Reject, self.mod.parse_request, json.dumps(request(reservations=res)).encode())


def run_helper_with(body):
    stage(body)
    return run_helper()


# ================================================================ (d) every forbidden directive is refused as a whole
class ForbiddenDirectives(Base):
    def setUp(self):
        Base.setUp(self)
        self.mod = load_module()

    def forms(self, name):
        yield name
        yield name.upper()
        yield name.replace('-', '_')
        yield ' ' + name
        yield name + ' '
        yield '--' + name
        yield 'Dhcp_Script' if name == 'dhcp-script' else name.title()

    def test_the_helper_knows_every_directive_of_the_brief_and_the_extra_ones(self):
        missing = [n for n in ALL_FORBIDDEN if n not in self.mod.FORBIDDEN]
        self.assertEqual(missing, [], 'FORBIDDEN lacks: %s' % missing)

    def test_as_a_settings_key_every_form_is_refused_and_named_end_to_end(self):
        for name in ALL_FORBIDDEN:
            for form in self.forms(name):
                with self.subTest(directive=form):
                    s = dict(GOOD)
                    s[form] = '/tmp/x'
                    rc, resp, out, err = run_helper_with(request(settings=s))
                    self.assertEqual(rc, 2, '%r: exit %s %s' % (form, rc, out[:200]))
                    self.assertFalse(resp['success'])
                    self.assertIn('forbidden directive', resp['error'], form)
                    self.untouched()

    def test_as_a_top_level_key_or_reservation_key_it_is_refused_end_to_end(self):
        for name in ALL_FORBIDDEN:
            with self.subTest(directive=name, where='top'):
                rc, resp, out, err = run_helper_with(request(**{name: '/tmp/x'}))
                self.assertEqual(rc, 2)
                self.assertIn('forbidden directive', resp['error'])
                self.untouched()
            with self.subTest(directive=name, where='reservation'):
                res = [dict(GOOD_RES[0])]
                res[0][name] = '/tmp/x'
                rc, resp, out, err = run_helper_with(request(reservations=res))
                self.assertEqual(rc, 2)
                self.assertIn('forbidden directive', resp['error'])
                self.untouched()

    def test_the_directive_inside_a_value_or_with_an_equals_sign_is_refused_end_to_end(self):
        for name in ALL_FORBIDDEN:
            for key in ('domain', 'interface', 'lease_time'):
                with self.subTest(directive=name, field=key):
                    s = dict(GOOD)
                    s[key] = name + '=/tmp/x'
                    rc, resp, out, err = run_helper_with(request(settings=s))
                    self.assertEqual(rc, 2)
                    self.untouched()
            with self.subTest(directive=name, as_key_with_value='eq'):
                s = dict(GOOD)
                s[name + '=/tmp/x'] = 'y'
                rc, resp, out, err = run_helper_with(request(settings=s))
                self.assertEqual(rc, 2)
                self.untouched()

    def test_one_forbidden_key_poisons_an_otherwise_valid_request(self):
        s = dict(GOOD, **{'dhcp-script': '/tmp/x'})
        rc, resp, out, err = run_helper_with(request(settings=s))
        self.assertEqual(rc, 2)
        self.untouched()
        self.assertEqual(systemctl_log(), [], 'dnsmasq must not even be stopped for a refused request')

    def test_unknown_keys_are_refused_too(self):
        for key in ('irongate_enabled', 'password', 'dhcp_leasetime', 'x', ''):
            rc, resp, out, err = run_helper_with(request(settings=dict(GOOD, **{key: 'v'})))
            self.assertEqual(rc, 2, key)
            self.untouched()
        rc, resp, out, err = run_helper_with(request(extra_top='v'))
        self.assertEqual(rc, 2)

    def test_control_the_same_request_without_the_forbidden_key_is_applied(self):
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual((rc, resp['success']), (0, True), out + err)
        self.assertNotEqual(read(CONF), OLD_MAIN)


# ================================================================ a genuine apply, and what it leaves behind
class Apply(Base):
    def test_apply_renders_installs_and_restarts(self):
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual((rc, resp), (0, {'success': True, 'stage': 'start'}), out + err)
        main, res = read(CONF).decode(), read(RES).decode()
        self.assertEqual(st(CONF), '0:0:644')
        self.assertEqual(st(RES), '0:0:644')
        self.assertEqual(st(CONFD), '0:0:755')
        self.assertIn('\ndhcp-script=/opt/irongate/dhcp-notify.sh\n', main)
        self.assertIn('\nconf-dir=/etc/dnsmasq.d/,*.conf\n', main)
        self.assertEqual(main.count('dhcp-script'), 1)
        self.assertIn('dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h', main)
        self.assertEqual(res, "# Static DHCP Reservations - Auto-generated by Web UI\n"
                              "dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,printer\ndhcp-host=aa:bb:cc:dd:ee:02,192.168.1.11\n")
        self.assertEqual(systemctl_log(), ['stop dnsmasq', 'start dnsmasq'])
        self.assertEqual(left_over(), [])
        self.assertFalse(os.path.exists(os.path.join(STAGE, 'request.json')))

    def test_the_rendering_passes_the_real_dnsmasq_with_the_operator_file_in_the_directory(self):
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 0, out)
        proc = sh('dnsmasq --test --conf-file=/etc/dnsmasq.conf')
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(b'syntax check OK', proc.stdout)
        self.assertEqual(read(OPERATOR), OPERATOR_TEXT)
        self.assertEqual(st(OPERATOR), '0:0:644')

    def test_the_operator_file_is_never_modified(self):
        before = os.stat(OPERATOR)
        run_helper_with(request())
        run_helper_with(request(settings=dict(GOOD, domain='lan')))
        after = os.stat(OPERATOR)
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_size), (after.st_ino, after.st_mtime_ns, after.st_size))
        self.assertEqual(read(OPERATOR), OPERATOR_TEXT)

    def test_validate_changes_nothing_and_reports_dnsmasqs_verdict(self):
        rc, resp, out, err = run_helper_with(request(action='validate'))
        self.assertEqual(rc, 0, out)
        self.assertTrue(resp['success'] and resp['valid'], resp)
        self.assertEqual(resp['return_code'], 0)
        self.assertIn('syntax check OK', resp['output'])
        self.untouched()
        self.assertEqual(systemctl_log(), [])

    def test_a_clash_with_the_operator_file_is_refused_by_dnsmasq_and_rolled_back(self):
        """The operator's own file sits in the same directory: dnsmasq reads both, so a duplicate dhcp-host fails --test."""
        write(OPERATOR, OPERATOR_TEXT + b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\n')
        before = read(OPERATOR)
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 3, out + err)
        self.assertFalse(resp['success'])
        self.assertIn('duplicate dhcp-host', resp['error'])
        self.assertEqual(read(CONF), OLD_MAIN)
        self.assertEqual(read(RES), OLD_RES)
        self.assertEqual(read(OPERATOR), before)
        self.assertEqual(systemctl_log(), [])

    def test_empty_interface_uses_the_default_route_like_the_old_generator(self):
        rc, resp, out, err = run_helper_with(request(settings=dict(GOOD, interface='')))
        self.assertEqual(rc, 0, out)
        self.assertIn('\ninterface=eth9\n', read(CONF).decode())

    def test_dhcp_disabled_or_range_missing_renders_the_disabled_branch(self):
        for s in ({'dhcp_enabled': 'false', 'interface': 'eth0'},
                  dict(GOOD, range_end=''), dict(GOOD, dhcp_enabled='false')):
            rc, resp, out, err = run_helper_with(request(settings=s, reservations=[]))
            self.assertEqual(rc, 0, out)
            main = read(CONF).decode()
            self.assertIn('# DHCP is disabled - configure via Web UI', main)
            self.assertNotIn('dhcp-range', main)

    def test_dnsmasq_test_failure_restores_the_previous_files(self):
        dup = [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '192.168.1.10', 'hostname': 'a'},
               {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '192.168.1.10', 'hostname': 'b'}]
        rc, resp, out, err = run_helper_with(request(reservations=dup))
        self.assertEqual(rc, 3, out + err)
        self.assertEqual((resp['success'], resp['stage']), (False, 'validation'))
        self.assertIn('duplicate dhcp-host IP', resp['error'])
        self.untouched()
        self.assertEqual(systemctl_log(), [])

    def test_start_failure_restores_the_previous_files_and_starts_dnsmasq_again(self):
        write('/tmp/systemctl.start.rcs', '5\n')
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 4, out + err)
        self.assertEqual((resp['success'], resp['stage'], resp['error']), (False, 'start', 'Service start failed'))
        self.assertTrue(resp['restored'] and resp['restarted'])
        self.untouched()
        self.assertEqual(systemctl_log(), ['stop dnsmasq', 'start dnsmasq', 'start dnsmasq'])

    def test_an_unexpected_error_halfway_restores_the_previous_files(self):
        mod = load_module()
        action, settings, reservations = mod.parse_request(json.dumps(request()).encode())
        real_run = mod._run
        calls = []

        def boom(argv, timeout):
            calls.append(argv)
            if 'stop' in argv:
                raise RuntimeError('simulated crash while stopping dnsmasq')
            return real_run(argv, timeout)
        mod._run = boom
        with self.assertRaises(RuntimeError):
            mod.apply('apply', settings, reservations)
        self.untouched()
        self.assertTrue(any('stop' in c for c in calls))

    def test_first_install_without_previous_files_is_cleaned_up_on_failure(self):
        os.unlink(CONF)
        os.unlink(RES)
        write('/tmp/systemctl.start.rcs', '5\n')
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 4)
        self.assertFalse(os.path.exists(CONF))
        self.assertFalse(os.path.exists(RES))

    def test_no_request_symlink_foreign_owner_or_hardlink_is_refused(self):
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        # symlink to a file of the attacker's choosing: refused and removed, the target is never read
        write('/tmp/secret-target', json.dumps(request()))
        os.symlink('/tmp/secret-target', os.path.join(STAGE, 'request.json'))
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        self.assertFalse(os.path.lexists(os.path.join(STAGE, 'request.json')))
        self.assertTrue(os.path.exists('/tmp/secret-target'))
        # owned by somebody else
        stage(request(), uid=1000, gid=1000)
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        # a second hard link
        p = stage(request())
        os.link(p, '/tmp/second-link')
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        os.unlink('/tmp/second-link')
        # a directory (cleared by the helper, see DirectoryNamedRequest) and a FIFO
        os.mkdir(os.path.join(STAGE, 'request.json'))
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        self.assertFalse(os.path.lexists(os.path.join(STAGE, 'request.json')), 'a directory named request.json must not stay in the way')
        os.mkfifo(os.path.join(STAGE, 'request.json'))
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        # too large
        stage(b'{"version": 1, "pad": "' + b'x' * (1024 * 1024) + b'"}')
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        self.untouched()

    def test_unsafe_directories_stop_the_helper_before_anything_is_written(self):
        os.chmod(CONFD, 0o775)
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 5, out)
        os.chmod(CONFD, 0o755)
        os.chown(CONFD, WEB, WEB)
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 5, out)
        os.chown(CONFD, 0, 0)
        os.chmod(STAGE, 0o777)
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 5, out)
        os.chmod(STAGE, 0o770)
        self.untouched()

    def test_the_maintenance_modes_work_when_started_through_sudo_by_any_user(self):
        """The installer is started with `sudo bash irongate-install.sh`, and by the updater that www-data starts through
        sudo: SUDO_UID is set to a non-root uid in both and --lockdown must still run (the sudoers rule is what keeps
        arguments away from the web tier)."""
        write(CONF, b'# user wrote this\n', WEB, WEB, 0o664)
        for uid in (str(WEB), '1000', '0'):
            proc = subprocess.run([HELPER, '--lockdown'], env={'PATH': '/usr/bin:/bin', 'SUDO_UID': uid, 'SUDO_USER': 'x'},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, (uid, proc.stdout, proc.stderr))
            proc = subprocess.run([HELPER, '--audit'], env={'PATH': '/usr/bin:/bin', 'SUDO_UID': uid},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, (uid, proc.stdout, proc.stderr))
        self.assertEqual(st(CONF), '0:0:644')

    def test_unknown_arguments_are_a_usage_error_and_change_nothing(self):
        for args in (['--bogus'], ['--lockdown', 'x'], ['x'], ['--audit', '--lockdown']):
            rc, resp, out, err = run_helper(args)
            self.assertEqual(rc, 2, (args, out, err))
        self.untouched()

    def test_runs_as_root_only(self):
        def drop():
            os.setgroups([])
            os.setgid(WEB)
            os.setuid(WEB)
        proc = subprocess.run([sys.executable, '-I', HELPER_SRC], preexec_fn=drop, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 5)


# ================================================================ lockdown and audit (installer and apply.sh call these)
class Lockdown(Base):
    def www_tree(self):
        """What the host looked like before: everything in the web tier's hands."""
        os.chown(CONFD, WEB, WEB)
        os.chmod(CONFD, 0o775)
        write(CONF, b'# user wrote this\ndhcp-range=192.168.1.5,192.168.1.50,12h\n', WEB, WEB, 0o664)
        write(RES, b'# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n', WEB, WEB, 0o775)
        write(CONFD + '/README', b'# readme\n', WEB, WEB, 0o775)

    def test_after_lockdown_www_data_can_write_nothing(self):
        self.www_tree()
        before_ino, before_mtime = os.stat(CONF).st_ino, os.stat(CONF).st_mtime_ns
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual((st(CONFD), st(CONF), st(RES), st(CONFD + '/README')), ('0:0:755', '0:0:644', '0:0:644', '0:0:644'))
        self.assertNotEqual(os.stat(CONF).st_ino, before_ino, 'the file must be re-created, not chown-ed in place')
        self.assertEqual(os.stat(CONF).st_mtime_ns, before_mtime, 'a re-created file keeps its modification time')
        self.assertEqual(read(CONF), b'# user wrote this\ndhcp-range=192.168.1.5,192.168.1.50,12h\n')
        code = ('import os,sys\n'
                'r=[]\n'
                'def t(label, fn):\n'
                '    try: fn(); r.append(label+": WRITABLE")\n'
                '    except OSError as e: r.append(label+": denied")\n'
                't("conf", lambda: open("%s","ab").close())\n'
                't("res", lambda: open("%s","ab").close())\n'
                't("create", lambda: open("%s/new.conf","wb").close())\n'
                't("rename", lambda: os.rename("%s","%s/gone"))\n'
                't("unlink", lambda: os.unlink("%s"))\n'
                't("symlink", lambda: os.symlink("/etc/shadow","%s/s.conf"))\n'
                't("chmod", lambda: os.chmod("%s",0o777))\n'
                'print("\\n".join(r))\n') % (CONF, RES, CONFD, RES, CONFD, RES, CONFD, CONF)
        proc = as_web(code)
        self.assertNotIn(b'WRITABLE', proc.stdout, proc.stdout)
        self.assertEqual(proc.stdout.count(b'denied'), 7, proc.stdout)

    def test_a_descriptor_the_web_tier_still_holds_is_useless_afterwards(self):
        self.www_tree()
        code = ('import sys\nf=open("%s","ab")\nprint("ready",flush=True)\nsys.stdin.readline()\n'
                'f.write(b"dhcp-script=/tmp/evil\\n")\nf.flush()\nprint("wrote",flush=True)\n') % CONF

        def drop():
            os.setgroups([])
            os.setgid(WEB)
            os.setuid(WEB)
        child = subprocess.Popen([sys.executable, '-I', '-c', code], preexec_fn=drop, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(child.stdout.readline().strip(), b'ready')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out)
        child.stdin.write(b'go\n')
        child.stdin.flush()
        child.stdout.readline()
        child.wait(timeout=10)
        self.assertNotIn(b'evil', read(CONF), 'a write through the old descriptor reached the live file')

    def test_operator_file_and_other_root_owned_files_are_left_exactly_as_they_are(self):
        self.www_tree()
        before = os.stat(OPERATOR)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0)
        after = os.stat(OPERATOR)
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_mode, before.st_uid), (after.st_ino, after.st_mtime_ns, after.st_mode, after.st_uid))
        self.assertIn('kept %s' % OPERATOR, out)

    def test_links_and_special_files_are_renamed_aside_not_followed_or_deleted(self):
        self.www_tree()
        write('/tmp/victim', b'root-only\n', 0, 0, 0o600)
        os.symlink('/tmp/victim', CONFD + '/evil.conf')
        os.symlink('/nonexistent/target', CONFD + '/dangling.conf')
        os.mkfifo(CONFD + '/pipe.conf')
        os.chown(CONFD + '/pipe.conf', WEB, WEB)
        os.mkdir(CONFD + '/sub')
        os.chown(CONFD + '/sub', WEB, WEB)
        write('/tmp/outside', b'# outside\n', WEB, WEB, 0o666)
        os.link('/tmp/outside', CONFD + '/linked.conf')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        names = sorted(os.listdir(CONFD))
        self.assertFalse([n for n in names if n in ('evil.conf', 'dangling.conf', 'pipe.conf')], names)
        refused = [n for n in names if n.startswith('.refused.')]
        self.assertEqual(len(refused), 4, names)
        self.assertEqual(st('/tmp/victim'), '0:0:600')
        self.assertTrue(any(os.path.islink(CONFD + '/' + n) for n in refused))
        self.assertNotIn('sub', names, 'a directory the web tier made is put aside like a link (the audit objects to non-files)')
        self.assertTrue(all(st(CONFD + '/' + n).startswith('0:0:') for n in refused), [(n, st(CONFD + '/' + n)) for n in refused])
        # the hard-linked file became a new root-owned file; the outside link still belongs to www-data and is the old inode
        self.assertEqual(st(CONFD + '/linked.conf'), '0:0:644')
        self.assertNotEqual(os.stat(CONFD + '/linked.conf').st_ino, os.stat('/tmp/outside').st_ino)
        self.assertEqual(read('/tmp/victim'), b'root-only\n')
        # a second run is quiet and changes nothing
        snapshot = sorted((n, os.lstat(CONFD + '/' + n).st_ino) for n in os.listdir(CONFD))
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(snapshot, sorted((n, os.lstat(CONFD + '/' + n).st_ino) for n in os.listdir(CONFD)))

    def test_a_symlinked_main_file_is_refused_not_moved(self):
        os.unlink(CONF)
        write('/tmp/real.conf', OLD_MAIN)
        os.symlink('/tmp/real.conf', CONF)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 5, out + err)
        self.assertTrue(os.path.islink(CONF))

    def test_audit_finds_planted_directives_and_prints_no_values(self):
        self.www_tree()
        write(CONFD + '/planted.conf', b'dhcp-script=/tmp/evil-secret-value\nconf-script=/tmp/x\n', WEB, WEB, 0o664)
        write(CONF, b'# fine\ninterface=eth0\ndhcp-script=/opt/irongate/dhcp-notify.sh\nconf-dir=/etc/dnsmasq.d/,*.conf\n'
                    b'dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases\nlog-facility=/var/log/dnsmasq.log\n'
                    b'dhcp-luascript=/tmp/lua-secret-value\n', WEB, WEB, 0o664)
        write(RES, b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\naddn-hosts=/tmp/h\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 1, out)
        self.assertIn('planted.conf:1: dhcp-script', out)
        self.assertIn('planted.conf:2: conf-script', out)
        self.assertIn('dnsmasq.conf:7: dhcp-luascript', out)
        self.assertIn('reservations.conf:2: addn-hosts', out)
        self.assertNotIn('secret-value', out + err)
        self.assertNotIn('dnsmasq.conf:3', out, 'the template\'s own dhcp-script line is expected')
        self.assertNotIn('operator-local', out, 'a clean root-owned operator file is scanned and quiet')

    def test_audit_is_quiet_on_a_genuine_rendering(self):
        run_helper_with(request())
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)
        self.assertIn('0 finding', out)


# ================================================================ the rendering is a template, whatever the input
class Fuzz(unittest.TestCase):
    def test_nothing_accepted_ever_renders_a_directive_of_the_attacker(self):
        mod = load_module()
        rng = random.Random(20261027)
        alphabet = ['a', 'b', '0', '1', '.', '-', '_', ':', ',', ' ', '\n', '\r', '\t', '=', '#', '/', 'h', 'd', 'c', 'p', '\x00', '\u00e9']
        words = ['dhcp-script', 'conf-file', 'conf-dir', 'dhcp-luascript', 'addn-hosts', 'user', '/tmp/x', '192.168.1.1', 'eth0', '24h', 'infinite']

        def junk():
            kind = rng.random()
            if kind < 0.4:
                return ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
            if kind < 0.7:
                return rng.choice(words) + rng.choice(['', '\n', ' ', '=', ',']) + rng.choice(words)
            return rng.choice(words)

        accepted = rejected = 0
        for _ in range(4000):
            s = {}
            for key in GOOD:
                s[key] = rng.choices([GOOD[key], junk(), ''], weights=[55, 15, 30])[0]
            res = [{'mac': rng.choice([GOOD_RES[0]['mac'], junk()]), 'ip': rng.choice(['10.0.0.1', junk()]),
                    'hostname': rng.choice(['ok', junk(), ''])} for _ in range(rng.randint(0, 3))]
            try:
                action, settings, reservations = mod.parse_request(json.dumps(request(settings=s, reservations=res)).encode())
            except mod.Reject:
                rejected += 1
                continue
            accepted += 1
            for text, allowed in ((mod.render_main(settings, default_interface=lambda: 'eth0'), mod.MAIN_NAMES),
                                  (mod.render_reservations(reservations), {'dhcp-host'})):
                for line in text.split('\n'):
                    body = line.strip()
                    if body == '' or body.startswith('#'):
                        continue
                    self.assertIn(re.split(r'[=\s]', body, 1)[0], allowed, line)
                self.assertNotIn('/tmp/x', text)
                self.assertNotIn('\r', text)
                self.assertNotIn('\x00', text)
            main = mod.render_main(settings, default_interface=lambda: 'eth0')
            self.assertEqual(main.count('\ndhcp-script=/opt/irongate/dhcp-notify.sh\n'), 1)
            lines = main.split('\n')
            self.assertEqual(sum(1 for l in lines if l.startswith('dhcp-script')), 1)
            self.assertEqual(sum(1 for l in lines if l.startswith('conf-dir')), 1)
        # controls: the generator produces both outcomes, so a pass is not "everything was rejected"
        self.assertGreater(accepted, 100)
        self.assertGreater(rejected, 1000)


# ================================================================ characterization against the old PHP generator (18e5177)
def normalise(text):
    return re.sub(r'(Auto-generated by Web UI on )\d{4}-\d\d-\d\d \d\d:\d\d:\d\d', r'\1<DATE>', text)


# The two differences from the old generator that are documented (README of the slice) and checked here instead of hidden:
#   x16  an empty cidr made the old generator write the netmask 0.0.0.0; the helper takes the dashboard's default, /24
#   x18-x20  white space around a value was written as it was (dnsmasq ignores it); the helper strips it
WHITESPACE_VECTORS = ('x18-ws-gateway', 'x19-ws-start', 'x20-domain-trailing-space')


def expected_main(name, legacy):
    legacy = normalise(legacy)
    if name == 'x16-empty-cidr':
        assert legacy.count(',0.0.0.0,') == 1
        return legacy.replace(',0.0.0.0,', ',255.255.255.0,')
    if name in WHITESPACE_VECTORS:
        return '\n'.join(re.sub(r'=[ \t]+', '=', l.rstrip()) for l in legacy.split('\n'))
    return legacy


class Characterization(Base):
    def vectors(self):
        names = sorted(glob.glob(os.path.join(CHAR_DIR, '*.request.json')))
        return [n[:-len('.request.json')] for n in names]

    def test_characterization_data_is_there(self):
        self.assertGreaterEqual(len(self.vectors()), 29, 'no characterization data in %s: run tests/test_dnsmasq_phpside.php first' % CHAR_DIR)

    def test_dnsmasq_itself_accepted_the_white_space_the_old_generator_wrote(self):
        """Why x18-x20 must not be refused: the real dnsmasq reads the old generator's output with the stray spaces in it."""
        for name in WHITESPACE_VECTORS:
            with self.subTest(vector=name):
                fresh_env()
                legacy = read(os.path.join(CHAR_DIR, name + '.legacy.conf'))
                self.assertRegex(legacy.decode(), r'(?m)(= \S|\S $)', 'the vector has no stray white space in the old output')
                write('/tmp/legacy-main.conf', legacy)
                proc = sh('dnsmasq --test --conf-file=/tmp/legacy-main.conf')
                self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_helper_output_equals_the_old_generators_for_every_vector(self):
        mod = load_module()
        for base in self.vectors():
            name = os.path.basename(base)
            with self.subTest(vector=name):
                raw = read(base + '.request.json')
                legacy_main = read(base + '.legacy.conf').decode()
                legacy_res = read(base + '.legacy.res').decode()
                action, settings, reservations = mod.parse_request(raw)
                self.assertEqual(normalise(mod.render_main(settings)), expected_main(name, legacy_main))
                self.assertEqual(mod.render_reservations(reservations), legacy_res)

    def test_end_to_end_the_staged_request_installs_the_old_generators_files(self):
        for base in self.vectors():
            name = os.path.basename(base)
            with self.subTest(vector=name):
                fresh_env()
                write('/tmp/legacy-main.conf', read(base + '.legacy.conf'))
                legacy_ok = sh('dnsmasq --test --conf-file=/tmp/legacy-main.conf').returncode == 0
                stage(read(base + '.request.json'))
                rc, resp, out, err = run_helper()
                if not legacy_ok:
                    # a rendering dnsmasq itself refuses (x06: a /32 network cannot hold a range) was refused by the old API's own
                    # `dnsmasq --test` as well: nothing is applied, the previous files stay
                    self.assertEqual((rc, resp['stage']), (3, 'validation'), '%s: %s %s' % (name, out, err))
                    self.assertEqual((read(CONF), read(RES)), (OLD_MAIN, OLD_RES))
                    continue
                self.assertEqual(rc, 0, '%s: %s %s' % (name, out, err))
                self.assertEqual(normalise(read(CONF).decode()), expected_main(name, read(base + '.legacy.conf').decode()))
                self.assertEqual(read(RES).decode(), read(base + '.legacy.res').decode())
                proc = sh('dnsmasq --test --conf-file=/etc/dnsmasq.conf')
                self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_the_timestamp_line_has_the_old_format(self):
        mod = load_module()
        action, settings, reservations = mod.parse_request(json.dumps(request()).encode())
        line = mod.render_main(settings).split('\n')[1]
        self.assertRegex(line, r'^# Auto-generated by Web UI on \d{4}-\d\d-\d\d \d\d:\d\d:\d\d$')



# ================================================================ the second review (round 5b): hostile content never survives the lockdown
PWN = '/tmp/pwn.sh'
MARKER = '/tmp/PWNED-uid'
QUARANTINE = '/var/lib/irongate/dnsmasq-quarantine'
SNAPSHOT = '/var/lib/irongate/dnsmasq-good'
MAIN_WITH_CONFDIR = (b'# written by the web UI\ninterface=eth0\nbind-dynamic\nport=0\n'
                     b'dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases\nlog-facility=/var/log/dnsmasq.log\n'
                     b'dhcp-script=/opt/irongate/dhcp-notify.sh\nconf-dir=/etc/dnsmasq.d/,*.conf\n')


def arm_marker():
    """A program that records that root ran it. Nothing in these tests may ever make that file appear."""
    write(PWN, '#!/bin/sh\nid -u > %s\n' % MARKER, 0, 0, 0o755)
    if os.path.exists(MARKER):
        os.unlink(MARKER)


def run_dnsmasq_as_root():
    """What the installer's tail and apply.sh run: dnsmasq --test on the live configuration, the way Debian starts it
    (conf-dir of the main file, plus the init script's -7 /etc/dnsmasq.d which reads every file whatever its name)."""
    return sh('dnsmasq --test --conf-file=/etc/dnsmasq.conf --conf-dir=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new')


def web_tree(main=MAIN_WITH_CONFDIR):
    """The tree as the installer's permission step leaves it: everything handed to www-data."""
    os.chown(CONFD, WEB, WEB)
    os.chmod(CONFD, 0o775)
    write(CONF, main, WEB, WEB, 0o664)
    write(RES, b'# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n', WEB, WEB, 0o775)
    write(CONFD + '/README', b'# readme\n', WEB, WEB, 0o775)
    write(OPERATOR, OPERATOR_TEXT, WEB, WEB, 0o775)


def quarantined_files():
    return sorted(os.listdir(QUARANTINE)) if os.path.isdir(QUARANTINE) else []


class HostileContent(Base):
    """F1 (a): the lockdown must never preserve hostile content. Every one of these ran as root in the installer's window
    between the permission step (www-data owns the tree) and the lockdown."""

    def setUp(self):
        Base.setUp(self)
        arm_marker()

    def test_a_conf_script_file_planted_in_the_window_is_quarantined_not_re_created(self):
        web_tree()
        write(CONFD + '/zz-evil.conf', b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o644)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.lexists(CONFD + '/zz-evil.conf'), 'the planted file is still in the directory dnsmasq reads')
        self.assertIn('QUARANTINED %s/zz-evil.conf (conf-script at line 1) -> %s/' % (CONFD, QUARANTINE), out)
        self.assertNotIn(PWN, out + err, 'the value of a planted directive is never printed')
        kept = quarantined_files()
        self.assertEqual(len(kept), 1, kept)
        self.assertEqual(read(os.path.join(QUARANTINE, kept[0])), b'conf-script=' + PWN.encode() + b'\n', 'a copy is kept for the operator')
        self.assertEqual(st(os.path.join(QUARANTINE, kept[0])), '0:0:600')
        self.assertEqual(st(QUARANTINE), '0:0:700')
        proc = run_dnsmasq_as_root()
        self.assertFalse(os.path.exists(MARKER), 'dnsmasq --test, run as root after the lockdown, executed the planted conf-script:\n' + proc.stdout.decode())
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)

    def test_control_the_planted_file_really_runs_as_root_when_it_stays(self):
        """Control for the test above: with the planted file in place, dnsmasq --test really does run it, so a green
        test above means the file is gone, not that the probe cannot see it."""
        web_tree()
        write(CONFD + '/zz-evil.conf', b'conf-script=' + PWN.encode() + b'\n', 0, 0, 0o644)
        run_dnsmasq_as_root()
        self.assertTrue(os.path.exists(MARKER), 'the probe does not detect a planted conf-script')
        self.assertEqual(read(MARKER).strip(), b'0')

    def test_files_of_every_name_are_scanned(self):
        """A Debian dnsmasq reads every file of the directory (init script: -7), dot files and ~ backups excepted; the lockdown
        looks at all of them and quarantines each one that holds a forbidden directive."""
        web_tree()
        names = ['zz.conf', 'plain', 'x.conf.bak', 'UPPER.CONF', '.hidden.conf', 'backup.conf~', '#auto#']
        for n in names:
            write(os.path.join(CONFD, n), b'dhcp-script=/tmp/x\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(sorted(os.listdir(CONFD)), sorted(['README', 'operator-local.conf', 'reservations.conf']))
        self.assertEqual(len(quarantined_files()), len(names))

    def test_a_directive_added_to_the_main_file_in_the_window_is_not_kept(self):
        web_tree(MAIN_WITH_CONFDIR + b'conf-script=' + PWN.encode() + b'\n')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn(b'conf-script', read(CONF))
        self.assertIn(b'# DHCP is disabled', read(CONF), 'without a snapshot the main file becomes the safe default')
        self.assertEqual(st(CONF), '0:0:644')
        self.assertIn('QUARANTINED /etc/dnsmasq.conf (conf-script at line 9)', out)
        self.assertEqual(len(quarantined_files()), 1)
        run_dnsmasq_as_root()
        self.assertFalse(os.path.exists(MARKER))

    def test_the_main_file_comes_back_from_the_root_held_snapshot(self):
        """A genuine apply keeps what it rendered in a root-only directory; a main file the web tier has changed is replaced by
        exactly that, not by whatever is on disk."""
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 0, out + err)
        good = read(CONF)
        self.assertEqual(st(SNAPSHOT), '0:0:700')
        self.assertEqual(st(SNAPSHOT + '/dnsmasq.conf'), '0:0:600')
        self.assertEqual(read(SNAPSHOT + '/dnsmasq.conf'), good)
        # the permission step hands the tree to www-data, then www-data edits the file (a different, but clean, range)
        os.chown(CONFD, WEB, WEB)
        os.chmod(CONFD, 0o775)
        write(CONF, good.replace(b'192.168.1.100,192.168.1.200', b'10.0.0.1,10.0.0.250') + b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(read(CONF), good)
        self.assertEqual(st(CONF), '0:0:644')
        self.assertIn('restored /etc/dnsmasq.conf from the root-held snapshot', out)
        self.assertEqual(len(quarantined_files()), 1)

    def test_the_first_lockdown_of_a_clean_tree_takes_the_snapshot_that_the_next_one_restores(self):
        """Not only an apply: the lockdown itself keeps what it found clean, so the second installer run already has a
        root-held reference when www-data edits the main file in the window."""
        web_tree()
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(read(SNAPSHOT + '/dnsmasq.conf'), MAIN_WITH_CONFDIR)
        self.assertEqual(read(SNAPSHOT + '/reservations.conf'), b'# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n')
        web_tree(MAIN_WITH_CONFDIR + b'conf-script=' + PWN.encode() + b'\n')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(read(CONF), MAIN_WITH_CONFDIR)
        self.assertIn('QUARANTINED /etc/dnsmasq.conf (conf-script at line 9)', out)
        self.assertIn('restored /etc/dnsmasq.conf from the root-held snapshot', out)

    def test_a_clean_but_different_main_file_is_replaced_by_the_snapshot_and_a_copy_is_kept(self):
        rc, resp, out, err = run_helper_with(request())
        good = read(CONF)
        os.chown(CONFD, WEB, WEB)
        write(CONF, good.replace(b'192.168.1.100,192.168.1.200', b'10.0.0.1,10.0.0.250'), WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(read(CONF), good)
        self.assertIn('REPLACED /etc/dnsmasq.conf (differs from the root-held snapshot)', out)
        self.assertNotIn('QUARANTINED /etc/dnsmasq.conf', out, 'a clean difference is not an alarm')

    def test_a_snapshot_the_web_tier_could_have_touched_is_not_believed(self):
        rc, resp, out, err = run_helper_with(request())
        good = read(CONF)
        os.chmod(SNAPSHOT, 0o755)  # readable by everybody: not private to root any more
        os.chown(CONFD, WEB, WEB)
        write(CONF, good + b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 5, out + err)  # refuses to use state directories that are not private
        os.chmod(SNAPSHOT, 0o700)
        write(SNAPSHOT + '/dnsmasq.conf', b'# tampered\nconf-script=/tmp/pwn.sh\n', 0, 0, 0o600)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn(b'conf-script', read(CONF), 'a snapshot that fails the checks of a rendering is ignored')

    def test_hostile_reservations_keep_only_their_valid_lines(self):
        web_tree()
        write(RES, b'# r\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\ndhcp-script=/tmp/pwn.sh\n'
                   b'dhcp-host=aa:bb:cc:dd:ee:02,192.168.1.11\ndhcp-host=bogus\n', WEB, WEB, 0o775)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(read(RES), b'# Static DHCP Reservations - Auto-generated by Web UI\n'
                                    b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\ndhcp-host=aa:bb:cc:dd:ee:02,192.168.1.11\n')
        self.assertIn('QUARANTINED /etc/dnsmasq.d/reservations.conf (dhcp-script at line 3)', out)
        run_dnsmasq_as_root()
        self.assertFalse(os.path.exists(MARKER))

    def test_a_second_or_different_dhcp_script_line_in_the_main_file_is_not_kept(self):
        """The fixed dhcp-script line is allowed once and only as it is; the same name with another value is not."""
        for extra in (b'dhcp-script=/tmp/pwn.sh\n', b'dhcp-script=/opt/irongate/dhcp-notify.sh.evil\n', b'conf-dir=/tmp/evil,*.conf\n', b'log-facility=/etc/cron.d/x\n'):
            with self.subTest(extra=extra):
                fresh_env()
                arm_marker()
                web_tree(MAIN_WITH_CONFDIR + extra)
                rc, resp, out, err = run_helper(['--lockdown'])
                self.assertEqual(rc, 0, out + err)
                self.assertNotIn(extra.split(b'=')[0] + b'=/tmp', read(CONF) + b'.')
                self.assertIn('QUARANTINED /etc/dnsmasq.conf', out)
        fresh_env()
        web_tree(MAIN_WITH_CONFDIR.replace(b'dhcp-script=/opt/irongate/dhcp-notify.sh', b'dhcp-script=/tmp/pwn.sh'))
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertNotIn(b'/tmp/pwn.sh', read(CONF), 'the fixed line replaced by another value must not survive')

    def test_the_scan_is_wider_than_dnsmasq_never_narrower(self):
        """Upper case, underscores and leading dashes are not read by dnsmasq as options, but a file that spells a forbidden name so is
        refused anyway (what is recognised can only be widened)."""
        for spelling in (b'CONF-FILE=/x', b'Conf_File=/x', b'--conf-file=/x', b'conf_script=/x', b'DHCP_SCRIPT=/x', b'-dhcp-script=/x'):
            with self.subTest(spelling=spelling):
                fresh_env()
                write(CONFD + '/spelled.conf', spelling + b'\n', 0, 0, 0o644)
                rc, resp, out, err = run_helper(['--audit'])
                self.assertEqual(rc, 1, out)
                self.assertIn('spelled.conf:1:', out)

    def test_syntax_that_cannot_be_checked_is_not_kept_even_without_a_forbidden_name(self):
        """The plain-syntax rule on its own: quotes, a backslash, a CR, a byte above 0x7e, an over-long line, a stray word."""
        web_tree()
        odd = {'quote.conf': b'address="/a.example/1.2.3.4"\n', 'backslash.conf': b'domain=a\\b\n', 'cr.conf': b'port=0\r\n',
               'high.conf': b'# caf\xc3\xa9\n', 'long.conf': b'# ' + b'x' * 1100 + b'\n', 'word.conf': b'this is not a configuration line\n',
               'nul.conf': b'port=0\x00\n'}
        for name, data in odd.items():
            write(CONFD + '/' + name, data, WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(sorted(n for n in os.listdir(CONFD) if n in odd), [], out)
        for name in odd:
            self.assertIn('QUARANTINED /etc/dnsmasq.d/%s (' % name, out)

    def test_a_root_owned_file_the_group_can_write_is_not_trusted(self):
        web_tree()
        write(CONFD + '/shared.conf', b'conf-script=/tmp/pwn.sh\n', 0, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.lexists(CONFD + '/shared.conf'))
        self.assertIn('QUARANTINED /etc/dnsmasq.d/shared.conf (conf-script at line 1)', out)

    def test_a_clean_web_tree_is_re_created_unchanged(self):
        """Control: nothing is quarantined, replaced or rewritten when there is nothing wrong (same bytes, same mtime)."""
        web_tree()
        before = {n: (read(os.path.join(CONFD, n)), os.stat(os.path.join(CONFD, n)).st_mtime_ns) for n in os.listdir(CONFD)}
        main_before = (read(CONF), os.stat(CONF).st_mtime_ns)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn('QUARANTINED', out)
        self.assertNotIn('REPLACED', out)
        for n, (data, mtime) in before.items():
            self.assertEqual((read(os.path.join(CONFD, n)), os.stat(os.path.join(CONFD, n)).st_mtime_ns), (data, mtime), n)
        self.assertEqual((read(CONF), os.stat(CONF).st_mtime_ns), main_before)
        self.assertEqual(quarantined_files(), [])
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)

    def test_a_second_lockdown_changes_nothing_and_does_not_grow_the_quarantine(self):
        web_tree()
        write(CONFD + '/zz-evil.conf', b'conf-script=/tmp/x\n', WEB, WEB, 0o644)
        os.symlink('/tmp/victim', CONFD + '/evil2.conf')
        run_helper(['--lockdown'])
        first = (quarantined_files(), sorted(os.listdir(CONFD)))
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual((quarantined_files(), sorted(os.listdir(CONFD))), first)
        self.assertNotIn('QUARANTINED', out)

    def test_the_quarantine_cannot_be_read_by_the_web_tier(self):
        web_tree()
        write(CONFD + '/zz-evil.conf', b'conf-script=/tmp/x\n', WEB, WEB, 0o644)
        run_helper(['--lockdown'])
        proc = as_web('import os\ntry:\n    print(os.listdir("%s"))\nexcept OSError as e:\n    print("denied", e.errno)\n' % QUARANTINE)
        self.assertIn(b'denied', proc.stdout, proc.stdout)

    def test_oversized_files_are_not_kept(self):
        web_tree()
        write(CONFD + '/big.conf', b'# ' + b'x' * (8 * 1024 * 1024 + 10) + b'\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.lexists(CONFD + '/big.conf'))
        self.assertIn('QUARANTINED /etc/dnsmasq.d/big.conf (larger than', out)


# the spellings that make dnsmasq read a directive that a plain "split the line at =" scan does not see; the first test of
# the class below asks the real dnsmasq in the container, so every row is a genuine bypass, not a guess
EVASIONS = [
    ('plain', b'conf-file=/nonexistent-EV\n'),
    ('quotes inside the name', b'conf"-"file=/nonexistent-EV\n'),
    ('1023-character comment, directive in the next read chunk', b'#' + b'A' * 1023 + b'conf-file=/nonexistent-EV\n'),
    ('blank-padded line, directive in the next read chunk', b' ' * 1024 + b'conf-file=/nonexistent-EV\n'),
    ('CR line end', b'conf-file=/nonexistent-EV\r\n'),
    ('vertical tab before the name', b'\x0bconf-file=/nonexistent-EV\n'),
    ('white space around the equals sign', b'conf-file \t=\t /nonexistent-EV\n'),
    ('text after a NUL', b'conf-file=/nonexistent-EV\x00 junk\n'),
    ('no final newline', b'conf-file=/nonexistent-EV'),
    ('trailing comment', b'conf-file=/nonexistent-EV # not a comment for the name\n'),
]


class Evasions(Base):
    """F1 (b): the scan sees what dnsmasq's own parser sees. Each row is first proved to be read by the real dnsmasq
    (control), then the audit must name it in a root-owned file and the lockdown must quarantine it in a web-owned one."""

    def real_dnsmasq_reads(self, data):
        write('/tmp/evasion.conf', data, 0, 0, 0o644)
        proc = sh('dnsmasq --test --conf-file=/tmp/evasion.conf')
        return b'nonexistent-EV' in proc.stdout

    def test_every_spelling_is_read_by_the_real_dnsmasq(self):
        for label, data in EVASIONS:
            with self.subTest(label=label):
                self.assertTrue(self.real_dnsmasq_reads(data), 'dnsmasq does not read this spelling, the table is wrong: %s' % label)

    def test_the_audit_names_each_one_in_a_root_owned_file(self):
        for label, data in EVASIONS:
            with self.subTest(label=label):
                fresh_env()
                write(CONFD + '/evasion.conf', data, 0, 0, 0o644)
                rc, resp, out, err = run_helper(['--audit'])
                self.assertEqual(rc, 1, '%s: %s' % (label, out))
                self.assertIn('FINDING /etc/dnsmasq.d/evasion.conf:', out)
                self.assertIn('conf-file', out)
                self.assertNotIn('nonexistent-EV', out + err)

    def test_the_lockdown_quarantines_each_one_in_a_web_owned_file(self):
        for label, data in EVASIONS:
            with self.subTest(label=label):
                fresh_env()
                os.chown(CONFD, WEB, WEB)
                write(CONFD + '/evasion.conf', data, WEB, WEB, 0o664)
                rc, resp, out, err = run_helper(['--lockdown'])
                self.assertEqual(rc, 0, '%s: %s' % (label, out + err))
                self.assertFalse(os.path.exists(CONFD + '/evasion.conf'), label)
                self.assertIn('QUARANTINED /etc/dnsmasq.d/evasion.conf', out)

    def test_a_scanner_that_only_looks_at_the_start_of_a_line_misses_them(self):
        """Control for the table: a naive scan (what a line-by-line `split on =` does) misses most of these, so the rows are
        not trivial."""
        naive = lambda data: any(l.startswith('conf-file=') for l in data.decode('latin-1').split('\n'))
        missed = [label for label, data in EVASIONS if not naive(data)]
        self.assertGreaterEqual(len(missed), 5, missed)

    def test_the_scan_agrees_with_the_real_dnsmasq_on_random_spellings(self):
        """Differential fuzz (fixed seed): whenever the real dnsmasq reads a mutated spelling of conf-file, the scan must flag it."""
        mod = load_module()
        rng = random.Random(20261028)
        ws = [' ', '\t', '\r', '\x0b', '\x0c', '\xa0']
        recognised = missed = 0
        for _ in range(400):
            name = 'conf-file'
            for _ in range(rng.randint(0, 3)):
                k = rng.random()
                i = rng.randint(0, len(name))
                if k < 0.3:
                    name = name[:i] + '"' + name[i:]
                elif k < 0.45:
                    name = name.upper()
                elif k < 0.6:
                    name = name.replace('-', '_')
                elif k < 0.7:
                    name = '--' + name
                elif k < 0.85:
                    name = name[:i] + rng.choice(ws) + name[i:]
                else:
                    name = name + '"'
            line = ''.join(rng.choice(ws) for _ in range(rng.choice([0, 0, 1]))) + name + rng.choice(['=', ' =', '= ', '\t=', ' ']) + '/nonexistent-EV'
            if rng.random() < 0.4:
                pad = rng.choice([1020, 1022, 1023, 1024, 1025])
                data = ('#' + 'A' * (pad - 1) + line + '\n') if rng.random() < 0.7 else (' ' * pad + line + '\n')
            else:
                data = line + rng.choice(['\n', '\r\n', '', '\x00x\n'])
            data = data.encode('latin-1')
            if self.real_dnsmasq_reads(data):
                recognised += 1
                if not mod.scan_config(data, 'other', strict=False) or not mod.scan_config(data, 'other', strict=True):
                    missed += 1
        self.assertGreater(recognised, 30, 'the generator produced too few spellings dnsmasq reads to mean anything')
        self.assertEqual(missed, 0)


class AuditCoversEverything(Base):
    """F1 (b): the audit scans every file, root-owned ones included, and the ownership of everything dnsmasq reads."""

    def test_a_root_owned_planted_file_is_a_finding(self):
        write(CONFD + '/zz-evil.conf', b'conf-script=/tmp/pwn.sh\n', 0, 0, 0o644)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 1, out)
        self.assertIn('FINDING /etc/dnsmasq.d/zz-evil.conf:1: conf-script', out)
        self.assertNotIn('/tmp/pwn.sh', out)

    def test_reservations_conf_holds_nothing_but_dhcp_host(self):
        """Not a forbidden name, but not a reservation either: a DHCP option (a rogue router, say) in the file the dashboard owns."""
        write(RES, b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\ndhcp-option=option:router,6.6.6.6\n', 0, 0, 0o644)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 1, out)
        self.assertIn('FINDING /etc/dnsmasq.d/reservations.conf:2: not-dhcp-host', out)
        self.assertNotIn('6.6.6.6', out)
        os.chown(RES, WEB, WEB)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertIn('QUARANTINED /etc/dnsmasq.d/reservations.conf (not-dhcp-host at line 2)', out)
        self.assertEqual(read(RES), b'# Static DHCP Reservations - Auto-generated by Web UI\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\n')

    def test_a_clean_operator_file_is_quiet_and_a_bad_one_is_not(self):
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual((rc, out.strip().splitlines()[-1]), (0, 'audit: 0 finding(s)'), out)
        write(OPERATOR, OPERATOR_TEXT + b'log-facility=/etc/cron.d/x\n', 0, 0, 0o644)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 1, out)
        self.assertIn('FINDING /etc/dnsmasq.d/operator-local.conf:3: log-facility', out)

    def test_every_forbidden_directive_is_a_finding_in_any_file(self):
        for name in ALL_FORBIDDEN:
            with self.subTest(directive=name):
                write(OPERATOR, ('%s=x\n' % name).encode(), 0, 0, 0o644)
                rc, resp, out, err = run_helper(['--audit'])
                self.assertEqual(rc, 1, out)
                self.assertIn('operator-local.conf:1: %s' % name, out)

    def test_ownership_and_modes_are_findings(self):
        os.chown(RES, WEB, WEB)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertIn('FINDING /etc/dnsmasq.d/reservations.conf:0: not-root-only', out)
        os.chown(RES, 0, 0)
        os.chmod(OPERATOR, 0o664)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertIn('FINDING /etc/dnsmasq.d/operator-local.conf:0: not-root-only', out)
        os.chmod(OPERATOR, 0o644)
        os.chmod(CONFD, 0o775)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertIn('FINDING /etc/dnsmasq.d:0: directory-not-root-only', out)
        os.chmod(CONFD, 0o755)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)

    def test_links_and_directories_are_findings_unless_the_lockdown_put_them_aside(self):
        os.symlink('/tmp/victim', CONFD + '/evil.conf')
        os.mkdir(CONFD + '/sub')
        rc, resp, out, err = run_helper(['--audit'])
        self.assertIn('evil.conf:0: symlink', out)
        self.assertIn('sub:0: not-a-regular-file', out)
        os.unlink(CONFD + '/evil.conf')
        os.rmdir(CONFD + '/sub')
        os.symlink('/tmp/victim', CONFD + '/.refused.1.2.evil.conf')
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, 'a root-owned .refused.* link is what the lockdown leaves behind: ' + out)

    def test_the_programs_root_runs_must_not_be_writable_by_others(self):
        write('/opt/irongate/dhcp-notify.sh', '#!/bin/sh\nexit 0\n', 0, 0, 0o755)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)
        os.chown('/opt/irongate/dhcp-notify.sh', WEB, WEB)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertIn('FINDING /opt/irongate/dhcp-notify.sh:0: exec-path-not-root-only', out)
        os.chown('/opt/irongate/dhcp-notify.sh', 0, 0)
        os.chmod('/opt/irongate', 0o775)
        rc, resp, out, err = run_helper(['--audit'])
        os.chmod('/opt/irongate', 0o755)
        self.assertIn('FINDING /opt/irongate:0: exec-path-not-root-only', out)

    def test_the_helper_will_not_run_dnsmasq_on_a_tree_the_audit_objects_to(self):
        """apply() and validate run `dnsmasq --test`, which executes conf-script: never on a dirty tree (exit 5)."""
        arm_marker()
        write(CONF, MAIN_WITH_CONFDIR, 0, 0, 0o644)
        write(CONFD + '/zz-evil.conf', b'conf-script=' + PWN.encode() + b'\n', 0, 0, 0o644)
        for action in ('apply', 'validate'):
            with self.subTest(action=action):
                rc, resp, out, err = run_helper_with(request(action=action))
                self.assertEqual(rc, 5, out + err)
                self.assertFalse(resp['success'])
                self.assertIn('not clean', resp['error'])
                self.assertFalse(os.path.exists(MARKER), 'the helper ran dnsmasq on a tree with a planted conf-script')
        self.assertEqual(systemctl_log(), [])


class StrayWhiteSpace(Base):
    """F5: dnsmasq ignored white space around a value, the old generator wrote it as it was; the helper strips it."""

    def parse(self, **fields):
        mod = load_module()
        return mod.parse_request(json.dumps(request(settings=dict(GOOD, **fields))).encode())

    def test_gateway_range_start_and_domain_with_stray_spaces_are_accepted_and_stripped(self):
        for field, value, want in (('gateway', '192.168.1.1 ', '192.168.1.1'), ('range_start', ' 192.168.1.100', '192.168.1.100'),
                                   ('domain', 'local ', 'local'), ('dns_primary', '  8.8.8.8  ', '8.8.8.8'), ('interface', ' eth0', 'eth0'),
                                   ('lease_time', ' 24h ', '24h'), ('cidr', ' 24 ', 24)):
            with self.subTest(field=field):
                action, settings, reservations = self.parse(**{field: value})
                self.assertEqual(settings[field], want)

    def test_end_to_end_the_stripped_value_is_what_dnsmasq_gets(self):
        rc, resp, out, err = run_helper_with(request(settings=dict(GOOD, gateway='192.168.1.1 ', range_start=' 192.168.1.100', domain='local ')))
        self.assertEqual(rc, 0, out + err)
        main = read(CONF).decode()
        self.assertIn('dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h\n', main)
        self.assertIn('dhcp-option=option:router,192.168.1.1\n', main)
        self.assertIn('domain=local\n', main)
        proc = sh('dnsmasq --test --conf-file=/etc/dnsmasq.conf')
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_reservation_fields_are_stripped_too(self):
        mod = load_module()
        action, s, r = mod.parse_request(json.dumps(request(reservations=[{'mac': ' aa:bb:cc:dd:ee:01 ', 'ip': '192.168.1.10 ', 'hostname': ' printer '}])).encode())
        self.assertEqual(r, [('aa:bb:cc:dd:ee:01', '192.168.1.10', 'printer')])

    def test_white_space_inside_a_value_and_other_control_characters_are_still_refused(self):
        mod = load_module()
        for field, value in (('gateway', '192.168.1. 1'), ('domain', 'lo cal'), ('domain', 'local\t'), ('gateway', '192.168.1.1\n'), ('range_start', '\t192.168.1.100')):
            with self.subTest(field=field, value=value):
                self.assertRaises(mod.Reject, mod.parse_request, json.dumps(request(settings=dict(GOOD, **{field: value}))).encode())

    def test_every_refusal_names_the_field_and_never_the_value(self):
        mod = load_module()
        cases = [dict(GOOD, gateway='999.1.1.1'), dict(GOOD, range_start='x'), dict(GOOD, range_end='1.2.3'), dict(GOOD, dns_primary='1.2.3.4.5'),
                 dict(GOOD, dns_secondary='::1'), dict(GOOD, cidr='99'), dict(GOOD, lease_time='forever'), dict(GOOD, domain='a b'),
                 dict(GOOD, interface='-x'), dict(GOOD, dhcp_enabled='yes'), dict(GOOD, domain='tab\there'), dict(GOOD, gateway='a\u00e9')]
        wanted = ['gateway', 'range_start', 'range_end', 'dns_primary', 'dns_secondary', 'cidr', 'lease_time', 'domain', 'interface', 'dhcp_enabled', 'settings.domain', 'settings.gateway']
        for settings, want in zip(cases, wanted):
            with self.subTest(field=want):
                with self.assertRaises(mod.Reject) as ctx:
                    mod.parse_request(json.dumps(request(settings=settings)).encode())
                self.assertIn(want, str(ctx.exception))
        bad_res = [dict(GOOD_RES[0], mac='zz'), dict(GOOD_RES[0], ip='300.1.1.1'), dict(GOOD_RES[0], hostname='-x')]
        for item, want in zip(bad_res, ('reservation 2 mac', 'reservation 2 ip', 'reservation 2 hostname')):
            with self.subTest(field=want):
                with self.assertRaises(mod.Reject) as ctx:
                    mod.parse_request(json.dumps(request(reservations=[GOOD_RES[0], item])).encode())
                self.assertIn(want, str(ctx.exception))
        with self.assertRaises(mod.Reject) as ctx:
            mod.parse_request(json.dumps(request(reservations=[GOOD_RES[0], dict(GOOD_RES[0], hostname='a\tb')])).encode())
        self.assertIn('reservations[2].hostname', str(ctx.exception))

    def test_a_key_the_dashboard_never_sends_is_not_echoed_in_the_path(self):
        mod = load_module()
        with self.assertRaises(mod.Reject) as ctx:
            mod.parse_request(json.dumps(request(settings={'evil key': 'v\tx'})).encode())
        self.assertNotIn('evil', str(ctx.exception))


class LockdownLock(Base):
    """The lockdown and a request write the same two files: they take the same lock, so neither can lose the other's work."""

    def test_the_lockdown_waits_for_a_request_that_is_being_applied(self):
        import fcntl
        import time
        fd = os.open('/run/irongate-dnsmasq-apply.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            proc = subprocess.Popen([HELPER, '--lockdown'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            time.sleep(1.0)
            self.assertIsNone(proc.poll(), 'the lockdown ran while a request held the lock')
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, out + err)


class HelperHygiene(Base):
    """F10."""

    def test_an_interface_may_not_start_with_a_dash_or_a_dot(self):
        mod = load_module()
        for bad in ('-eth0', '.eth0', '--x', '-', '.'):
            with self.subTest(interface=bad):
                self.assertRaises(mod.Reject, mod.parse_request, json.dumps(request(settings=dict(GOOD, interface=bad))).encode())
        for good in ('eth0', '_x', '0a', 'wlan0.100', 'br-lan', 'a' * 15):
            mod.parse_request(json.dumps(request(settings=dict(GOOD, interface=good))).encode())
        self.assertIsNone(mod._IFACE_RE.fullmatch('a' * 16))

    def test_forbidden_names_are_the_real_dnsmasq_options(self):
        """Against the binary's own option table (names it accepts in a configuration file), not against `dnsmasq --help`, which leaves
        out aliases such as dhcp-lease."""
        mod = load_module()
        self.assertIn('dhcp-scriptuser', mod.FORBIDDEN)
        self.assertIn('dnssec-timestamp', mod.FORBIDDEN)
        self.assertNotIn('script-user', mod.FORBIDDEN, 'there is no such dnsmasq option')
        names = set(n for n, has_arg, val in dnsmasq_option_table())
        self.assertGreater(len(names), 150)
        self.assertEqual(sorted(n for n in mod.FORBIDDEN if n not in names), [], 'every forbidden name is an option of the installed dnsmasq')
        help_options = set(re.findall(r'--([A-Za-z0-9-]+)', sh('dnsmasq --help').stdout.decode()))
        self.assertTrue(help_options <= names, 'the table is a superset of what --help lists: %s' % sorted(help_options - names))
        self.assertIn('dhcp-lease', names - help_options, 'control: the alias is in the binary and not in --help, which is why --help is no reference')

    def test_re_split_gets_maxsplit_as_a_keyword(self):
        """Python 3.13 deprecates the positional form (`re.split(p, s, 1)`)."""
        import ast
        tree = ast.parse(read(HELPER_SRC).decode())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ('split', 'sub', 'subn')
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 're']
        self.assertTrue(calls)
        for call in calls:
            self.assertLessEqual(len(call.args), 2 if call.func.attr == 'split' else 3, ast.dump(call)[:100])

    def test_a_directory_named_request_json_is_cleared_and_the_next_request_works(self):
        os.mkdir(os.path.join(STAGE, 'request.json'))
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        self.assertIn('directory', resp['error'])
        self.assertFalse(os.path.lexists(os.path.join(STAGE, 'request.json')))
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual((rc, resp['success']), (0, True), out + err)

    def test_a_directory_with_content_is_put_aside_not_left_stuck(self):
        d = os.path.join(STAGE, 'request.json')
        os.mkdir(d)
        write(d + '/x', b'junk')
        rc, resp, out, err = run_helper()
        self.assertEqual(rc, 2, out)
        self.assertFalse(os.path.lexists(d), 'api.php renames its file over this name: a directory there blocks every request')
        self.assertTrue([n for n in os.listdir(STAGE) if n.startswith('.refused.')])
        rc, resp, out, err = run_helper_with(request())
        self.assertEqual(rc, 0, out + err)


# ================================================================ option aliases, an allowlist, a lockdown that nothing can stop half way
ALIAS_VICTIM = '/tmp/alias-victim'
# the options that took a path when every name of dnsmasq's table was given one and dnsmasq was started for real, as root (a universe probe)
PATH_CONSUMERS = ['user', 'group', 'dhcp-leasefile', 'dhcp-lease', 'pid-file', 'conf-file', 'conf-script', 'conf-dir', 'log-facility',
                  'dhcp-hostsfile', 'dhcp-optsfile', 'dhcp-hostsdir', 'dhcp-optsdir', 'dumpfile']
LONG_NAME = 'a' * 250 + '.conf'  # 255 characters: NAME_MAX


def start_dnsmasq_as_root(seconds=1.5):
    """What `systemctl start dnsmasq` does, in the container: a root dnsmasq in the foreground reads a main file and every file of
    /etc/dnsmasq.d and opens the files they name; it is stopped after a moment. Returns 'running' or what it said when it exited."""
    os.makedirs('/var/lib/misc', exist_ok=True)  # where dnsmasq keeps its leases unless a file names another place (it refuses to be told twice)
    write('/tmp/start-main.conf', 'port=0\ninterface=lo\nbind-interfaces\ndhcp-range=127.0.0.50,127.0.0.60,255.255.255.0,1h\nno-ping\n'
          'conf-dir=/etc/dnsmasq.d/,*.conf\n', 0, 0, 0o644)
    try:
        proc = subprocess.run(['dnsmasq', '-k', '-C', '/tmp/start-main.conf', '--user=root', '--group=root', '--log-facility=-', '-x', '/tmp/start-dnsmasq.pid'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=seconds)
        return 'exited %d: %s' % (proc.returncode, proc.stdout.decode('latin-1')[:300])
    except subprocess.TimeoutExpired:
        return 'running'


def clear_victim():
    for path in (ALIAS_VICTIM, '/var/lib/misc/dnsmasq.leases'):
        if os.path.lexists(path):
            os.unlink(path)


class OptionTable(Base):
    """N1 (HIGH): `dhcp-lease` is an alias of `dhcp-leasefile` that dnsmasq accepts, `dnsmasq --help` does not list and the scanner did not
    know: a root dnsmasq creates and rewrites the file it names. The forbidden set is now derived from dnsmasq's own option table by option
    VALUE, so every alias of a forbidden option is in it. The table in the helper is checked against the binary (names and values) and against
    the strings of the binary."""

    def setUp(self):
        Base.setUp(self)
        self.mod = load_module()
        self.table = dnsmasq_option_table()
        clear_victim()

    def test_the_table_in_the_helper_is_the_table_of_the_dnsmasq_binary(self):
        names = [n for n, has_arg, val in self.table]
        self.assertEqual(len(names), len(set(names)), 'duplicate names in the binary')
        self.assertGreater(len(names), 150)
        self.assertEqual(dict((n, val) for n, has_arg, val in self.table), self.mod.OPTION_VALUES)

    def test_every_name_in_the_helpers_table_is_a_string_of_the_binary(self):
        blob = read('/host-dnsmasq')
        self.assertEqual(sorted(n for n in self.mod.OPTION_VALUES if n.encode() + b'\x00' not in blob), [])
        self.assertEqual(sorted(n for n in ('dhcp-lease', 'dhcp-leasefile', 'conf-script', 'domain-suffix') if n not in self.mod.OPTION_VALUES), [])

    def test_every_alias_of_a_forbidden_option_is_forbidden(self):
        base = [n for n in ALL_FORBIDDEN if n != 'dhcp-lease']  # what the brief and the first reviews named, without the alias this one found
        by_value = {}
        for name, has_arg, val in self.table:
            by_value.setdefault(val, []).append(name)
        grouped = [names for names in by_value.values() if any(n in base for n in names)]
        self.assertTrue([names for names in grouped if len(names) > 1], 'control: the table has aliases of forbidden options')
        for names in grouped:
            for name in names:
                with self.subTest(name=name, aliases=names):
                    self.assertIn(name, self.mod.FORBIDDEN)
        self.assertEqual(sorted(n for n in self.mod.FORBIDDEN if n not in base), ['dhcp-lease'], 'derived by value: exactly the alias, nothing else')
        self.assertNotIn('domain-suffix', self.mod.FORBIDDEN, 'an alias of an option that is not forbidden stays allowed (it is plain `domain`)')
        self.assertEqual(self.mod.OPTION_VALUES['domain-suffix'], self.mod.OPTION_VALUES['domain'])

    def test_the_scanner_flags_every_option_that_took_a_path_in_the_universe_probe(self):
        for name in PATH_CONSUMERS:
            data = ('%s=/tmp/probe/%s\n' % (name, name)).encode()
            with self.subTest(name=name):
                self.assertTrue(self.mod.scan_config(data, 'other', strict=False), 'the audit misses it')
                self.assertTrue(self.mod.scan_config(data, 'other', strict=True), 'the lockdown misses it')
                self.assertTrue(self.mod.scan_config(data, 'main', strict=True))
                self.assertTrue(self.mod.scan_config(data, 'res', strict=False))
        self.assertTrue(set(PATH_CONSUMERS) <= self.mod.FORBIDDEN)

    def test_as_a_request_key_the_alias_is_refused_as_a_forbidden_directive(self):
        for key in ('dhcp-lease', 'DHCP_LEASE', ' dhcp-lease', '--dhcp-lease'):
            with self.subTest(key=key):
                with self.assertRaises(self.mod.Reject) as ctx:
                    self.mod._check_key(key, self.mod.SETTING_KEYS, 'setting')
                self.assertIn('forbidden directive', str(ctx.exception))

    def test_control_the_real_dnsmasq_opens_the_file_the_alias_names_just_like_the_primary_name(self):
        """Without this the tests below would prove nothing: it is not a theory, a root dnsmasq really creates the file."""
        for name in ('dhcp-leasefile', 'dhcp-lease'):
            with self.subTest(name=name):
                fresh_env()
                clear_victim()
                write(CONFD + '/zz-path.conf', ('%s=%s\n' % (name, ALIAS_VICTIM)).encode(), 0, 0, 0o644)
                state = start_dnsmasq_as_root()
                self.assertTrue(os.path.exists(ALIAS_VICTIM), 'a root dnsmasq did not create the file named by %s (%s)' % (name, state))


class OptionAliases(Base):
    """N1 end to end: the alias in every kind of file the web tier could have written, in the audit, and with a real root dnsmasq."""

    def setUp(self):
        Base.setUp(self)
        arm_marker()
        clear_victim()

    def test_the_audit_names_the_alias_in_a_root_owned_file(self):
        write(OPERATOR, OPERATOR_TEXT + ('dhcp-lease=%s\n' % ALIAS_VICTIM).encode(), 0, 0, 0o644)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 1, out)
        self.assertIn('FINDING /etc/dnsmasq.d/operator-local.conf:3: dhcp-lease', out)
        self.assertNotIn(ALIAS_VICTIM, out + err, 'the value is never printed')

    def test_the_lockdown_quarantines_the_alias_in_every_file_and_a_root_dnsmasq_then_creates_nothing(self):
        web_tree(MAIN_WITH_CONFDIR + ('dhcp-lease=%s\n' % ALIAS_VICTIM).encode())
        write(CONFD + '/zz-alias.conf', ('dhcp-lease=%s\n' % ALIAS_VICTIM).encode(), WEB, WEB, 0o664)
        write(RES, b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\ndhcp-lease=' + ALIAS_VICTIM.encode() + b'\n', WEB, WEB, 0o775)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertIn('QUARANTINED /etc/dnsmasq.d/zz-alias.conf (dhcp-lease at line 1)', out)
        self.assertIn('QUARANTINED /etc/dnsmasq.conf (dhcp-lease at line 9)', out)
        self.assertIn('QUARANTINED /etc/dnsmasq.d/reservations.conf (dhcp-lease at line 2)', out)
        self.assertNotIn(ALIAS_VICTIM, out + err)
        for path in (CONF, RES, CONFD + '/zz-alias.conf'):
            self.assertNotIn(b'dhcp-lease=', read(path) if os.path.exists(path) else b'', path)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)
        state = start_dnsmasq_as_root()
        self.assertFalse(os.path.exists(ALIAS_VICTIM), 'a root dnsmasq, started on the tree the lockdown left, created the file the alias named (%s)' % state)

    def test_control_the_same_alias_in_a_root_owned_file_the_lockdown_keeps_is_what_creates_the_file(self):
        write(CONFD + '/zz-alias.conf', ('dhcp-lease=%s\n' % ALIAS_VICTIM).encode(), 0, 0, 0o644)
        start_dnsmasq_as_root()
        self.assertTrue(os.path.exists(ALIAS_VICTIM), 'the probe does not see the alias')

    def test_the_alias_is_flagged_in_every_spelling_the_scan_knows(self):
        """The alias goes through the same normalisation as every other name (quotes inside, case, underscores, leading dashes, white space)."""
        mod = load_module()
        for spelling in (b'DHCP_LEASE=/x', b'--dhcp-lease=/x', b'dhcp"-"lease=/x', b' dhcp-lease = /x', b'Dhcp_Lease /x', b'dhcp-lease'):
            with self.subTest(spelling=spelling):
                self.assertEqual([what for number, what in mod.scan_config(spelling + b'\n', 'other', strict=False)], ['dhcp-lease'])
                self.assertEqual([what for number, what in mod.scan_config(MAIN_WITH_CONFDIR + spelling + b'\n', 'main', strict=False)], ['dhcp-lease'])

    def test_the_old_name_is_refused_in_a_request_as_well(self):
        rc, resp, out, err = run_helper_with(request(settings=dict(GOOD, **{'dhcp-lease': ALIAS_VICTIM})))
        self.assertEqual(rc, 2, out)
        self.assertIn('forbidden directive', resp['error'])
        self.untouched()


class AllowlistPolicy(Base):
    """What the web tier could have written is checked against a list of what may be there, not only against a list of what may not:
    the main file holds what render_main() emits, reservations.conf holds dhcp-host, any other file holds options dnsmasq has. (A root-owned
    file is not the web tier's: the audit keeps refusing only the forbidden names there.)"""

    def setUp(self):
        Base.setUp(self)
        self.mod = load_module()
        arm_marker()

    def scan(self, text, kind, strict=True):
        return self.mod.scan_config(text if isinstance(text, bytes) else text.encode(), kind, strict)

    def test_every_rendering_and_every_file_the_old_generator_wrote_is_accepted_as_a_main_file(self):
        texts = []
        for settings in (GOOD, dict(GOOD, dhcp_enabled='false'), dict(GOOD, gateway='', dns_primary='', dns_secondary='', domain=''),
                         dict(GOOD, lease_time='infinite', cidr='16', interface='')):
            action, s, r = self.mod.parse_request(json.dumps(request(settings=settings)).encode())
            texts.append(self.mod.render_main(s, default_interface=lambda: 'eth9'))
        texts.append(self.mod._default_main().decode())
        for text in texts:
            self.assertEqual(self.scan(text, 'main'), [], text)
        legacy = sorted(glob.glob(os.path.join(CHAR_DIR, '*.legacy.conf')))
        self.assertGreaterEqual(len(legacy), 25, 'the characterization data is missing')
        for path in legacy:
            with self.subTest(file=os.path.basename(path)):
                self.assertEqual(self.scan(read(path), 'main'), [])

    def test_any_request_the_helper_accepts_renders_files_the_allowlist_accepts(self):
        """Property (fixed seed): the allowlist and the renderer cannot drift apart - whatever the helper accepts renders to a main file and a
        reservations file that the strict scan of the lockdown takes without a finding (or the next lockdown would replace the helper's own work)."""
        rng = random.Random(20261029)
        ip = lambda: '.'.join(str(rng.randint(0, 255)) for _ in range(4))
        for _ in range(300):
            settings = {'dhcp_enabled': rng.choice(['true', 'false']), 'interface': rng.choice(['eth0', 'end0', 'br-lan', 'wlan0.100', '_x', '']),
                        'cidr': rng.choice(['', '8', '16', '24', '30', '32']), 'range_start': rng.choice(['', ip()]), 'range_end': rng.choice(['', ip()]),
                        'gateway': rng.choice(['', ip()]), 'dns_primary': rng.choice(['', ip()]), 'dns_secondary': rng.choice(['', ip()]),
                        'lease_time': rng.choice(['', '24h', '30m', '1w', '7d', '3600', 'infinite', '12H']),
                        'domain': rng.choice(['', 'local', 'lan.example.com', 'a-b_c'])}
            items = [{'mac': ':'.join('%02x' % rng.randint(0, 255) for _ in range(6)), 'ip': ip(), 'hostname': rng.choice(['', 'printer', 'a-b.c'])} for _ in range(rng.randint(0, 4))]
            action, s, r = self.mod.parse_request(json.dumps(request(settings=settings, reservations=items)).encode())
            main = self.mod.render_main(s, default_interface=lambda: 'eth9')
            res = self.mod.render_reservations(r)
            self.assertEqual(self.scan(main, 'main'), [], main)
            self.assertEqual(self.scan(res, 'res'), [], res)

    def test_a_name_the_renderer_does_not_emit_is_not_kept_in_the_main_file_even_when_it_is_harmless(self):
        cases = [(b'no-daemon\n', 'not-rendered'), (b'keep-in-foreground\n', 'not-rendered'), (b'domain-needed\n', 'not-rendered'),
                 (b'address=/evil.example/6.6.6.6\n', 'not-rendered'), (b'server=6.6.6.6\n', 'not-rendered'), (b'domain-suffix=evil.example\n', 'not-rendered'),
                 (b'script-on-renewal\n', 'not-rendered'), (b'version\n', 'not-rendered'), (b'help\n', 'not-rendered'), (b'frobnicate=1\n', 'not-rendered'),
                 (b'dhcp-lease=/tmp/x\n', 'dhcp-lease'), (b'conf-script=/tmp/x\n', 'conf-script')]
        for line, tag in cases:
            with self.subTest(line=line):
                self.assertEqual(self.scan(MAIN_WITH_CONFDIR + line, 'main'), [(9, tag)])
        self.assertEqual(self.scan(MAIN_WITH_CONFDIR, 'main'), [], 'control: the same file without the extra line')

    def test_the_fixed_lines_are_allowed_only_as_they_are(self):
        for fixed in (b'dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases', b'log-facility=/var/log/dnsmasq.log', b'dhcp-script=/opt/irongate/dhcp-notify.sh',
                      b'conf-dir=/etc/dnsmasq.d/,*.conf'):
            with self.subTest(fixed=fixed):
                self.assertEqual(self.scan(fixed + b'\n', 'main'), [])
                self.assertEqual(len(self.scan(fixed + b'2\n', 'main')), 1)
                self.assertTrue(self.scan(fixed + b' # trailing\n', 'main'))
                self.assertTrue(self.scan(fixed + b' # trailing\n', 'main', strict=False))

    def test_end_to_end_availability_options_planted_in_the_window_do_not_survive_the_lockdown(self):
        """Not what the brief asked (they are out of scope) - the allowlist closes them for free: a no-daemon line in the main file made
        systemd wait for a daemon that never forks."""
        for extra, line in ((b'no-daemon\n', 9), (b'keep-in-foreground\n', 9), (b'port=53\nno-hosts\n', 10)):
            with self.subTest(extra=extra):
                fresh_env()
                web_tree(MAIN_WITH_CONFDIR + extra)
                rc, resp, out, err = run_helper(['--lockdown'])
                self.assertEqual(rc, 0, out + err)
                self.assertNotIn(extra.split(b'\n')[-2], read(CONF))
                self.assertIn('QUARANTINED /etc/dnsmasq.conf (not-rendered at line %d)' % line, out)
                self.assertEqual(st(CONF), '0:0:644')

    def test_the_other_files_take_every_option_dnsmasq_has_that_is_not_forbidden_and_nothing_else(self):
        names = [n for n, has_arg, val in dnsmasq_option_table()]
        benign = sorted(n for n in names if n not in self.mod.FORBIDDEN and n.islower())  # filter-A and filter-AAAA are not plain syntax
        self.assertGreater(len(benign), 140)
        for name in benign:
            self.assertEqual(self.scan('%s=1\n' % name, 'other'), [], name)
        for name in ('frobnicate', 'conf-file2', 'dhcp-lease-file', 'dhcp-leasefiles', 'x-new-option', 'dhcp-leasefile-2'):
            self.assertEqual(self.scan('%s=/tmp/x\n' % name, 'other'), [(1, 'unknown-option')], name)
        self.assertEqual(self.scan('# a comment\n\n', 'other'), [])

    def test_end_to_end_an_unknown_name_in_a_web_owned_file_is_quarantined(self):
        web_tree()
        write(CONFD + '/zz-new.conf', b'some-option-of-dnsmasq-99=/etc/cron.d/x\n', WEB, WEB, 0o664)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(CONFD + '/zz-new.conf'))
        self.assertIn('QUARANTINED /etc/dnsmasq.d/zz-new.conf (unknown-option at line 1)', out)

    def test_root_owned_files_are_audited_by_the_forbidden_names_only(self):
        write(OPERATOR, OPERATOR_TEXT + b'frobnicate=1\nno-daemon\n', 0, 0, 0o644)
        write(CONF, MAIN_WITH_CONFDIR + b'domain-needed\n', 0, 0, 0o644)
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)


class LockdownRobustness(Base):
    """N6 (HIGH): a name of 244 or more characters made the temporary file name `.<name>.lock.<pid>` longer than NAME_MAX, so the lockdown
    stopped with an exception half way, the main file (the last one it handles) stayed www-data's and hostile, and the installer's
    `dnsmasq --test` ran its conf-script as root. The temporary name no longer depends on the entry, an error on one entry puts that entry
    aside and goes on, and the main file and the directory are always finished; anything that could not be locked makes the exit status 5."""

    def setUp(self):
        Base.setUp(self)
        arm_marker()
        self.mod = load_module()
        self.addCleanup(self.remove_etc_decoys)

    def remove_etc_decoys(self):
        for n in os.listdir('/etc'):
            path = '/etc/' + n
            if n.startswith('.new.') or re.fullmatch(r'\.dnsmasq\.conf\.lock\.\d+', n):
                shutil.rmtree(path) if os.path.isdir(path) and not os.path.islink(path) else os.unlink(path)

    def plant(self, long_name=LONG_NAME, long_content=b'# decoy\n'):
        web_tree()
        write(CONFD + '/' + long_name, long_content, WEB, WEB, 0o664)
        write(CONFD + '/zz-evil.conf', b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o664)
        write(CONF, MAIN_WITH_CONFDIR + b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o664)

    def finished(self, rc, out, err):
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(st(CONF), '0:0:644', 'the main file is handled last: it must be root-owned')
        self.assertEqual(st(CONFD), '0:0:755')
        self.assertNotIn(b'conf-script', read(CONF))
        self.assertFalse(os.path.lexists(CONFD + '/zz-evil.conf'))
        run_dnsmasq_as_root()
        self.assertFalse(os.path.exists(MARKER), 'dnsmasq --test, run as root after the lockdown, executed the planted conf-script')
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, out)

    def test_a_long_file_name_does_not_stop_the_lockdown_half_way(self):
        for length in (255, 252, 250):
            with self.subTest(length=length):
                fresh_env()
                arm_marker()
                name = ('a' * (length - 5)) + '.conf'
                self.assertEqual(len(name), length)
                self.plant(long_name=name)
                rc, resp, out, err = run_helper(['--lockdown'])
                self.finished(rc, out, err)
                self.assertEqual(st(CONFD + '/' + name), '0:0:644', 'a clean file with a long name is re-created under its own name')
                self.assertEqual(read(CONFD + '/' + name), b'# decoy\n')
                self.assertEqual(self.leftover_temp_files(), [])

    def leftover_temp_files(self):
        return [os.path.join(d, n) for d in ('/etc', CONFD, SNAPSHOT, QUARANTINE) if os.path.isdir(d) for n in os.listdir(d) if n.startswith('.new.')]

    def test_a_hostile_file_with_a_very_long_name_is_quarantined_too(self):
        self.plant(long_content=b'conf-script=' + PWN.encode() + b'\n')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.finished(rc, out, err)
        self.assertFalse(os.path.lexists(CONFD + '/' + LONG_NAME))
        self.assertTrue(all(len(n) < 200 for n in quarantined_files()), 'the quarantine copy is named with a bounded part of the name')

    def test_entries_of_every_type_with_a_name_of_255_characters_are_put_aside_and_the_lockdown_finishes(self):
        self.plant(long_name='b' * 250 + '.conf')
        os.mkfifo(CONFD + '/' + 'f' * 250 + '.conf')
        os.chown(CONFD + '/' + 'f' * 250 + '.conf', WEB, WEB)
        os.mkdir(CONFD + '/' + 'd' * 250 + '.conf')
        os.chown(CONFD + '/' + 'd' * 250 + '.conf', WEB, WEB)
        os.symlink('/nonexistent/target', CONFD + '/' + 'l' * 250 + '.conf')
        os.symlink('/etc/shadow', CONFD + '/' + 's' * 250 + '.conf')
        rc, resp, out, err = run_helper(['--lockdown'])
        self.finished(rc, out, err)
        names = sorted(os.listdir(CONFD))
        self.assertEqual(len([n for n in names if n.startswith('.refused.')]), 4, names)
        self.assertEqual(sorted(n for n in names if len(n) > 200), ['b' * 250 + '.conf'])
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn('QUARANTINED', out, 'a second run changes nothing')

    def test_a_decoy_at_the_guessed_temporary_name_does_not_stop_the_lockdown(self):
        """The attacker knows the pid scheme of the old name and may guess the new one: every name the helper could pick is taken beforehand
        (by files root keeps, so that they are still there when the helper needs the name)."""
        self.plant()
        pid, ns = 4242, 1000
        for n in ('README', 'operator-local.conf', 'reservations.conf'):
            write(CONFD + '/.%s.lock.%d' % (n, pid), b'decoy', 0, 0, 0o644)  # the old scheme, for every entry of the directory
        write('/etc/.dnsmasq.conf.lock.%d' % pid, b'decoy', 0, 0, 0o644)  # ... and for the main file
        for base in (CONFD, '/etc'):  # the new scheme, with a clock the attacker guessed, and the first retry name
            write(base + '/.new.%d.%d' % (pid, ns), b'decoy', 0, 0, 0o644)
            write(base + '/.new.%d.%d.1' % (pid, ns), b'decoy', 0, 0, 0o644)
        with unittest.mock.patch.object(self.mod.os, 'getpid', return_value=pid), unittest.mock.patch.object(self.mod.time, 'monotonic_ns', return_value=ns):
            out = self.mod.lockdown()
        self.assertEqual(st(CONF), '0:0:644')
        self.assertNotIn(b'conf-script', read(CONF))
        for n in ('README', 'operator-local.conf', 'reservations.conf'):
            self.assertEqual(st(CONFD + '/' + n), '0:0:644', n)
        self.assertEqual(sorted(l for l in out if 'QUARANTINED' in l and 'could not be locked' in l), [], out)
        for path in (CONFD, '/etc'):
            self.assertEqual(read(path + '/.new.%d.%d' % (pid, ns)), b'decoy', 'the helper did not touch the decoy')

    def test_a_decoy_directory_at_every_name_makes_the_lockdown_fail_and_say_so_but_finish_the_main_file(self):
        """The retry gives up after 33 names: that is a refusal (exit 5), not an exception, and not a main file left in www-data's hands."""
        self.plant()
        pid, ns = 4243, 2000
        for suffix in [''] + ['.%d' % i for i in range(1, 40)]:  # in /etc, where the main file is re-created (the directory's entries are scanned, these would be put aside)
            os.mkdir('/etc/.new.%d.%d%s' % (pid, ns, suffix))
        with unittest.mock.patch.object(self.mod.os, 'getpid', return_value=pid), unittest.mock.patch.object(self.mod.time, 'monotonic_ns', return_value=ns):
            with self.assertRaises(self.mod.Failure) as ctx:
                self.mod.lockdown()
        self.assertEqual(ctx.exception.code, 5)
        self.assertIn('dnsmasq.conf', ctx.exception.error)
        self.assertIn('QUARANTINED /etc/dnsmasq.conf', ctx.exception.output)
        self.assertFalse(os.path.exists(CONF), 'the main file that could not be re-created is put aside, not left web-writable')
        self.assertEqual(st(CONFD), '0:0:755')
        self.assertFalse(os.path.lexists(CONFD + '/zz-evil.conf'))

    def test_a_directory_at_the_name_an_entry_is_put_aside_under_is_not_in_the_way(self):
        """`.refused.<time>.<pid>.<name>` is also a name somebody can take beforehand (a directory with content there: a rename onto it fails)."""
        self.plant(long_name='ordinary.conf')
        os.mkfifo(CONFD + '/pipe.conf')
        os.chown(CONFD + '/pipe.conf', WEB, WEB)
        pid, now = 4244, 1790000000
        for suffix in ('', '.1'):
            d = CONFD + '/.refused.%d.%d.pipe.conf%s' % (now, pid, suffix)
            os.mkdir(d)
            write(d + '/x', b'x')
        with unittest.mock.patch.object(self.mod.os, 'getpid', return_value=pid), unittest.mock.patch.object(self.mod.time, 'time', return_value=now):
            out = self.mod.lockdown()
        self.assertFalse(os.path.lexists(CONFD + '/pipe.conf'))
        self.assertTrue(os.path.lexists(CONFD + '/.refused.%d.%d.pipe.conf.2' % (now, pid)), sorted(os.listdir(CONFD)))
        self.assertIn('QUARANTINED /etc/dnsmasq.d/pipe.conf (special file) -> .refused.%d.%d.pipe.conf.2' % (now, pid), '\n'.join(out))
        self.assertEqual(st(CONF), '0:0:644')
        self.assertNotIn(b'conf-script', read(CONF))

    def test_an_error_on_one_entry_puts_that_entry_aside_and_the_others_and_the_main_file_are_finished(self):
        self.plant()
        real = self.mod._write_new

        def failing(dfd, name, *args, **kw):
            if name in ('README', 'reservations.conf'):
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
            return real(dfd, name, *args, **kw)
        with unittest.mock.patch.object(self.mod, '_write_new', failing):
            out = self.mod.lockdown()
        self.assertEqual(st(CONF), '0:0:644')
        self.assertNotIn(b'conf-script', read(CONF))
        self.assertEqual(st(CONFD + '/operator-local.conf'), '0:0:644', 'the entries after the failing ones were handled')
        self.assertFalse(os.path.lexists(CONFD + '/README'))
        self.assertTrue([n for n in os.listdir(CONFD) if n.startswith('.refused.') and n.endswith('.README')])
        self.assertIn('QUARANTINED /etc/dnsmasq.d/README (could not be locked: No space left on device)', '\n'.join(out))
        self.assertTrue(all(st(CONFD + '/' + n).startswith('0:0:') for n in os.listdir(CONFD)), [(n, st(CONFD + '/' + n)) for n in os.listdir(CONFD)])
        aside = [n for n in os.listdir(CONFD) if n.startswith('.refused.') and n.endswith('.README')][0]
        self.assertEqual(st(CONFD + '/' + aside), '0:0:755', 'the file put aside is root\'s and nobody else can write it (it was 775)')
        rc, resp, out, err = run_helper(['--audit'])
        self.assertEqual(rc, 0, 'the audit accepts the tree the lockdown left, put-aside regular files included: ' + out)

    def test_an_entry_that_cannot_even_be_put_aside_makes_the_exit_status_5_after_everything_else_is_done(self):
        self.plant()
        real_write, real_rename = self.mod._write_new, os.rename

        def failing_write(dfd, name, *args, **kw):
            if name == 'README':
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            return real_write(dfd, name, *args, **kw)

        def failing_rename(src, dst, *args, **kw):
            if src == 'README':
                raise OSError(errno.EPERM, os.strerror(errno.EPERM))
            return real_rename(src, dst, *args, **kw)
        with unittest.mock.patch.object(self.mod, '_write_new', failing_write), unittest.mock.patch.object(self.mod.os, 'rename', failing_rename):
            with self.assertRaises(self.mod.Failure) as ctx:
                self.mod.lockdown()
        self.assertEqual((ctx.exception.code, ctx.exception.error), (5, 'could not lock: /etc/dnsmasq.d/README'))
        self.assertIn('FAILED /etc/dnsmasq.d/README (Input/output error; it could not be put aside either: Operation not permitted)', ctx.exception.output)
        self.assertEqual(st(CONF), '0:0:644', 'the main file was finished')
        self.assertNotIn(b'conf-script', read(CONF))
        self.assertEqual(st(CONFD), '0:0:755')
        self.assertFalse(os.path.lexists(CONFD + '/zz-evil.conf'))

    def test_a_read_error_on_one_entry_does_not_stop_the_lockdown(self):
        self.plant()
        real_read = self.mod._read_all
        calls = []

        def failing(fd, limit):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            return real_read(fd, limit)
        with unittest.mock.patch.object(self.mod, '_read_all', failing):
            out = self.mod.lockdown()
        self.assertGreaterEqual(len(calls), 3)
        self.assertIn('could not be locked: Input/output error', '\n'.join(out))
        self.assertEqual(st(CONF), '0:0:644')
        self.assertNotIn(b'conf-script', read(CONF))

    def test_an_unreadable_entry_is_put_aside(self):
        """A control (the fd0d663 lockdown handled it too): the entry is www-data's, mode 000, and the helper runs without
        CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH (dropped from the bounding set before it is executed), so it really cannot read it."""
        self.plant(long_name='ordinary.conf')
        write(CONFD + '/unreadable.conf', b'conf-script=' + PWN.encode() + b'\n', WEB, WEB, 0o000)
        libc = ctypes.CDLL(None, use_errno=True)

        def drop():
            for cap in (1, 2):  # CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH
                if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
                    os._exit(97)
        proc = subprocess.run([HELPER, '--lockdown'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        out, err = proc.stdout.decode(), proc.stderr.decode()
        self.assertNotEqual(proc.returncode, 97, 'the container does not let the test drop the capabilities')
        self.assertEqual(proc.returncode, 0, out + err)
        self.assertIn('QUARANTINED /etc/dnsmasq.d/unreadable.conf (Permission denied) -> .refused.', out, 'the helper really could not read it')
        self.assertFalse(os.path.lexists(CONFD + '/unreadable.conf'))
        self.assertEqual(st(CONF), '0:0:644')
        self.assertNotIn(b'conf-script', read(CONF))

    def test_the_report_goes_out_with_the_failure_and_the_exit_status_is_5(self):
        self.plant()
        real = self.mod._write_new

        def failing(dfd, name, *args, **kw):
            if name == 'dnsmasq.conf':
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
            return real(dfd, name, *args, **kw)
        stdout, stderr = io.StringIO(), io.StringIO()
        self.addCleanup(os.umask, os.umask(0o022))  # main() sets the umask of its process
        with unittest.mock.patch.object(self.mod, '_write_new', failing), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = self.mod.main(['dnsmasq-apply', '--lockdown'])
        self.assertEqual(rc, 5)
        self.assertIn('lockdown: /etc/dnsmasq.d is root:root 0755', stdout.getvalue(), 'what was done before the failure is not lost')
        self.assertIn('QUARANTINED /etc/dnsmasq.conf (could not be locked: No space left on device)', stdout.getvalue())
        self.assertEqual(stderr.getvalue().strip(), 'error: could not lock: /etc/dnsmasq.conf')

    def test_a_symlinked_main_file_stops_the_lockdown_with_exit_5_but_the_report_is_not_lost(self):
        """The entries are handled first and the main file last; a main file that is a link ends the run (nobody follows it), and what was
        done to the directory before that is in the output."""
        web_tree()
        os.unlink(CONF)
        write('/tmp/real.conf', MAIN_WITH_CONFDIR, WEB, WEB, 0o664)
        os.symlink('/tmp/real.conf', CONF)
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 5, out + err)
        self.assertIn('lockdown: /etc/dnsmasq.d is root:root 0755', out)
        self.assertIn('lockdown: re-created /etc/dnsmasq.d/README as root:root 0644', out)
        self.assertIn('is a symbolic link', err)
        self.assertTrue(os.path.islink(CONF))

    def test_a_clean_lockdown_leaves_no_temporary_file_and_a_second_one_is_quiet(self):
        web_tree()
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.leftover_temp_files(), [])
        self.assertEqual(left_over(), [])
        rc, resp, out, err = run_helper(['--lockdown'])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn('re-created', out)

# ================================================================ the restart is waited for (live finding on the router, 2026-10-28)
import time

FAKE_DIR = '/tmp/fake-systemd'
FAKE_SYSTEMCTL = r'''#!/usr/bin/python3
# systemd as the router has it. `stop dnsmasq` is a job that waits for irongate.service to stop first (BindsTo/PartOf) and then runs; the
# job belongs to systemd, so it goes on when its client is killed; a `start` that arrives while it is still queued CANCELS it (MainPID
# unchanged, nothing restarted); the client of a cancelled or failed job exits non-zero.
import json, os, sys, time
D, S = '/tmp/fake-systemd', '/tmp/fake-systemd/state.json'
def load():
    s = json.load(open(S))
    job = s['stop_job']
    if job and job['due'] is not None and time.time() >= job['due']:
        s['pid'], s['stop_job'] = 0, None                    # the queued stop runs by itself once it is due
    return s
def save(s):
    json.dump(s, open(S + '.tmp', 'w')); os.replace(S + '.tmp', S)
cmd = sys.argv[1]
open(D + '/log', 'a').write(' '.join(sys.argv[1:]) + '\n')
s = load(); cfg = s['cfg']
if cmd == 'stop':
    if cfg['stop_rc']:
        print('Failed to stop dnsmasq.service: simulated'); sys.exit(cfg['stop_rc'])
    if s['pid']:
        s['stop_job'] = {'due': None if cfg['stop_never'] else time.time() + cfg['stop_delay']}; save(s)
    while load()['stop_job']: time.sleep(0.05)               # the client waits for its job
    s = load(); save(s)
    if s['pid']:
        print('Job for dnsmasq.service canceled.'); sys.exit(1)
elif cmd == 'start':
    if cfg['start_rc']:
        print('Failed to start dnsmasq.service: simulated'); sys.exit(cfg['start_rc'])
    if s['stop_job']: s['stop_job'] = None                   # cancelled: the old process goes on
    elif not s['pid']: s['pid'], s['next_pid'] = s['next_pid'], s['next_pid'] + 1
    save(s)
elif cmd == 'is-active':
    save(s); print('active' if s['pid'] else 'inactive'); sys.exit(0 if s['pid'] else 3)
'''


class ServiceRestart(Base):
    """On the router `systemctl stop dnsmasq` takes ~95 s (irongate.service stops first, BindsTo/PartOf, TimeoutStopSec=180) and the helper
    waited 60 s, ignored the result and ran `start`, which cancelled the queued stop: success was reported while dnsmasq went on with its old
    process and its old configuration. Times are scaled here: the old wait of 60 s is 1 s, the stop of 95 s is 3 s, the new wait is 10 s."""
    PID = 4242

    def setUp(self):
        Base.setUp(self)
        self.addCleanup(shutil.rmtree, FAKE_DIR, True)

    def fake(self, stop_delay=0, stop_never=False, stop_rc=0, start_rc=0):
        shutil.rmtree(FAKE_DIR, ignore_errors=True)
        os.makedirs(FAKE_DIR)
        write(FAKE_DIR + '/systemctl', FAKE_SYSTEMCTL, mode=0o755)
        write(FAKE_DIR + '/state.json', json.dumps({'pid': self.PID, 'next_pid': 5000, 'stop_job': None,
                                                     'cfg': {'stop_delay': stop_delay, 'stop_never': stop_never, 'stop_rc': stop_rc,
                                                             'start_rc': start_rc}}))

    def apply(self, wait_start, wait_stop):
        mod = load_module()
        mod.SYSTEMCTL_BIN = (FAKE_DIR + '/systemctl',)
        mod.SERVICE_TIMEOUT, mod.STOP_TIMEOUT = wait_start, wait_stop
        stage(request())
        return mod.run_request()

    def state(self):
        return json.loads(read(FAKE_DIR + '/state.json'))

    def log(self):
        return read(FAKE_DIR + '/log').decode().splitlines()

    def active(self):
        return subprocess.run([FAKE_DIR + '/systemctl', 'is-active', 'dnsmasq'], stdout=subprocess.PIPE).stdout.decode().strip()

    def failed_and_back(self, rc, body):
        self.assertEqual(rc, 4, body)
        self.assertEqual((body['success'], body['stage'], body['restored'], body['restarted']), (False, 'start', True, True), body)
        self.untouched()

    def test_control_a_stop_that_is_quick_ends_in_a_new_process(self):
        self.fake()
        rc, body = self.apply(1, 10)
        self.assertEqual((rc, body), (0, {'success': True, 'stage': 'start'}))
        self.assertNotIn(self.state()['pid'], (0, self.PID))
        self.assertEqual(self.log(), ['stop dnsmasq', 'start dnsmasq'])

    def test_a_stop_that_takes_longer_than_the_old_wait_still_ends_in_a_restart(self):
        self.fake(stop_delay=3)
        rc, body = self.apply(1, 10)
        self.assertEqual((rc, body), (0, {'success': True, 'stage': 'start'}))
        state = self.state()
        self.assertNotIn(state['pid'], (0, self.PID), 'success was reported: dnsmasq must be a NEW process, not the one that was running')
        self.assertIsNone(state['stop_job'])
        self.assertEqual(self.log(), ['stop dnsmasq', 'start dnsmasq'])
        self.assertNotEqual(read(CONF), OLD_MAIN)
        self.assertEqual(self.active(), 'active')

    def test_a_stop_that_never_finishes_is_a_failure_with_the_old_files_back_and_dnsmasq_running(self):
        self.fake(stop_never=True)
        rc, body = self.apply(1, 2)
        self.failed_and_back(rc, body)
        self.assertIn('stop', body['error'] + body['output'])
        self.assertEqual(self.log(), ['stop dnsmasq', 'start dnsmasq'])
        state = self.state()
        self.assertEqual((state['pid'], state['stop_job']), (self.PID, None), 'the stop job is cancelled, not left to run later')
        self.assertEqual(self.active(), 'active')

    def test_a_stop_job_that_outlives_the_wait_never_stops_dnsmasq_later(self):
        self.fake(stop_delay=3)
        rc, body = self.apply(1, 1)            # the helper gives up at 1 s; the queued stop would run at 3 s
        self.failed_and_back(rc, body)
        time.sleep(3.5)                        # well past the moment it was due
        self.assertEqual((self.active(), self.state()['pid']), ('active', self.PID))

    def test_a_stop_that_fails_at_once_is_a_failure_and_dnsmasq_stays_up(self):
        self.fake(stop_rc=1)
        rc, body = self.apply(1, 2)
        self.failed_and_back(rc, body)
        self.assertEqual(self.log(), ['stop dnsmasq', 'start dnsmasq'])
        self.assertEqual((self.active(), self.state()['pid']), ('active', self.PID))

    def test_when_even_the_start_that_follows_a_failed_stop_fails_the_report_says_so(self):
        self.fake(stop_never=True, start_rc=5)
        rc, body = self.apply(1, 2)
        self.assertEqual(rc, 4, body)
        self.assertEqual((body['success'], body['restored'], body['restarted']), (False, True, False))
        self.untouched()

    def test_the_wait_for_the_stop_outlasts_what_the_units_need(self):
        mod = load_module()
        self.assertGreaterEqual(getattr(mod, 'STOP_TIMEOUT', 0), 240, 'irongate.service: TimeoutStopSec=180, and it stops before dnsmasq does')
        self.assertGreater(mod.STOP_TIMEOUT, mod.SERVICE_TIMEOUT)


def print_option_table(path):
    """The `_OPTION_TABLE` block of src/dnsmasq-apply for the dnsmasq binary at `path` (what to paste when the table test names a difference)."""
    lines, current = [], '   '
    for name, has_arg, val in dnsmasq_option_table(path):
        item = '%s %d' % (name, val)
        if len(current) + len(item) + 2 > 138:
            lines.append(current)
            current = '   '
        current += (' ' if current == '   ' else '; ') + item
    lines.append(current)
    print("_OPTION_TABLE = '''\n" + '\n'.join(lines) + "\n'''")


if __name__ == '__main__':
    if sys.argv[1:2] == ['--print-option-table']:
        print_option_table(sys.argv[2] if len(sys.argv) > 2 else '/usr/sbin/dnsmasq')
        sys.exit(0)
    unittest.main()
