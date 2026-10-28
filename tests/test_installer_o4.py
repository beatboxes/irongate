#!/usr/bin/env python3
"""
irongate-audit O4 and the installer's commit stamp: tests for irongate-install.sh.

The installer is not run as a whole (apt, systemd, nginx); like tests/test_installer_links.sh this cuts the real
blocks out of the installer text and runs them as root against scratch trees in a throw-away container:

  K  "installer commit id"   how IRONGATE_COMMIT is found (GitHub API, else dhcp.db) and checked
  S  "installer commit stamp" the one place IRONGATE_COMMIT is written into a root `sqlite3` statement
  W  "Setting permissions"    the block that still hands /etc/dnsmasq.conf and /etc/dnsmasq.d to www-data (kept byte
                              for byte: the O1 tests pin it)
  L1 "dnsmasq root helper"    installs the root helper, its sudoers drop-in and the staging directory - BEFORE W, so that
                              only the lockdown is left in the window W opens
  L2 "dnsmasq lockdown"       right after W: lockdown (scan, quarantine, re-create) and audit; a finding is fatal
  G  "dnsmasq gate"           ig_dnsmasq_tree_ok, used by the EXIT trap and the installer's tail so that dnsmasq is never
                              started (or run under `dnsmasq --test`, which executes conf-script) on a tree that is not clean
  R  the reservations.conf block that runs as root in a directory the web tier used to own

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IG_INSTALLER=/w/_work/patched/irongate-install.sh \
        -e IG_SRC=/w/_work/patched/src -v "$PWD":/w:ro -v /usr/sbin/visudo:/host-visudo:ro -v /usr/sbin/dnsmasq:/host-dnsmasq:ro \
        -v /lib/x86_64-linux-gnu:/hostlib:ro -v /usr/libexec/sudo:/usr/libexec/sudo:ro \
        -w /w python:3.12-slim python -m pytest tests/test_installer_o4.py

Against an installer from before the fix (18e5177) most of it fails; that is the point.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import unittest

INSTALLER = os.environ.get('IG_INSTALLER', 'irongate-install.sh')
SRC = os.environ.get('IG_SRC', os.path.join(os.path.dirname(os.path.abspath(INSTALLER)), 'src'))
WEB = 33
SHIM = '/tmp/ig-shim'
TEXT = open(INSTALLER, encoding='utf-8').read()
LINES = TEXT.split('\n')

COLORS = "RED=; GREEN=; YELLOW=; CYAN=; MAGENTA=; BOLD=; NC=; "


def find(regex):
    return [i for i, line in enumerate(LINES) if re.search(regex, line)]


def seg(start_re, end_re, include_end=False):
    s, e = find(start_re), find(end_re)
    if len(s) != 1 or len(e) != 1 or s[0] >= e[0]:
        return None
    return '\n'.join(LINES[s[0]:e[0] + (1 if include_end else 0)]) + '\n'


K = seg(r'^# Get current commit hash from GitHub \(will be stored after install\)$', r'^echo "Commit: \$IRONGATE_COMMIT"$', True)
W = seg(r'^echo -e "\$\{YELLOW\}Setting permissions\.\.\.\$\{NC\}"$', r'^# Ensure lease file has proper ownership for dnsmasq to write$')
WH = seg(r'^# ---- web-tree permission helper: begin ----$', r'^# ---- web-tree permission helper: end ----$', True)
L1 = seg(r'^# ---- dnsmasq root helper: begin ----$', r'^# ---- dnsmasq root helper: end ----$', True)
L2 = seg(r'^# ---- dnsmasq lockdown: begin ----$', r'^# ---- dnsmasq lockdown: end ----$', True)
# the single block of ec3b495 (helper, drop-in and lockdown after W); None in the current installer. Kept only so that the
# window test below can show the old installer being exploited.
OLD_L = seg(r'^echo -e "\$\{YELLOW\}Making /etc/dnsmasq\.conf and /etc/dnsmasq\.d root-only\.\.\.\$\{NC\}"$', r'^cat > /etc/sudoers\.d/dnsmasq-web << EOF$')
GATE = seg(r'^# ---- dnsmasq gate: begin ----$', r'^# ---- dnsmasq gate: end ----$', True)
TRAP = seg(r'^cleanup_on_exit\(\) \{$', r'^trap cleanup_on_exit EXIT$', True)
TAIL = seg(r'^# Test dnsmasq config before starting$', r'^# Final output$')
R = seg(r"^# Create empty reservations file only if it doesn't exist$", r'^# Clean up any old backup files in dnsmasq\.d that could cause duplicate errors$')
S_NEW = seg(r'^# ---- installer commit stamp: begin ----$', r'^# ---- installer commit stamp: end ----$', True)
OLD_STAMP_LINE = [l for l in LINES if re.search(r"^sqlite3 /var/www/irongate/dhcp\.db \"INSERT OR REPLACE INTO settings \(key, value\) VALUES \('installed_commit', '\$\{IRONGATE_COMMIT\}'\);\"$", l)]
S = S_NEW if S_NEW is not None else ('\n'.join(OLD_STAMP_LINE) + '\n' if len(OLD_STAMP_LINE) == 1 else None)


def sh(script, env=None, check=False):
    e = {'PATH': SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C'}
    e.update(env or {})
    proc = subprocess.run(['bash', '-c', script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=e, timeout=180)
    return proc.returncode, proc.stdout.decode('utf-8', 'replace')


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


def as_web(code):
    def drop():
        os.setgroups([])
        os.setgid(WEB)
        os.setuid(WEB)
    return subprocess.run([sys.executable, '-I', '-c', code], preexec_fn=drop, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def setUpModule():
    if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
        raise RuntimeError('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
    if os.geteuid() != 0:
        raise RuntimeError('must run as root')
    for d in ('/etc/irongate', '/opt/irongate', '/var/www/irongate', '/var/lib/irongate'):
        if os.path.exists(d):
            raise RuntimeError('refusing to run: %s already exists' % d)
    os.makedirs(SHIM, exist_ok=True)
    if not os.path.exists('/usr/bin/python3'):
        os.symlink(sys.executable, '/usr/bin/python3')
    # curl: the GitHub API is unreachable unless a test says otherwise
    write(SHIM + '/curl', '#!/bin/sh\nif [ -n "$IG_FAKE_API" ]; then printf "%s\\n" "$IG_FAKE_API"; exit 0; fi\nexit 22\n', mode=0o755)
    # sqlite3: the CLI's behaviour for `sqlite3 DB "SQL"`: every statement of the string runs, until one fails
    write(SHIM + '/sqlite3', textwrap.dedent('''\
        #!/usr/bin/env python3
        import sqlite3, sys
        db, sql = sys.argv[1], sys.argv[2]
        con = sqlite3.connect(db, isolation_level=None)
        rest = sql
        try:
            while rest.strip():
                for i, ch in enumerate(rest):
                    if ch == ';' and sqlite3.complete_statement(rest[:i + 1]):
                        stmt, rest = rest[:i + 1], rest[i + 1:]
                        break
                else:
                    stmt, rest = rest, ''
                for row in con.execute(stmt):
                    print('|'.join('' if v is None else str(v) for v in row))
        except sqlite3.Error as exc:
            print('Error: %s' % exc, file=sys.stderr)
            sys.exit(1)
        '''), mode=0o755)
    # visudo: the host's, through its own loader (sudo-rs on the workstation)
    if os.path.exists('/host-visudo'):
        write(SHIM + '/visudo', '#!/bin/sh\nexec /hostlib/ld-linux-x86-64.so.2 --library-path /hostlib /host-visudo "$@"\n', mode=0o755)
    elif os.environ.get('IG_ALLOW_STUB_VISUDO') == '1':
        write(SHIM + '/visudo', '#!/bin/sh\nexit 0\n', mode=0o755)
    else:
        raise RuntimeError('the real visudo is not mounted at /host-visudo')
    # dnsmasq: the host's, through its own loader (the installer's tail runs `dnsmasq --test` as root)
    if os.path.exists('/host-dnsmasq'):
        write(SHIM + '/dnsmasq', '#!/bin/sh\nexec /hostlib/ld-linux-x86-64.so.2 --library-path /hostlib /host-dnsmasq "$@"\n', mode=0o755)
    else:
        raise RuntimeError('the real dnsmasq is not mounted at /host-dnsmasq')


def need(block, name):
    if block is None:
        raise AssertionError('the installer has no %s block (an installer from before the fix)' % name)
    return block


def installer_o4_script():
    """The blocks of the installer that matter, in installer order: root helper (L1), permission step (WH, W), lockdown
    (L2). An installer from before round 5b has one block after W instead (OLD_L)."""
    if L1 is not None and L2 is not None:
        return L1 + need(WH, 'web-tree permission helper') + need(W, 'permissions') + L2
    return need(WH, 'web-tree permission helper') + need(W, 'permissions') + need(OLD_L, 'O4 lockdown')


# ===================================================================================================== commit id and stamp
class CommitStamp(unittest.TestCase):
    DB = '/var/www/irongate/dhcp.db'

    def setUp(self):
        shutil.rmtree('/var/www/irongate', ignore_errors=True)
        for p in ('/tmp/o4-pwned.db', '/tmp/o4-pwned-2.db'):
            if os.path.exists(p):
                os.unlink(p)
        os.makedirs('/var/www/irongate')

    def make_db(self, installed_commit):
        if os.path.exists(self.DB):
            os.unlink(self.DB)
        import sqlite3
        con = sqlite3.connect(self.DB)
        con.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)')
        con.executemany('INSERT INTO settings VALUES (?, ?)', [('dhcp_enabled', 'true'), ('range_start', '192.168.1.100'),
                                                               ('auto_update_enabled', 'false'), ('installed_commit', installed_commit)])
        con.commit()
        con.close()

    def db(self, sql):
        import sqlite3
        con = sqlite3.connect(self.DB)
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()

    def run_k_then_s(self, fake_api=None):
        script = COLORS + 'IRONGATE_API=http://127.0.0.1:9/unreachable; ' + 'set +e\n' + need(K, 'commit id') + \
                 'echo "RESULT_COMMIT=[$IRONGATE_COMMIT] STAMP=[${IRONGATE_COMMIT_STAMP-unset}]"\n' + \
                 'set -e\n' + need(S, 'commit stamp') + 'echo STAMP_BLOCK_DONE\n'
        return sh(script, env={'IG_FAKE_API': fake_api} if fake_api else None)

    def installed(self):
        rows = self.db("SELECT value FROM settings WHERE key='installed_commit'")
        return rows[0][0] if rows else None

    def test_the_two_blocks_exist(self):
        need(K, 'commit id')
        need(S, 'commit stamp')

    def test_a_crafted_installed_commit_cannot_drop_the_settings_table(self):
        payload = "x'); DROP TABLE settings;--"
        self.make_db(payload)
        rc, out = self.run_k_then_s()
        tables = [r[0] for r in self.db("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertIn('settings', tables, 'the settings table is gone: the DB value ran as SQL as root\n' + out[-400:])
        self.assertEqual(self.db('SELECT COUNT(*) FROM settings')[0][0], 4, out[-400:])

    def test_a_crafted_installed_commit_is_not_stamped_and_not_shown(self):
        payload = "x'); DROP TABLE settings;--"
        self.make_db(payload)
        rc, out = self.run_k_then_s()
        self.assertEqual(self.installed(), payload, 'installed_commit must be left alone, got %r\n%s' % (self.installed(), out[-300:]))
        self.assertNotIn('DROP TABLE', out, 'the hostile value was printed')
        self.assertEqual(rc, 0, out[-400:])
        self.assertIn('STAMP=[0]', out)

    def test_attach_database_payload_creates_no_file(self):
        self.make_db("x'); ATTACH DATABASE '/tmp/o4-pwned.db' AS a; CREATE TABLE a.t(x);--")
        rc, out = self.run_k_then_s()
        self.assertFalse(os.path.exists('/tmp/o4-pwned.db'), 'root created a file named by the DB value\n' + out[-300:])

    def test_other_hostile_values_are_ignored(self):
        for value in ["abc1234'; DELETE FROM settings;--", 'ABCDEF1', 'abc123', 'abc 1234', 'abc1234\nDROP TABLE settings;', '`id`',
                      '$(touch /tmp/o4-pwned-2.db)', "\x1b]0;owned\x07abc1234", 'a' * 41]:
            with self.subTest(value=value[:30]):
                self.make_db(value)
                rc, out = self.run_k_then_s()
                self.assertEqual(self.db('SELECT COUNT(*) FROM settings')[0][0], 4, out[-300:])
                self.assertFalse(os.path.exists('/tmp/o4-pwned-2.db'))
                self.assertNotIn('\x1b', out)
                self.assertEqual(self.installed(), value)

    def test_garbage_from_the_api_is_not_used(self):
        self.make_db('abc1234')
        rc, out = self.run_k_then_s(fake_api='{"sha": "zz\'); DROP TABLE settings;--", "x": 1}')
        self.assertEqual(self.db('SELECT COUNT(*) FROM settings')[0][0], 4, out[-300:])
        self.assertIn('RESULT_COMMIT=[abc1234]', out, out[-300:])
        self.assertEqual(self.installed(), 'abc1234')

    def test_control_a_good_api_answer_is_stamped_first_seven_characters(self):
        self.make_db('abc1234')
        rc, out = self.run_k_then_s(fake_api='{\n  "sha": "0123456789abcdef0123456789abcdef01234567",\n  "x": 1}')
        self.assertIn('RESULT_COMMIT=[0123456]', out, out[-300:])
        self.assertEqual(self.installed(), '0123456')

    def test_control_a_stored_commit_id_is_kept_when_the_api_is_down(self):
        self.make_db('abc1234')
        rc, out = self.run_k_then_s()
        self.assertEqual(self.installed(), 'abc1234', out[-300:])
        self.assertEqual(self.db('SELECT COUNT(*) FROM settings')[0][0], 4)

    def test_control_nothing_known_stamps_local_as_before(self):
        self.make_db('')
        rc, out = self.run_k_then_s()
        self.assertEqual(self.installed(), 'local', out[-300:])
        self.make_db('local')
        rc, out = self.run_k_then_s()
        self.assertEqual(self.installed(), 'local', out[-300:])

    def test_a_fresh_install_without_a_database_file_still_gets_local(self):
        if os.path.exists(self.DB):
            os.unlink(self.DB)
        rc, out = sh(COLORS + 'IRONGATE_API=http://127.0.0.1:9/x; set +e\n' + need(K, 'commit id') + 'echo "R=[$IRONGATE_COMMIT] S=[${IRONGATE_COMMIT_STAMP-unset}]"\n')
        self.assertIn('R=[local]', out)

    def test_each_of_the_two_guards_works_alone(self):
        """The stamp refuses a hostile value even if the commit-id block let it through, and refuses to write at all when
        the commit-id block said 'unusable' (IRONGATE_COMMIT_STAMP=0), whatever the value looks like."""
        self.make_db('abc1234')
        payload = "x'); DROP TABLE settings;--"
        script = COLORS + 'IRONGATE_COMMIT=\'' + payload.replace("'", "'\\''") + '\'; IRONGATE_COMMIT_STAMP=1\n' + \
                 'ig_valid_commit() { [[ "$1" =~ ^[0-9a-f]{7,40}$ ]]; }\nset -e\n' + need(S, 'commit stamp')
        rc, out = sh(script)
        self.assertEqual(self.db('SELECT COUNT(*) FROM settings')[0][0], 4, 'the sink wrote a hostile value: ' + out[-300:])
        self.assertEqual(self.installed(), 'abc1234')
        script = COLORS + 'IRONGATE_COMMIT=0123456; IRONGATE_COMMIT_STAMP=0\n' + \
                 'ig_valid_commit() { [[ "$1" =~ ^[0-9a-f]{7,40}$ ]]; }\nset -e\n' + need(S, 'commit stamp')
        rc, out = sh(script)
        self.assertEqual(self.installed(), 'abc1234', 'IRONGATE_COMMIT_STAMP=0 must mean "do not write": ' + out[-300:])

    # ---- F1: the stamp comes only after everything else has succeeded
    def test_the_commit_is_stamped_once_and_only_at_the_end_of_the_install(self):
        stamps = [i for i, l in enumerate(LINES) if re.search(r"VALUES \('installed_commit', '\$\{IRONGATE_COMMIT\}'\)", l)]
        self.assertEqual(len(stamps), 1, 'exactly one statement may write the installed commit: %s' % stamps)
        done = find(r'^echo -e "\$\{GREEN\}Done\.\$\{NC\}"$')
        packages = find(r'^apt install -y dnsmasq nginx php-fpm php-sqlite3 sqlite3 jq$')
        self.assertEqual((len(done), len(packages)), (1, 1))
        self.assertGreater(stamps[0], done[0], 'the commit is stamped at line %d, before the end of the install (line %d): '
                           'a failed install would look installed' % (stamps[0] + 1, done[0] + 1))
        # nothing that can still fail comes after it except the credentials banner
        tail = [l for l in LINES[stamps[0]:] if re.match(r'^(systemctl|apt|cp|mv|chown|chmod|sed -i|pip|python3)\b', l)]
        self.assertEqual(tail, [])

    def test_the_stamp_is_the_only_sql_that_gets_a_shell_variable_from_outside(self):
        """Census: every sqlite3 statement in the installer and the updater that interpolates a variable."""
        found = set()
        for path in (INSTALLER, os.path.join(SRC, 'irongate-updater.sh')):
            for line in open(path, encoding='utf-8').read().split('\n'):
                if 'sqlite3' in line and not line.lstrip().startswith('#'):
                    for m in re.finditer(r"'\$\{?([A-Za-z_]+)\}?'", line):
                        found.add(m.group(1))
        self.assertEqual(found, {'IRONGATE_COMMIT', 'TARGET_COMMIT'}, found)

    def test_the_updaters_interpolated_value_comes_from_the_validated_pin(self):
        text = open(os.path.join(SRC, 'irongate-updater.sh'), encoding='utf-8').read()
        self.assertIn('PINNED_COMMIT=([0-9a-f]{40})', text)
        self.assertIn("TARGET_COMMIT=$(printf '%s' \"$TARGET_SHA\" | cut -c1-7)", text)


# ===================================================================================================== the dnsmasq lockdown
class Lockdown(unittest.TestCase):
    CONF = '/etc/dnsmasq.conf'
    CONFD = '/etc/dnsmasq.d'

    def setUp(self):
        for p in ('/etc/dnsmasq.conf', '/etc/dnsmasq.d', '/opt/irongate', '/var/lib/irongate', '/var/www/irongate',
                  '/etc/sudoers.d/irongate-dnsmasq-apply', '/etc/sudoers.d/dnsmasq-web', '/tmp/victim', '/tmp/outside'):
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
            elif os.path.isdir(p):
                shutil.rmtree(p)
        os.makedirs('/etc/sudoers.d', exist_ok=True)
        write('/etc/sudoers.d/dnsmasq-web', 'www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq\n', mode=0o440)
        os.makedirs('/var/www/irongate')
        write('/var/www/irongate/dhcp.db', b'db', 0, 0, 0o666)
        write(self.CONF, '# the file the web UI wrote\ninterface=eth0\n', 0, 0, 0o644)
        os.makedirs(self.CONFD)
        os.chmod(self.CONFD, 0o755)
        write(self.CONFD + '/reservations.conf', '# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n', WEB, WEB, 0o664)
        write(self.CONFD + '/README', '# readme\n', 0, 0, 0o644)
        write(self.CONFD + '/operator-local.conf', '# operator file\ndhcp-option=option:ntp-server,192.168.1.2\n', 0, 0, 0o644)

    def installer_perms_then_o4(self, w=True):
        return sh(COLORS + 'set -e\n' + installer_o4_script())

    def web_attempts(self):
        code = ('import os\nr=[]\n'
                'def t(label, fn):\n'
                '    try: fn(); r.append(label+": WRITABLE")\n'
                '    except OSError: r.append(label+": denied")\n'
                't("conf", lambda: open("/etc/dnsmasq.conf","ab").close())\n'
                't("res", lambda: open("/etc/dnsmasq.d/reservations.conf","ab").close())\n'
                't("readme", lambda: open("/etc/dnsmasq.d/README","ab").close())\n'
                't("create", lambda: open("/etc/dnsmasq.d/evil.conf","wb").close())\n'
                't("symlink", lambda: os.symlink("/tmp/x","/etc/dnsmasq.d/evil2.conf"))\n'
                't("rename", lambda: os.rename("/etc/dnsmasq.d/reservations.conf","/etc/dnsmasq.d/gone"))\n'
                't("unlink", lambda: os.unlink("/etc/dnsmasq.d/reservations.conf"))\n'
                't("chmod", lambda: os.chmod("/etc/dnsmasq.conf",0o777))\n'
                'print("\\n".join(r))\n')
        return as_web(code).stdout.decode()

    def test_the_installer_works_when_it_is_started_through_sudo(self):
        """`sudo bash irongate-install.sh`, or the updater started by www-data through sudo: SUDO_UID is set to a non-root uid."""
        script = COLORS + 'set -e\n' + installer_o4_script()
        rc, out = sh(script, env={'SUDO_UID': str(WEB), 'SUDO_USER': 'www-data', 'SUDO_GID': str(WEB)})
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual((st(self.CONF), st(self.CONFD)), ('0:0:644', '0:0:755'))

    def test_the_o4_blocks_exist_in_the_installer(self):
        need(L1, 'dnsmasq root helper')
        need(L2, 'dnsmasq lockdown')
        need(GATE, 'dnsmasq gate')

    def test_after_the_permissions_step_www_data_cannot_write_dnsmasqs_configuration(self):
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-600:])
        result = self.web_attempts()
        self.assertNotIn('WRITABLE', result, result)
        self.assertEqual(result.count('denied'), 8, result)

    def test_owners_and_modes_afterwards(self):
        before = os.stat(self.CONFD + '/operator-local.conf')
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-600:])
        self.assertIn('audit: 0 finding(s)', out, 'the audit is quiet on a clean tree')
        self.assertNotIn('WARNING', out)
        self.assertEqual(st(self.CONF), '0:0:644')
        self.assertEqual(st(self.CONFD), '0:0:755')
        self.assertEqual(st(self.CONFD + '/reservations.conf'), '0:0:644')
        self.assertEqual(st(self.CONFD + '/README'), '0:0:644')
        after = os.stat(self.CONFD + '/operator-local.conf')
        # The permissions step above (kept byte for byte, pinned by the O1 tests) hands EVERY file in /etc/dnsmasq.d to
        # www-data, the operator's included; the lockdown gives it back as a new file with the same content, root:root
        # 0644 and the same modification time.
        self.assertEqual((before.st_mtime_ns, before.st_uid, before.st_mode), (after.st_mtime_ns, after.st_uid, after.st_mode))
        self.assertEqual(read(self.CONFD + '/operator-local.conf'), b'# operator file\ndhcp-option=option:ntp-server,192.168.1.2\n')
        self.assertEqual(read(self.CONFD + '/reservations.conf'), b'# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n')
        self.assertEqual(st('/var/www/irongate/dhcp.db'), '33:33:664', 'the O1 permissions of the web tree must be as before')

    def test_an_update_does_not_revert_it(self):
        for run in (1, 2, 3):
            rc, out = self.installer_perms_then_o4()
            self.assertEqual(rc, 0, 'run %d: %s' % (run, out[-600:]))
            result = self.web_attempts()
            self.assertNotIn('WRITABLE', result, 'run %d: %s' % (run, result))
        self.assertEqual((st(self.CONF), st(self.CONFD)), ('0:0:644', '0:0:755'))

    def test_helper_and_sudoers_dropin_are_installed_exactly_as_in_the_tree(self):
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(read('/opt/irongate/dnsmasq-apply'), read(os.path.join(SRC, 'dnsmasq-apply')))
        self.assertEqual(st('/opt/irongate/dnsmasq-apply'), '0:0:755')
        self.assertEqual(st('/var/lib/irongate'), '0:0:755')
        self.assertEqual(st('/var/lib/irongate/dnsmasq-staged'), '0:%d:770' % WEB)
        sudoers = '/etc/sudoers.d/irongate-dnsmasq-apply'
        self.assertEqual(st(sudoers), '0:0:440')
        active = [l for l in read(sudoers).decode().split('\n') if l.strip() and not l.startswith('#')]
        self.assertEqual(active, ['www-data ALL=(root) NOPASSWD: /opt/irongate/dnsmasq-apply ""'])
        self.assertEqual(read('/etc/sudoers.d/dnsmasq-web'), b'www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq\n', 'the existing drop-in is not widened')
        self.assertEqual(sorted(os.listdir('/etc/sudoers.d')), ['dnsmasq-web', 'irongate-dnsmasq-apply'])
        rc, out = sh('visudo -cf %s' % sudoers)
        self.assertEqual(rc, 0, out)

    def test_planted_links_and_special_files_are_moved_aside_by_the_installer(self):
        write('/tmp/victim', b'root-only\n', 0, 0, 0o600)
        os.symlink('/tmp/victim', self.CONFD + '/evil.conf')
        os.mkfifo(self.CONFD + '/pipe.conf')
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-600:])
        names = os.listdir(self.CONFD)
        self.assertNotIn('evil.conf', names)
        self.assertNotIn('pipe.conf', names)
        self.assertEqual(len([n for n in names if n.startswith('.refused.')]), 2, names)
        self.assertEqual((st('/tmp/victim'), read('/tmp/victim')), ('0:0:600', b'root-only\n'))
        self.assertIn('QUARANTINED', out)

    def test_a_file_the_web_tier_still_holds_open_is_cut_off(self):
        code = ('import sys\nf=open("/etc/dnsmasq.conf","ab")\nprint("ready",flush=True)\nsys.stdin.readline()\n'
                'f.write(b"dhcp-script=/tmp/evil\\n")\nf.flush()\nprint("wrote",flush=True)\n')

        def drop():
            os.setgroups([])
            os.setgid(WEB)
            os.setuid(WEB)
        os.chown(self.CONF, WEB, WEB)
        os.chmod(self.CONF, 0o664)
        child = subprocess.Popen([sys.executable, '-I', '-c', code], preexec_fn=drop, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(child.stdout.readline().strip(), b'ready')
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-600:])
        child.stdin.write(b'go\n')
        child.stdin.flush()
        child.stdout.readline()
        child.wait(timeout=10)
        self.assertNotIn(b'evil', read(self.CONF))

    def test_a_directive_planted_in_reservations_conf_is_quarantined_and_the_installer_says_so(self):
        """Round 5b: the lockdown used to keep such a file (root-owned from then on) and only warn."""
        write(self.CONFD + '/reservations.conf', 'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\ndhcp-script=/tmp/evil\n', WEB, WEB, 0o664)
        rc, out = self.installer_perms_then_o4()
        self.assertEqual(rc, 0, out[-800:])
        self.assertIn('QUARANTINED /etc/dnsmasq.d/reservations.conf (dhcp-script at line 2)', out)
        self.assertIn('WARNING', out)
        self.assertNotIn('/tmp/evil', out)
        self.assertEqual(read(self.CONFD + '/reservations.conf'),
                         b'# Static DHCP Reservations - Auto-generated by Web UI\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10\n')
        self.assertIn('audit: 0 finding(s)', out)

    def test_the_old_permission_lines_are_kept_byte_for_byte(self):
        """The O1 tests pin them; the O4 block takes the ownership back afterwards."""
        for line in ('chown www-data:www-data /etc/dnsmasq.conf', 'chmod 664 /etc/dnsmasq.conf', 'ig_perm_fix tree /etc/dnsmasq.d www-data www-data 775'):
            self.assertEqual(TEXT.count('\n' + line + '\n'), 1, line)
        self.assertLess(find(r'^ig_perm_fix tree /etc/dnsmasq\.d www-data www-data 775$')[0], find(r"^echo -e \"\$\{YELLOW\}Making /etc/dnsmasq\.conf")[0])


# ===================================================================================================== round 5b: the window, the failure paths
PWN = '/tmp/pwn.sh'
MARKER = '/tmp/PWNED-uid'
STUBS = '/tmp/ig-trap-bin'


def arm_marker():
    """A program that records that root ran it. Nothing in these tests may ever make that file appear."""
    write(PWN, '#!/bin/sh\nid -u > %s\n' % MARKER, 0, 0, 0o755)
    if os.path.exists(MARKER):
        os.unlink(MARKER)


def dnsmasq_test_as_root():
    """The installer's tail without its gate: dnsmasq --test on the live configuration, the way Debian reads it (the main
    file's conf-dir plus the init script's -7, which reads every file of the directory whatever its name)."""
    return sh('dnsmasq --test --conf-file=/etc/dnsmasq.conf --conf-dir=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new')


MAIN_TEXT = ('# DHCP Server Configuration\ninterface=eth0\nbind-dynamic\nport=0\ndhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases\n'
             'log-facility=/var/log/dnsmasq.log\ndhcp-script=/opt/irongate/dhcp-notify.sh\nconf-dir=/etc/dnsmasq.d/,*.conf\n')


class TreeCase(unittest.TestCase):
    """A host as the lead described it: root-owned dnsmasq tree with an operator file, no helper yet."""

    def setUp(self):
        for p in ('/etc/dnsmasq.conf', '/etc/dnsmasq.d', '/opt/irongate', '/var/lib/irongate', '/var/www/irongate', '/etc/sudoers.d/irongate-dnsmasq-apply',
                  '/etc/sudoers.d/.irongate-dnsmasq-apply.new', '/etc/sudoers.d/dnsmasq-web', '/tmp/victim', '/tmp/outside', '/tmp/evil-second-name',
                  '/tmp/visudo.log', '/tmp/trap-systemctl.log', '/tmp/tail-dnsmasq.log', STUBS):
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
            elif os.path.isdir(p):
                shutil.rmtree(p)
        os.makedirs('/etc/sudoers.d', exist_ok=True)
        write('/etc/sudoers.d/dnsmasq-web', 'www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq\n', mode=0o440)
        os.makedirs('/var/www/irongate')
        write('/var/www/irongate/dhcp.db', b'db', 0, 0, 0o666)
        write('/etc/dnsmasq.conf', MAIN_TEXT, 0, 0, 0o644)
        os.makedirs('/etc/dnsmasq.d')
        os.chmod('/etc/dnsmasq.d', 0o755)
        write('/etc/dnsmasq.d/reservations.conf', '# Static DHCP Reservations\ndhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,x\n', 0, 0, 0o644)
        write('/etc/dnsmasq.d/README', '# readme\n', 0, 0, 0o644)
        write('/etc/dnsmasq.d/operator-local.conf', '# operator file\ndhcp-option=option:ntp-server,192.168.1.2\n', 0, 0, 0o644)
        os.makedirs(STUBS)
        arm_marker()

    def stub(self, name, body):
        write(STUBS + '/' + name, '#!/bin/sh\n' + body, mode=0o755)

    def run_with_stubs(self, script, env=None):
        e = {'PATH': STUBS + ':' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
        e.update(env or {})
        return sh(script, env=e)

    def web_plants(self):
        """What a compromised php-fpm worker does the moment the permission step has handed it the tree."""
        return as_web('import os\n'
                      'open("/etc/dnsmasq.d/zz-evil.conf","w").write("conf-script=%s\\n")\n'
                      'open("/etc/dnsmasq.conf","a").write("conf-script=%s\\n")\n'
                      'open("/etc/dnsmasq.d/reservations.conf","a").write("conf-script=%s\\n")\n'
                      'os.symlink("/root", "/etc/dnsmasq.d/zz-link.conf")\n' % (PWN, PWN, PWN))


class InstallerWindow(TreeCase):
    """F1: the permission step (block W, kept as it was: the O1 tests pin it) hands the tree to www-data; whatever it plants
    before the lockdown used to be kept, made root-owned and run by the installer's own `dnsmasq --test`."""

    def test_what_www_data_plants_after_the_permission_step_never_runs_as_root(self):
        if L1 is not None and L2 is not None:
            first, last = L1 + need(WH, 'web-tree permission helper') + need(W, 'permissions'), L2
        else:  # ec3b495: helper, drop-in and lockdown form one block after W
            first, last = need(WH, 'web-tree permission helper') + need(W, 'permissions'), need(OLD_L, 'O4 lockdown')
        rc, out = sh(COLORS + 'set -e\n' + first)
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(st('/etc/dnsmasq.d'), '%d:%d:775' % (WEB, WEB), 'the window is open: www-data owns the tree')
        planted = self.web_plants()
        self.assertEqual(planted.returncode, 0, planted.stdout)
        rc, out = sh(COLORS + 'set -e\n' + last)
        self.assertEqual(rc, 0, out[-800:])
        rc_t, out_t = dnsmasq_test_as_root()  # the installer's tail
        self.assertFalse(os.path.exists(MARKER), 'a conf-script planted by www-data between the permission step and the lockdown ran as root:\n' + out_t[-300:])
        self.assertFalse(os.path.exists('/etc/dnsmasq.d/zz-evil.conf'))
        self.assertNotIn(b'conf-script', read('/etc/dnsmasq.conf'))
        self.assertNotIn(b'conf-script', read('/etc/dnsmasq.d/reservations.conf'))
        self.assertEqual((st('/etc/dnsmasq.conf'), st('/etc/dnsmasq.d')), ('0:0:644', '0:0:755'))
        self.assertIn('QUARANTINED', out)

    def test_control_the_same_plant_does_run_when_the_tree_is_left_as_the_permission_step_made_it(self):
        """Control: without the lockdown the planted file runs, so the test above measures the lockdown."""
        rc, out = sh(COLORS + 'set -e\n' + need(WH, 'web-tree permission helper') + need(W, 'permissions'))
        self.assertEqual(rc, 0, out[-400:])
        self.web_plants()
        dnsmasq_test_as_root()
        self.assertTrue(os.path.exists(MARKER), 'the probe does not detect the plant')

    LONG_NAME = 'a' * 250 + '.conf'  # 255 characters: NAME_MAX
    ALIAS_VICTIM = '/tmp/alias-victim'

    def window(self):
        """L1 (helper, drop-in, staging directory) and the permission step W: the window is open, www-data owns the tree."""
        rc, out = sh(COLORS + 'set -e\n' + need(L1, 'dnsmasq root helper') + need(WH, 'web-tree permission helper') + need(W, 'permissions'))
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(st('/etc/dnsmasq.d'), '%d:%d:775' % (WEB, WEB), 'the window is open: www-data owns the tree')

    def start_dnsmasq_as_root(self):
        """`systemctl start dnsmasq` in the container: a root dnsmasq reads the main file and every file of the directory and opens the
        files they name; stopped after a moment."""
        for p in (self.ALIAS_VICTIM, '/var/lib/misc/dnsmasq.leases'):
            if os.path.lexists(p):
                os.unlink(p)
        os.makedirs('/var/lib/misc', exist_ok=True)
        write('/tmp/start-main.conf', 'port=0\ninterface=lo\nbind-interfaces\ndhcp-range=127.0.0.50,127.0.0.60,255.255.255.0,1h\nno-ping\n'
              'conf-dir=/etc/dnsmasq.d/,*.conf\n')
        return sh('timeout 1.5 dnsmasq -k -C /tmp/start-main.conf --user=root --group=root --log-facility=- -x /tmp/start-dnsmasq.pid')

    def test_a_long_file_name_planted_in_the_window_does_not_stop_the_lockdown(self):
        """N6: a name of 244 or more characters made the lockdown stop with an exception half way; the installer stopped, the main file
        (handled last) stayed www-data's with the planted conf-script line, and its own `dnsmasq --test` or a start by www-data
        (sudoers dnsmasq-web) ran that as root."""
        self.window()
        planted = as_web('open("/etc/dnsmasq.d/%s","w").write("# decoy\\n")\n'
                         'open("/etc/dnsmasq.d/zz-evil.conf","w").write("conf-script=%s\\n")\n'
                         'open("/etc/dnsmasq.conf","a").write("conf-script=%s\\n")\n' % (self.LONG_NAME, PWN, PWN))
        self.assertEqual(planted.returncode, 0, planted.stdout)
        rc, out = sh(COLORS + 'set -e\n' + need(L2, 'dnsmasq lockdown'))
        self.assertEqual(rc, 0, out[-800:])
        self.assertEqual((st('/etc/dnsmasq.conf'), st('/etc/dnsmasq.d')), ('0:0:644', '0:0:755'), 'the tree is root\'s although the plant had a name of 255 characters')
        self.assertNotIn(b'conf-script', read('/etc/dnsmasq.conf'))
        self.assertFalse(os.path.exists('/etc/dnsmasq.d/zz-evil.conf'))
        self.assertEqual(st('/etc/dnsmasq.d/' + self.LONG_NAME), '0:0:644', 'a clean file with a long name keeps its name')
        rc_t, out_t = dnsmasq_test_as_root()
        self.assertFalse(os.path.exists(MARKER), 'a conf-script planted next to a 255-character name ran as root:\n' + out_t[-300:])
        self.assertIn('QUARANTINED', out)
        self.assertIn('audit: 0 finding(s)', out)

    def test_the_old_name_of_the_lease_file_planted_in_the_window_never_creates_the_file(self):
        """N1: `dhcp-lease=` is dnsmasq's undocumented old name of dhcp-leasefile; a root dnsmasq creates the file it names."""
        self.window()
        planted = as_web('open("/etc/dnsmasq.d/zz-alias.conf","w").write("dhcp-lease=%s\\n")\n'
                         'open("/etc/dnsmasq.conf","a").write("dhcp-lease=%s\\n")\n' % (self.ALIAS_VICTIM, self.ALIAS_VICTIM))
        self.assertEqual(planted.returncode, 0, planted.stdout)
        rc, out = sh(COLORS + 'set -e\n' + need(L2, 'dnsmasq lockdown'))
        self.assertEqual(rc, 0, out[-800:])
        self.assertIn('QUARANTINED /etc/dnsmasq.d/zz-alias.conf (dhcp-lease at line 1)', out)
        self.assertIn('QUARANTINED /etc/dnsmasq.conf (dhcp-lease at line', out)
        rc_s, out_s = self.start_dnsmasq_as_root()
        self.assertFalse(os.path.exists(self.ALIAS_VICTIM), 'a root dnsmasq created the file the planted alias named:\n' + out_s[-300:])

    def test_control_the_same_alias_does_create_the_file_when_the_tree_is_left_as_the_permission_step_made_it(self):
        self.window()
        as_web('open("/etc/dnsmasq.d/zz-alias.conf","w").write("dhcp-lease=%s\\n")\n' % self.ALIAS_VICTIM)
        self.start_dnsmasq_as_root()
        self.assertTrue(os.path.exists(self.ALIAS_VICTIM), 'the probe does not see the alias')

    def test_a_file_in_the_directory_that_no_scan_of_the_old_audit_would_look_at_is_found(self):
        """A root-owned file the permission step leaves alone (a second hard link) used to be taken for an operator file."""
        write('/etc/dnsmasq.d/evil.conf', 'conf-script=%s\n' % PWN, 0, 0, 0o644)
        os.link('/etc/dnsmasq.d/evil.conf', '/tmp/evil-second-name')
        rc, out = sh(COLORS + 'set -e\n' + installer_o4_script())
        self.assertNotEqual(rc, 0, 'an audit finding must stop the installer:\n' + out[-800:])
        self.assertIn('FINDING /etc/dnsmasq.d/evil.conf:1: conf-script', out)
        self.assertNotIn(PWN, out)
        self.assertFalse(os.path.exists(MARKER))

    def test_the_helper_drop_in_and_staging_directory_are_installed_before_the_permission_step(self):
        need(L1, 'dnsmasq root helper')
        need(L2, 'dnsmasq lockdown')
        l1_end = find(r'^# ---- dnsmasq root helper: end ----$')[0]
        wh_begin = find(r'^# ---- web-tree permission helper: begin ----$')[0]
        w_begin = find(r'^echo -e "\$\{YELLOW\}Setting permissions\.\.\.\$\{NC\}"$')[0]
        marker = find(r'^# Ensure lease file has proper ownership for dnsmasq to write$')[0]
        l2_begin = find(r'^# ---- dnsmasq lockdown: begin ----$')[0]
        self.assertLess(l1_end, wh_begin)
        self.assertLess(wh_begin, w_begin)
        self.assertLess(w_begin, marker)
        self.assertGreater(l2_begin, marker)
        helper = find(r"^cat > /opt/irongate/dnsmasq-apply << 'DNSMASQAPPLY'$")[0]
        staging = find(r'^install -d -o root -g www-data -m 0770 /var/lib/irongate/dnsmasq-staged$')[0]
        dropin = find(r"^cat << 'DNSMASQAPPLY_SUDOEOF' > \"\$IG_SUDOERS_NEW\"$")[0]
        for line in (helper, staging, dropin):
            self.assertLess(line, wh_begin, 'line %d is installed after the permission step opened the window' % (line + 1))
        # between W and the lockdown there is nothing but comments
        between = [l for l in LINES[find(r'^ig_perm_fix tree /etc/dnsmasq\.d www-data www-data 775$')[0] + 1:l2_begin] if l.strip() and not l.startswith('#')]
        self.assertEqual(between, [], 'commands between the dnsmasq part of the permission step and the lockdown: %s' % between)

    def test_the_lockdown_is_the_first_thing_after_the_permission_step_not_the_lease_file(self):
        marker = find(r'^# Ensure lease file has proper ownership for dnsmasq to write$')[0]
        l2_begin = find(r'^# ---- dnsmasq lockdown: begin ----$')[0]
        lease = [i for i in find(r'^chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq\.leases') if i > marker][0]
        self.assertLess(l2_begin, lease)
        self.assertLess(marker, l2_begin)


class FailurePaths(TreeCase):
    """F6: a failed or half-done installer must not hand a www-data-owned tree to a root daemon."""

    def trap_script(self, body):
        return COLORS + (GATE or '') + need(TRAP, 'EXIT trap') + '\n' + body + '\nexit 1\n'

    def stubs_for_trap(self):
        self.stub('systemctl', 'echo "$*" >> /tmp/trap-systemctl.log\nexit 0\n')
        self.stub('php', 'echo "PHP 8.3.1 (cli)"\n')
        os.makedirs('/etc/nginx/sites-enabled', exist_ok=True)
        os.makedirs('/etc/nginx/sites-available', exist_ok=True)
        write('/etc/nginx/sites-available/irongate', 'server {}\n')

    def started(self):
        return 'start dnsmasq' in (read('/tmp/trap-systemctl.log').decode().split('\n') if os.path.exists('/tmp/trap-systemctl.log') else [])

    def test_the_trap_starts_dnsmasq_on_a_tree_that_is_locked_and_clean(self):
        self.stubs_for_trap()
        rc, out = sh(COLORS + 'set -e\n' + installer_o4_script())
        self.assertEqual(rc, 0, out[-600:])
        rc, out = self.run_with_stubs(self.trap_script('true'))
        self.assertEqual(rc, 1, out)
        self.assertTrue(self.started(), 'control: on a clean tree the trap still brings dnsmasq back\n' + out[-400:])

    def test_the_trap_does_not_start_dnsmasq_on_a_tree_www_data_still_owns(self):
        self.stubs_for_trap()
        first = (L1 or '') + need(WH, 'web-tree permission helper') + need(W, 'permissions')
        rc, out = sh(COLORS + 'set -e\n' + first)
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(st('/etc/dnsmasq.d'), '%d:%d:775' % (WEB, WEB))
        rc, out = self.run_with_stubs(self.trap_script('true'))
        self.assertFalse(self.started(), 'the EXIT trap started dnsmasq on a tree www-data owns:\n' + out[-500:])
        self.assertIn('dnsmasq NOT started', out)

    def test_a_lockdown_that_fails_stops_the_installer_and_dnsmasq_stays_stopped(self):
        self.stubs_for_trap()
        script = COLORS + (GATE or '') + need(TRAP, 'EXIT trap') + '\nset -e\n'
        if L1 is not None and L2 is not None:
            # the quarantine directory cannot be created: the lockdown fails (exit 5) with the tree still in www-data's hands
            script += L1 + need(WH, 'web-tree permission helper') + need(W, 'permissions') + 'echo x > /var/lib/irongate/dnsmasq-quarantine\n' + L2
        else:
            script += need(WH, 'web-tree permission helper') + need(W, 'permissions') + need(OLD_L, 'O4 lockdown') + '\nfalse\n'
        rc, out = self.run_with_stubs(script)
        self.assertNotEqual(rc, 0, out[-600:])
        if L1 is not None:
            self.assertIn('could not make /etc/dnsmasq.conf and /etc/dnsmasq.d root-only', out)
        self.assertFalse(self.started(), 'the EXIT trap started dnsmasq after a failed lockdown:\n' + out[-600:])

    def test_a_finding_makes_the_trap_leave_dnsmasq_stopped_even_though_the_lockdown_ran(self):
        self.stubs_for_trap()
        write('/etc/dnsmasq.d/evil.conf', 'conf-script=%s\n' % PWN, 0, 0, 0o644)
        os.link('/etc/dnsmasq.d/evil.conf', '/tmp/evil-second-name')
        script = COLORS + (GATE or '') + need(TRAP, 'EXIT trap') + '\nset -e\n' + installer_o4_script()
        rc, out = self.run_with_stubs(script)
        self.assertNotEqual(rc, 0, out[-600:])
        self.assertFalse(self.started(), 'the trap started dnsmasq on a tree with a finding')
        self.assertFalse(os.path.exists(MARKER))

    def run_tail(self):
        self.stub('dnsmasq', 'echo "$*" >> /tmp/tail-dnsmasq.log\nexit 0\n')
        self.stub('systemctl', 'echo "$*" >> /tmp/trap-systemctl.log\nexit 0\n')
        for tool in ('pkill', 'ss', 'journalctl'):
            self.stub(tool, 'exit 0\n')
        return self.run_with_stubs(COLORS + 'set +e\n' + (GATE or '') + need(TAIL, 'installer tail') + '\necho TAIL_DONE\n')

    def test_the_tail_neither_tests_nor_starts_dnsmasq_on_a_tree_that_is_not_clean(self):
        rc, out = sh(COLORS + 'set -e\n' + (L1 or '') + need(WH, 'web-tree permission helper') + need(W, 'permissions'))
        self.assertEqual(rc, 0, out[-400:])
        rc, out = self.run_tail()
        self.assertFalse(os.path.exists('/tmp/tail-dnsmasq.log'), '`dnsmasq --test` ran on a tree that is not clean (it executes conf-script):\n' + out[-400:])
        self.assertFalse(self.started())
        self.assertNotIn('TAIL_DONE', out, 'the installer must stop here')

    def test_the_tail_tests_and_starts_dnsmasq_on_a_clean_locked_tree(self):
        rc, out = sh(COLORS + 'set -e\n' + installer_o4_script())
        self.assertEqual(rc, 0, out[-400:])
        rc, out = self.run_tail()
        self.assertIn('TAIL_DONE', out)
        self.assertEqual(read('/tmp/tail-dnsmasq.log').decode().strip(), '--test')
        self.assertTrue(self.started(), out[-400:])


class SudoersDropIn(TreeCase):
    """F6: the drop-in is written under a dotted name (sudo ignores it), checked with visudo there, then renamed into place."""

    def recorder(self, rc):
        os.makedirs('/tmp/ig-shim2', exist_ok=True)
        write('/tmp/ig-shim2/visudo', '#!/bin/sh\n{ echo "ARGS $*"; if [ -e /etc/sudoers.d/irongate-dnsmasq-apply ]; then echo FINAL_PRESENT; else echo FINAL_ABSENT; fi; '
              'ls -A /etc/sudoers.d; } >> /tmp/visudo.log\nexit %d\n' % rc, mode=0o755)

    def run_l1(self):
        return sh(COLORS + 'set -e\n' + need(L1, 'dnsmasq root helper'), env={'PATH': '/tmp/ig-shim2:' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})

    def test_visudo_checks_a_dotted_file_while_the_real_name_does_not_exist_yet(self):
        self.recorder(0)
        rc, out = self.run_l1()
        self.assertEqual(rc, 0, out[-600:])
        log = read('/tmp/visudo.log').decode()
        self.assertIn('ARGS -cf /etc/sudoers.d/.irongate-dnsmasq-apply.new', log)
        self.assertIn('FINAL_ABSENT', log, 'the drop-in was already live while visudo checked it:\n' + log)
        self.assertNotIn('FINAL_PRESENT', log)
        self.assertEqual(sorted(os.listdir('/etc/sudoers.d')), ['dnsmasq-web', 'irongate-dnsmasq-apply'])
        self.assertEqual(st('/etc/sudoers.d/irongate-dnsmasq-apply'), '0:0:440')

    def test_a_drop_in_that_visudo_rejects_never_becomes_live_and_leaves_nothing_behind(self):
        self.recorder(1)
        rc, out = self.run_l1()
        self.assertEqual(rc, 0, 'a broken drop-in is reported, the installer goes on: ' + out[-400:])
        self.assertIn('failed validation', out)
        self.assertEqual(sorted(os.listdir('/etc/sudoers.d')), ['dnsmasq-web'])

    def test_an_existing_good_drop_in_survives_a_failed_update(self):
        write('/etc/sudoers.d/irongate-dnsmasq-apply', 'www-data ALL=(root) NOPASSWD: /opt/irongate/dnsmasq-apply ""\n', 0, 0, 0o440)
        self.recorder(1)
        rc, out = self.run_l1()
        self.assertEqual(read('/etc/sudoers.d/irongate-dnsmasq-apply'), b'www-data ALL=(root) NOPASSWD: /opt/irongate/dnsmasq-apply ""\n')
        self.assertEqual(sorted(os.listdir('/etc/sudoers.d')), ['dnsmasq-web', 'irongate-dnsmasq-apply'])

    def test_the_drop_in_is_the_one_in_config(self):
        tree = os.path.dirname(os.path.abspath(INSTALLER))
        m = re.search(r"cat << 'DNSMASQAPPLY_SUDOEOF' > \"\$IG_SUDOERS_NEW\"\n(.*?)\nDNSMASQAPPLY_SUDOEOF\n", TEXT, re.S)
        self.assertTrue(m)
        self.assertEqual(m.group(1) + '\n', read(os.path.join(tree, 'config', 'irongate-dnsmasq-apply')).decode())


class CommitLocale(unittest.TestCase):
    """F11."""

    def test_ig_valid_commit_does_not_depend_on_the_locale(self):
        line = [l for l in LINES if l.startswith('ig_valid_commit()')]
        self.assertEqual(len(line), 1)
        rc, out = sh(line[0] + '\ndeclare -f ig_valid_commit')
        self.assertIn('local LC_ALL=C', out, 'a locale whose collation puts upper case inside a-f would let ABCDEF1 pass: ' + out)
        rc, out = sh(line[0] + '\nLC_ALL=zz_ZZ; ig_valid_commit abc1234 && echo VALID; ig_valid_commit ABCDEF1 || echo REFUSED; echo "LC_ALL=$LC_ALL"')
        self.assertIn('VALID', out)
        self.assertIn('REFUSED', out)
        self.assertIn('LC_ALL=zz_ZZ', out, 'the function must not leak its locale')


# ===================================================================================================== reservations.conf
class ReservationsBlock(unittest.TestCase):
    def setUp(self):
        shutil.rmtree('/etc/dnsmasq.d', ignore_errors=True)
        for p in glob_tmp():
            os.unlink(p)
        os.makedirs('/etc/dnsmasq.d')
        os.chmod('/etc/dnsmasq.d', 0o775)
        os.chown('/etc/dnsmasq.d', WEB, WEB)
        write('/root/o4-secret', 'ROOT-ONLY-SECRET-MARKER\n', 0, 0, 0o600)

    def run_r(self):
        return sh(COLORS + 'set -e\n' + need(R, 'reservations') + '\n')

    def leaked(self):
        hits = []
        for path in ['/etc/dnsmasq.d/' + n for n in os.listdir('/etc/dnsmasq.d')] + glob_tmp():
            if os.path.isfile(path) and not os.path.islink(path) and b'ROOT-ONLY-SECRET-MARKER' in read(path):
                hits.append(path)
        return hits

    def test_a_planted_symlink_is_never_read_or_copied_by_root(self):
        os.symlink('/root/o4-secret', '/etc/dnsmasq.d/reservations.conf')
        rc, out = self.run_r()
        self.assertEqual(self.leaked(), [], 'root copied a root-only file named by a link the web tier planted\n' + out[-400:])
        self.assertTrue(os.path.islink('/etc/dnsmasq.d/reservations.conf'), 'the link must be left for the lockdown to move aside')
        self.assertEqual(read('/root/o4-secret'), b'ROOT-ONLY-SECRET-MARKER\n')

    def test_a_dangling_symlink_is_not_created_through(self):
        os.symlink('/var/tmp/o4-created-by-root', '/etc/dnsmasq.d/reservations.conf')
        if os.path.exists('/var/tmp/o4-created-by-root'):
            os.unlink('/var/tmp/o4-created-by-root')
        rc, out = self.run_r()
        self.assertFalse(os.path.exists('/var/tmp/o4-created-by-root'), 'root created the target of a dangling link\n' + out[-400:])

    def test_control_a_genuine_file_is_still_sanitised_and_is_root_owned(self):
        write('/etc/dnsmasq.d/reservations.conf', 'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,my laptop\n', WEB, WEB, 0o664)
        rc, out = self.run_r()
        self.assertEqual(rc, 0, out[-400:])
        self.assertEqual(read('/etc/dnsmasq.d/reservations.conf'), b'dhcp-host=aa:bb:cc:dd:ee:01,192.168.1.10,my-laptop\n')
        self.assertEqual(st('/etc/dnsmasq.d/reservations.conf'), '0:0:644', 'the installer must not hand the file back to www-data')

    def test_control_a_missing_file_is_created(self):
        rc, out = self.run_r()
        self.assertEqual(rc, 0, out[-400:])
        self.assertTrue(os.path.isfile('/etc/dnsmasq.d/reservations.conf'))


def glob_tmp():
    import glob
    return glob.glob('/tmp/reservations.conf.*')


# ===================================================================================================== the tree stays in sync
class Sync(unittest.TestCase):
    def test_heredoc_copies_of_the_new_files_match(self):
        tree = os.path.dirname(os.path.abspath(INSTALLER))
        tool = os.path.join(tree, 'tools', 'heredoc_sync.py')
        proc = subprocess.run([sys.executable, '-I', tool, '--check'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode())
        self.assertTrue(os.path.isfile(os.path.join(SRC, 'dnsmasq-apply')), 'src/dnsmasq-apply is missing')
        self.assertTrue(os.path.isfile(os.path.join(tree, 'config', 'irongate-dnsmasq-apply')), 'config/irongate-dnsmasq-apply is missing')
        self.assertIn("cat > /opt/irongate/dnsmasq-apply << 'DNSMASQAPPLY'", TEXT)
        # the drop-in is written under a dotted name now (SudoersDropIn.test_the_drop_in_is_the_one_in_config compares it with config/)
        self.assertIn("cat << 'DNSMASQAPPLY_SUDOEOF' > \"$IG_SUDOERS_NEW\"", TEXT)


if __name__ == '__main__':
    unittest.main()
