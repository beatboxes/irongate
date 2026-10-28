#!/usr/bin/env python3
"""
Irongate installer hardening (item E): behaviour of the pieces of irongate-install.sh that changed.

The installer is not run as a whole (apt, systemd, nginx); like tests/test_installer_links.sh and tests/test_installer_o4.py this cuts
the real blocks out of the installer text and runs them as root against scratch trees, with shims for dpkg, apt, pip and curl,
in a throw-away container:

  N   nginx      the "first install" decision (made once, at the top) and the two places that used to `rm -f sites-enabled/*`
                 every time: the nginx block and the EXIT trap; other sites survive a re-run, they go on a first install
  S   sudoers    /etc/sudoers.d/dnsmasq-web is written under a dotted name, checked with the REAL visudo, then renamed; a bad
                 file is rejected and the file in place stays; the real file is never replaced while visudo is still looking
  P   password   the generated admin password is never printed (stdout/stderr, banner); it goes to a root:root 0600 file that
                 is created with that mode, never rewritten in place and never written through a planted link
  PIP pip        every install is `--require-hashes -r <list>`; the lists (venv, system) are written to a root-only temporary
                 directory that is gone afterwards; the venv-then-system fallbacks keep their shape
  APT apt        only packages that are missing are installed (a package that was removed but kept its configuration files is
                 missing), `apt update` runs only when something is missing, nothing present is touched
  DB  dhcp.db    the backup made by a run is root:root 0600; dhcp.db keeps the mode it had (never world-writable; 0660 when
                 this run created it) after the permission step that sets everything in the web tree to 0755 / 0664
  OPT /opt       the mode pass over /opt/irongate never gives any file or directory a permission bit it did not have, and never
                 enters /opt/irongate/audit-bak
  E   /etc/irongate  (A1-A3) the directory is created root:www-data 0750 and an existing one keeps its mode (never 0775); config.yaml
                 is created only when absent (an EMPTY one counts as absent) 0640 and any non-empty one keeps its bytes, inode and
                 mtime and loses every `other` permission bit; auth.json is created 0640 and an existing one keeps its mode

It overwrites /etc/nginx, /etc/sudoers.d, /etc/irongate, /opt/irongate and /var/www/irongate, so it refuses to run outside a
throw-away container. The sudoers cases need the real visudo; the way tests/test_installer_o4.py gets it:

  docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro \
      -v /usr/sbin/visudo:/host-visudo:ro -v /lib/x86_64-linux-gnu:/hostlib:ro -v /usr/libexec/sudo:/usr/libexec/sudo:ro \
      -w /w python:3.12-slim python3 tests/test_item_e_installer.py irongate-install.sh

Without /host-visudo the sudoers cases FAIL (they are not skipped). Exit status 0 = every case passed; against the installer of
c866e4c most of it fails, which is the point.
"""
import os
import re
import shutil
import stat
import subprocess
import sys

INSTALLER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'irongate-install.sh')
TREE = os.path.dirname(INSTALLER)
TEXT = open(INSTALLER, encoding='utf-8').read()
LINES = TEXT.split('\n')
COLORS = "RED=; GREEN=; YELLOW=; CYAN=; MAGENTA=; BOLD=; NC=; "
SHIM = '/tmp/ig-shim'

if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
    sys.exit('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
if os.geteuid() != 0:
    sys.exit('must run as root')
for d in ('/etc/irongate', '/opt/irongate', '/var/www/irongate', '/etc/nginx', '/etc/sudoers.d', '/etc/.irongate-stage', '/etc/dnsmasq.d'):
    if os.path.exists(d):
        sys.exit('refusing to run: %s already exists' % d)
if shutil.which('python3') is None:
    sys.exit('needs python3 on PATH (the installer helpers call it)')

pass_n = fail_n = 0


def check(name, cond, detail=''):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print('PASS  ' + name)
    else:
        fail_n += 1
        print('FAIL  ' + name + ('  -- ' + detail if detail else ''))


def find(regex):
    return [i for i, line in enumerate(LINES) if re.search(regex, line)]


def seg(start_re, end_re, include_end=False):
    s, e = find(start_re), find(end_re)
    if len(s) != 1 or len(e) != 1 or s[0] >= e[0]:
        return None
    return '\n'.join(LINES[s[0]:e[0] + (1 if include_end else 0)]) + '\n'


def sh(script, env=None, umask=None):
    e = {'PATH': SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C'}
    e.update(env or {})
    if umask is not None:
        script = 'umask %s\n%s' % (umask, script)
    p = subprocess.run(['bash', '-c', script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=e, timeout=180)
    return p.returncode, p.stdout.decode('utf-8', 'replace')


def write(path, data, mode=0o644, uid=0, gid=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(data.encode() if isinstance(data, str) else data)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def read(path):
    with open(path, 'rb') as fh:
        return fh.read()


def st(path):
    try:
        s = os.lstat(path)
    except OSError:
        return 'missing'
    return '%d:%d:%o' % (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def rmrf(*paths):
    for p in paths:
        if os.path.islink(p) or os.path.isfile(p):
            os.unlink(p)
        elif os.path.isdir(p):
            shutil.rmtree(p)


def need(block, name):
    return block if block is not None else ''


os.makedirs(SHIM, exist_ok=True)

# ============================================================================== blocks cut out of the installer
FIRST = seg(r'^# First install of the nginx site, decided ONCE here', r'^# Detect primary network interface$')
NGINX = seg(r'^# On the FIRST install \(decided once at the top\) remove ALL other sites', r'^# Verify the symlink exists$')
GATE = seg(r'^# ---- dnsmasq gate: begin ----$', r'^# ---- dnsmasq gate: end ----$', True)
TRAP = seg(r'^cleanup_on_exit\(\) \{$', r'^trap cleanup_on_exit EXIT$', True)
SUDOERS = seg(r'^IG_SUDOERS_WEB_NEW=/etc/sudoers\.d/\.irongate-dnsmasq-web\.new$', r'^# Create systemd watchdog for auto-recovery$')
HELPERS = seg(r'^# ---- /etc/irongate fixed-file helpers: begin ----$', r'^# ---- /etc/irongate fixed-file helpers: end ----$', True)
AUTH = seg(r'^# access-control.json \S+ preserved across re-runs$', r'^# Generate the nginx allow-list snippet now')
BANNER = None
_b = find(r'^if \[ -n "\$WEBAUTH_INIT_PASSWORD" \]; then$')
if len(_b) == 1:
    BANNER = '\n'.join(LINES[_b[0]:]) + '\n'
PIP = seg(r'^# Create Python virtual environment$', r'^# Create Irongate main script$')
APT = seg(r'^# Update system$', r'^# Detect PHP version installed$')
DBHEAD = None
_s, _e = find(r'^IG_DB_MODE_BEFORE=""'), find(r'^    echo -e "\$\{GREEN\}Created database backup\$\{NC\}"$')
if len(_s) == 1 and len(_e) == 1 and _s[0] < _e[0]:
    DBHEAD = '\n'.join(LINES[_s[0]:_e[0] + 1]) + '\nfi\n'
DBPOST = seg(r'^# ---- dhcp\.db modes: begin ----$', r'^# ---- dhcp\.db modes: end ----$', True)
WH = seg(r'^# ---- web-tree permission helper: begin ----$', r'^# ---- web-tree permission helper: end ----$', True)
W = seg(r'^echo -e "\$\{YELLOW\}Setting permissions\.\.\.\$\{NC\}"$', r'^# Ensure lease file has proper ownership for dnsmasq to write$')
OPT = None
_s = find(r'^chown -R root:root /opt/irongate$')
if len(_s) == 1:
    _e = [i for i in find(r'^systemctl daemon-reload$') if i > _s[0]]
    if _e:
        OPT = '\n'.join(LINES[_s[0]:_e[0]]) + '\n'

ETCDIR = seg(r'^if \[ ! -e /etc/irongate \] && \[ ! -L /etc/irongate \]; then$', r'^# Check for old DHCP-admin installation and migrate$')
PERM = seg(r'^# IMPORTANT: www-data needs to write to config.yaml from the web UI$', r'^# Create Python virtual environment$')
CFGGEN = seg(r'^# Create config from database \(includes any existing devices\)$', r'^chown -R root:root /opt/irongate$')

# ============================================================================== N: nginx
def mk_nginx(avail_ours=False, enabled_ours=None, others=('other',)):
    """enabled_ours: None, 'link' (to our file) or 'dangling'."""
    rmrf('/etc/nginx')
    os.makedirs('/etc/nginx/sites-available')
    os.makedirs('/etc/nginx/sites-enabled')
    write('/etc/nginx/sites-available/default', 'server { # default }\n')
    os.symlink('/etc/nginx/sites-available/default', '/etc/nginx/sites-enabled/default')
    for o in others:
        write('/etc/nginx/sites-available/' + o, 'server { # %s }\n' % o)
        os.symlink('/etc/nginx/sites-available/' + o, '/etc/nginx/sites-enabled/' + o)
    if avail_ours:
        write('/etc/nginx/sites-available/irongate', 'server { # irongate fastcgi_pass unix:/run/php/php8.3-fpm.sock; }\n')
    if enabled_ours == 'link':
        os.symlink('/etc/nginx/sites-available/irongate', '/etc/nginx/sites-enabled/irongate')
    elif enabled_ours == 'dangling':
        os.symlink('/etc/nginx/sites-available/irongate', '/etc/nginx/sites-enabled/irongate')
        if os.path.exists('/etc/nginx/sites-available/irongate'):
            os.unlink('/etc/nginx/sites-available/irongate')


def enabled():
    return sorted(os.listdir('/etc/nginx/sites-enabled'))


def decision():
    rc, out = sh(COLORS + need(FIRST, 'first-install decision') + '\necho "FIRST=${IG_NGINX_FIRST_INSTALL-unset}"\n')
    m = re.search(r'FIRST=(\S+)', out)
    return m.group(1) if m else 'no-output:' + out[-120:]


check('N the installer decides "first install" once, near the top (block found)', FIRST is not None)
mk_nginx()
check('N decision: neither of our site files exists -> first install (1)', decision() == '1', decision())
mk_nginx(avail_ours=True)
check('N decision: sites-available/irongate exists -> re-run (0)', decision() == '0', decision())
mk_nginx(avail_ours=True, enabled_ours='link')
check('N decision: sites-available and sites-enabled link exist -> re-run (0)', decision() == '0', decision())
mk_nginx(enabled_ours='dangling')
check('N decision: a dangling sites-enabled/irongate (left by the trap of a run that failed early) is still a first install (1)', decision() == '1', decision())

if NGINX is not None:
    mk_nginx(avail_ours=True, enabled_ours='link')
    rc, out = sh(COLORS + 'IG_NGINX_FIRST_INSTALL=0\n' + NGINX)
    check('N nginx block, re-run: exits 0', rc == 0, out[-300:])
    check('N nginx block, re-run: the other sites stay enabled (default, other) and ours is linked',
          enabled() == ['default', 'irongate', 'other'], str(enabled()))
    check('N nginx block, re-run: sites-available/default is not deleted', os.path.exists('/etc/nginx/sites-available/default'))
    mk_nginx(avail_ours=True)
    rc, out = sh(COLORS + 'IG_NGINX_FIRST_INSTALL=1\n' + NGINX)
    check('N nginx block, first install: every other site is removed, only ours is enabled', rc == 0 and enabled() == ['irongate'], '%s rc=%s' % (enabled(), rc))
    check('N nginx block, first install: sites-available/default is removed, other available sites are kept',
          not os.path.exists('/etc/nginx/sites-available/default') and os.path.exists('/etc/nginx/sites-available/other'))
    mk_nginx(avail_ours=True)
    rc, out = sh(COLORS + NGINX)
    check('N nginx block with the flag unset behaves as a re-run (nothing removed)', rc == 0 and 'default' in enabled() and 'other' in enabled(), str(enabled()))
else:
    check('N nginx block found in the installer', False, 'block "On the FIRST install ... Verify the symlink exists" not found')

# the EXIT trap
for d, body in (('/usr/bin/true', None),):
    pass
write(SHIM + '/systemctl', '#!/bin/sh\nexit 0\n', 0o755)
write(SHIM + '/php', '#!/bin/sh\necho "PHP 8.3.1 (cli)"\n', 0o755)


def run_trap(flag):
    pre = '' if flag is None else 'IG_NGINX_FIRST_INSTALL=%s\n' % flag
    return sh(COLORS + need(GATE, 'gate') + need(TRAP, 'trap') + '\n' + pre + 'false\n')


check('N the EXIT trap block is found', TRAP is not None)
mk_nginx(avail_ours=True, enabled_ours='link')
rc, out = run_trap(0)
check('N EXIT trap on a re-run: other sites are left alone, ours stays linked', 'default' in enabled() and 'other' in enabled() and 'irongate' in enabled(), '%s %s' % (enabled(), out[-200:]))
mk_nginx(avail_ours=True, enabled_ours='link')
rc, out = run_trap(1)
check('N EXIT trap on a first install: only ours stays enabled', enabled() == ['irongate'], '%s %s' % (enabled(), out[-200:]))
mk_nginx(avail_ours=True, enabled_ours='link')
rc, out = run_trap(None)
check('N EXIT trap with the flag unset (isolated use) removes nothing', 'default' in enabled() and 'other' in enabled(), '%s %s' % (enabled(), out[-200:]))
rmrf('/etc/nginx')

# ============================================================================== S: sudoers
EXPECTED = read(os.path.join(TREE, 'templates', 'sudoers-dnsmasq-web.template')).decode()
NEWLINE = 'www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block irongate-updater-now.service'
REAL_VISUDO = os.path.exists('/host-visudo')
VIS_ENV = {}
if REAL_VISUDO:
    write(SHIM + '/visudo', '#!/bin/sh\nexec /hostlib/ld-linux-x86-64.so.2 --library-path /hostlib /host-visudo "$@"\n', 0o755)


def sudoers_fresh(existing=None):
    rmrf('/etc/sudoers.d')
    os.makedirs('/etc/sudoers.d')
    if existing is not None:
        write('/etc/sudoers.d/dnsmasq-web', existing, 0o440)


def run_sudoers(block=None, env=None):
    return sh(COLORS + 'set -e\n' + (block if block is not None else need(SUDOERS, 'sudoers')), env=env)


OLD = 'www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq\n# OLD-MARKER\n'
check('S the sudoers block is found in the installer', SUDOERS is not None)
check('S the real visudo is mounted at /host-visudo (the cases below need it)', REAL_VISUDO)
if SUDOERS is not None and REAL_VISUDO:
    sudoers_fresh()
    rc, out = run_sudoers()
    check('S good content: block exits 0, real visudo prints no error', rc == 0 and 'ERROR' not in out, out[-300:])
    check('S good content: /etc/sudoers.d/dnsmasq-web is root:root 0440 with exactly the template content',
          st('/etc/sudoers.d/dnsmasq-web') == '0:0:440' and read('/etc/sudoers.d/dnsmasq-web').decode() == EXPECTED, st('/etc/sudoers.d/dnsmasq-web'))
    check('S good content: the new rule is in, the old --force rule is not',
          NEWLINE in read('/etc/sudoers.d/dnsmasq-web').decode() and 'irongate-updater.sh --force' not in read('/etc/sudoers.d/dnsmasq-web').decode())
    check('S good content: nothing else is left in /etc/sudoers.d (no dotted temp file)', os.listdir('/etc/sudoers.d') == ['dnsmasq-web'], str(os.listdir('/etc/sudoers.d')))

    # an update replaces the previous file
    sudoers_fresh(OLD)
    rc, out = run_sudoers()
    check('S update over an existing file: replaced by the new content (0440 root:root)', rc == 0 and read('/etc/sudoers.d/dnsmasq-web').decode() == EXPECTED and st('/etc/sudoers.d/dnsmasq-web') == '0:0:440', out[-200:])

    # a file that visudo rejects
    bad = SUDOERS.replace(NEWLINE, 'www-data ALL=(root) NOPASSWD /usr/bin/systemctl start BROKEN (')
    check('S control: the doctored block really differs', bad != SUDOERS)
    sudoers_fresh(OLD)
    before = (read('/etc/sudoers.d/dnsmasq-web'), st('/etc/sudoers.d/dnsmasq-web'))
    rc, out = run_sudoers(bad)
    check('S rejected content: the installer goes on (exit 0) and says the check failed', rc == 0 and 'failed validation' in out, 'rc=%s %s' % (rc, out[-300:]))
    check('S rejected content: the sudoers file in place is byte-identical and keeps owner and mode', (read('/etc/sudoers.d/dnsmasq-web'), st('/etc/sudoers.d/dnsmasq-web')) == before, st('/etc/sudoers.d/dnsmasq-web'))
    check('S rejected content: no dotted temp file is left behind', os.listdir('/etc/sudoers.d') == ['dnsmasq-web'], str(os.listdir('/etc/sudoers.d')))
    sudoers_fresh()
    rc, out = run_sudoers(bad)
    check('S rejected content on a first install: no sudoers file comes into being', rc == 0 and os.listdir('/etc/sudoers.d') == [], str(os.listdir('/etc/sudoers.d')))

# the order: visudo looks at the dotted file while the real name still holds the old file
if SUDOERS is not None:
    write(SHIM + '/visudo-rec', '#!/bin/sh\n{ echo "ARGS $*"; echo "OLDMARK=$(grep -c OLD-MARKER /etc/sudoers.d/dnsmasq-web 2>/dev/null)"; ls -A /etc/sudoers.d; } >> /tmp/visudo.log\nexit ${VISUDO_RC:-0}\n', 0o755)
    os.makedirs('/tmp/ig-shim-rec', exist_ok=True)
    shutil.copy(SHIM + '/visudo-rec', '/tmp/ig-shim-rec/visudo')
    sudoers_fresh(OLD)
    rmrf('/tmp/visudo.log')
    rc, out = sh(COLORS + 'set -e\n' + SUDOERS, env={'PATH': '/tmp/ig-shim-rec:' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})
    log = read('/tmp/visudo.log').decode() if os.path.exists('/tmp/visudo.log') else ''
    check('S visudo is asked to check the dotted file /etc/sudoers.d/.irongate-dnsmasq-web.new', 'ARGS -cf /etc/sudoers.d/.irongate-dnsmasq-web.new' in log, log[-200:])
    check('S ... while the real name still holds the OLD file (nothing is live before the check passed)', 'OLDMARK=1' in log, log[-300:])
    rmrf('/tmp/visudo.log')
    sudoers_fresh(OLD)
    rc, out = sh(COLORS + 'set -e\n' + SUDOERS, env={'PATH': '/tmp/ig-shim-rec:' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'VISUDO_RC': '1'})
    check('S visudo exits 1: file in place untouched, error printed, installer continues', rc == 0 and read('/etc/sudoers.d/dnsmasq-web').decode() == OLD and 'failed validation' in out and os.listdir('/etc/sudoers.d') == ['dnsmasq-web'], out[-200:])
rmrf('/etc/sudoers.d', '/tmp/ig-shim-rec', SHIM + '/visudo-rec')

# ============================================================================== P: the generated admin password
PW = 'PWD-ITEM-E-7f3a9c11'
PWFILE = '/root/irongate-initial-admin-password'
PHPSHIM = '/tmp/ig-phpshim'
os.makedirs(PHPSHIM, exist_ok=True)
write(PHPSHIM + '/php', "#!/bin/bash\ncase \"$*\" in *password_hash*) printf '%s' '$2y$10$ShimHashShimHashShimHashShimHashShimHashShimHashSh' ;; *) printf '%s' '" + PW + "' ;; esac\n", 0o755)


def etc_fresh():
    rmrf('/etc/irongate', '/etc/.irongate-stage', PWFILE)
    os.makedirs('/etc/irongate')
    os.chown('/etc/irongate', 0, 33)
    os.chmod('/etc/irongate', 0o775)


def run_auth(umask=None, extra=''):
    return sh(COLORS + 'INTERFACE=eth0; CURRENT_IP=192.168.1.2; CURRENT_GATEWAY=192.168.1.1; ADMIN_LAN_IP=\nset -e\n' + need(HELPERS, 'helpers') + need(AUTH, 'auth block') + extra,
              env={'PATH': PHPSHIM + ':' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}, umask=umask)


check('P the auth.json block and the /etc/irongate helpers are found in the installer', AUTH is not None and HELPERS is not None)
if AUTH is not None and HELPERS is not None:
    etc_fresh()
    rc, out = run_auth(umask='000')
    check('P fresh install under a caller umask of 000: block exits 0 and created auth.json', rc == 0 and os.path.exists('/etc/irongate/auth.json'), out[-300:])
    check('P the generated password is not on stdout/stderr', PW not in out, out[-400:])
    check('P ... it is in the root-only file, with a newline', os.path.exists(PWFILE) and read(PWFILE).decode() == PW + '\n', 'file: %s' % (read(PWFILE) if os.path.exists(PWFILE) else 'missing'))
    check('P ... that file is root:root 0600 (the caller umask was 000)', st(PWFILE) == '0:0:600', st(PWFILE))
    check('P ... the only thing printed about it is the path', PWFILE in out, out[-300:])
    check('P ... the password is not in auth.json (only its bcrypt hash)', PW.encode() not in read('/etc/irongate/auth.json') and b'$2y$' in read('/etc/irongate/auth.json'))

    etc_fresh()
    write(PWFILE, 'OLD-PASSWORD\n', 0o644)
    rmrf('/root/ig-pw-prev')
    os.link(PWFILE, '/root/ig-pw-prev')
    rc, out = run_auth(umask='022')
    check('P an older, world-readable password file is not rewritten in place: old file untouched (hard link), path re-created 0600 with the new password',
          rc == 0 and st(PWFILE) == '0:0:600' and read(PWFILE).decode() == PW + '\n'
          and (read('/root/ig-pw-prev') if os.path.exists('/root/ig-pw-prev') else None) == b'OLD-PASSWORD\n'
          and st('/root/ig-pw-prev') == '0:0:644',
          '%s prev=%r %s' % (st(PWFILE), read('/root/ig-pw-prev') if os.path.exists('/root/ig-pw-prev') else 'missing', st('/root/ig-pw-prev')))
    rmrf('/root/ig-pw-prev')

    etc_fresh()
    write('/root/ig-victim', 'VICTIM\n', 0o600)
    os.symlink('/root/ig-victim', PWFILE)
    rc, out = run_auth(umask='022')
    check('P a symlink planted at the password file is not written through: victim untouched, a regular 0600 file replaces the link',
          rc == 0 and read('/root/ig-victim') == b'VICTIM\n' and not os.path.islink(PWFILE) and st(PWFILE) == '0:0:600' and read(PWFILE).decode() == PW + '\n', 'victim=%r %s' % (read('/root/ig-victim'), st(PWFILE)))
    rmrf('/root/ig-victim')

    etc_fresh()
    write('/etc/irongate/auth.json', '{"genuine":true}\n', 0o660, 0, 33)
    write(PWFILE, 'KEEP-THIS\n', 0o600)
    rc, out = run_auth()
    check('P re-run with an existing auth.json: no new password is generated, the password file is left alone', rc == 0 and read(PWFILE).decode() == 'KEEP-THIS\n' and PW not in out, out[-200:])
    rmrf(PWFILE)

check('P the end-of-install banner block is found', BANNER is not None)
if BANNER is not None:
    rc, out = sh(COLORS + 'WEBAUTH_INIT_PASSWORD=%s\nIG_ADMIN_PW_FILE=%s\n' % (PW, PWFILE) + BANNER)
    check('P banner: the password is not printed', PW not in out, out[-300:])
    check('P banner: it names the file instead', PWFILE in out and 'admin' in out, out[-300:])
    rc, out = sh(COLORS + 'WEBAUTH_INIT_PASSWORD=\nIG_ADMIN_PW_FILE=\n' + BANNER)
    check('P banner: nothing is printed when no password was generated', out.strip() == '', out[-200:])
rmrf('/etc/irongate', '/etc/.irongate-stage', PWFILE, PHPSHIM)

# ============================================================================== PIP
def pip_shim(path, tag):
    write(path, '#!/bin/bash\n'
          'n=$(( $(cat /tmp/pip-n 2>/dev/null || echo 0) + 1 )); echo $n > /tmp/pip-n\n'
          'echo "%s $*" >> /tmp/pip-calls\n'
          'f=""; a=("$@"); for ((i=0;i<${#a[@]};i++)); do [ "${a[$i]}" = -r ] && f="${a[$((i+1))]}"; done\n'
          '[ -n "$f" ] && { cp "$f" /tmp/pip-req.$n; stat -c "%%a %%U" "$(dirname "$f")" > /tmp/pip-dir.$n; stat -c "%%a %%U" "$f" > /tmp/pip-file.$n; }\n'
          '%s\n' % (tag, 'exit ${VENV_PIP_RC:-0}' if tag == 'venv' else 'exit 0'), 0o755)


def run_pip(venv_rc=0):
    for p in ('/tmp/pip-n', '/tmp/pip-calls') + tuple('/tmp/pip-req.%d' % i for i in range(1, 6)) + tuple('/tmp/pip-dir.%d' % i for i in range(1, 6)) + tuple('/tmp/pip-file.%d' % i for i in range(1, 6)):
        rmrf(p)
    for d in os.listdir('/tmp'):
        if d.startswith('irongate-req.'):
            rmrf('/tmp/' + d)
    rmrf('/opt/irongate')
    os.makedirs('/opt/irongate/venv/bin')
    pip_shim('/opt/irongate/venv/bin/pip', 'venv')
    pip_shim(SHIM + '/pip3', 'sys')
    write(SHIM + '/python3', '#!/bin/sh\n[ "$1" = -m ] && [ "$2" = venv ] && exit 0\nexec /usr/local/bin/python3 "$@"\n', 0o755)
    rc, out = sh(COLORS + 'set -e\n' + need(PIP, 'pip block'), env={'VENV_PIP_RC': str(venv_rc)})
    calls = read('/tmp/pip-calls').decode().strip().split('\n') if os.path.exists('/tmp/pip-calls') else []
    return rc, out, calls


def parse_req(path):
    pk, cur = {}, None
    for line in read(path).decode().split('\n'):
        if not line:
            continue
        pm = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.!+_-]*)( \\)?', line)
        hm = re.fullmatch(r'    --hash=sha256:([0-9a-f]{64})( \\)?', line)
        if pm:
            cur = pm.group(1)
            pk[cur] = []
        elif hm and cur:
            pk[cur].append(hm.group(1))
        else:
            return None
    return pk


check('PIP the pip block is found in the installer', PIP is not None)
if PIP is not None:
    rc, out, calls = run_pip(0)
    check('PIP block runs (exit 0) and calls the venv pip, then pip3 once', rc == 0 and len(calls) == 2 and calls[0].startswith('venv ') and calls[1].startswith('sys '), 'rc=%s calls=%s %s' % (rc, calls, out[-200:]))
    check('PIP every pip call is `--require-hashes -r <file>` and nothing is installed by name', all('--require-hashes' in c and ' -r /tmp/irongate-req.' in c and 'pyyaml' not in c for c in calls), str(calls))
    check('PIP the venv call has no --break-system-packages, the system call has it', calls and '--break-system-packages' not in calls[0] and all('--break-system-packages' in c for c in calls[1:]), str(calls))
    v = parse_req('/tmp/pip-req.1') if os.path.exists('/tmp/pip-req.1') else None
    s = parse_req('/tmp/pip-req.2') if os.path.exists('/tmp/pip-req.2') else None
    check('PIP the list handed to the venv pip pins 14 packages, each ==version with >= 1 sha256',
          v is not None and len(v) == 14 and all(h for h in v.values()) and {'PyYAML', 'scapy', 'netifaces'} <= set(v), str(sorted(v) if v else v))
    check('PIP the list handed to the system pip3 pins PyYAML, scapy, netifaces, each with >= 1 sha256',
          s is not None and set(s) == {'PyYAML', 'scapy', 'netifaces'} and all(h for h in s.values()), str(sorted(s) if s else s))
    check('PIP the venv list pins PyYAML 6.0.3 / scapy 2.7.0 / netifaces 0.11.0 (the live versions)',
          os.path.exists('/tmp/pip-req.1') and all(x in read('/tmp/pip-req.1').decode() for x in ('PyYAML==6.0.3', 'scapy==2.7.0', 'netifaces==0.11.0')))
    check('PIP the list is in a root-only directory (0700, root) while pip reads it', os.path.exists('/tmp/pip-dir.1') and read('/tmp/pip-dir.1').decode().strip() == '700 root', read('/tmp/pip-dir.1') if os.path.exists('/tmp/pip-dir.1') else 'no call')
    check('PIP the temporary directory is gone afterwards', not [d for d in os.listdir('/tmp') if d.startswith('irongate-req.')], str([d for d in os.listdir('/tmp') if d.startswith('irongate-req.')]))
    rc, out, calls = run_pip(1)
    check('PIP venv pip fails: the system pip3 fallback runs (with its own list), then the break-system-packages install - block still exits 0',
          rc == 0 and len(calls) == 3 and calls[0].startswith('venv ') and calls[1].startswith('sys ') and calls[2].startswith('sys '), 'rc=%s calls=%s' % (rc, calls))
    s2 = parse_req('/tmp/pip-req.2') if os.path.exists('/tmp/pip-req.2') else None
    check('PIP ... the fallback installs from the system list, not the venv list', s2 is not None and set(s2) == {'PyYAML', 'scapy', 'netifaces'}, str(s2 and sorted(s2)))
rmrf('/opt/irongate', SHIM + '/pip3', SHIM + '/python3')

# ============================================================================== APT
CORE = ['dnsmasq', 'nginx', 'php-fpm', 'php-sqlite3', 'sqlite3', 'jq']
DEPS = ['python3', 'python3-pip', 'python3-venv', 'python3-dev', 'nftables', 'iptables', 'arptables', 'ebtables', 'bridge-utils', 'libpcap-dev', 'arp-scan', 'tcpdump', 'net-tools', 'conntrack', 'ipset']
write(SHIM + '/dpkg', '#!/bin/bash\n[ "$1" = -s ] || exit 2\n'
      'if grep -qx "$2" /tmp/pkgs-installed 2>/dev/null; then printf "Package: %s\\nStatus: install ok installed\\nPriority: optional\\n" "$2"; exit 0; fi\n'
      'if grep -qx "$2" /tmp/pkgs-config 2>/dev/null; then printf "Package: %s\\nStatus: deinstall ok config-files\\nPriority: optional\\n" "$2"; exit 0; fi\n'
      'echo "dpkg-query: package \'$2\' is not installed and no information is available" >&2; exit 1\n', 0o755)
write(SHIM + '/apt', '#!/bin/bash\necho "apt $*" >> /tmp/apt.log\nexit 0\n', 0o755)
write(SHIM + '/apt-get', '#!/bin/bash\necho "apt-get $*" >> /tmp/apt.log\n[ -n "${APT_GET_FAIL:-}" ] && exit 100\nexit 0\n', 0o755)


def run_apt(installed, config=(), env=None):
    rmrf('/tmp/apt.log')
    write('/tmp/pkgs-installed', '\n'.join(installed) + '\n')
    write('/tmp/pkgs-config', '\n'.join(config) + '\n')
    rc, out = sh(COLORS + 'set -e\n' + need(APT, 'apt block'), env=env)
    log = read('/tmp/apt.log').decode().strip().split('\n') if os.path.exists('/tmp/apt.log') else []
    return rc, out, log


check('APT the apt block is found in the installer', APT is not None)
if APT is not None:
    rc, out, log = run_apt(CORE + DEPS)
    check('APT everything installed: no apt call at all (no update, no install, no upgrade)', rc == 0 and log == [], 'rc=%s log=%s' % (rc, log))
    rc, out, log = run_apt([p for p in CORE + DEPS if p != 'nftables'])
    check('APT one dependency missing: `apt update`, then apt-get install -y nftables and nothing else', rc == 0 and log == ['apt update', 'apt-get install -y nftables'], 'rc=%s log=%s' % (rc, log))
    rc, out, log = run_apt([p for p in CORE + DEPS if p != 'jq'])
    check('APT one core package missing: `apt update`, then apt-get install -y jq', rc == 0 and log == ['apt update', 'apt-get install -y jq'], 'rc=%s log=%s' % (rc, log))
    rc, out, log = run_apt([p for p in CORE + DEPS if p not in ('jq', 'conntrack', 'nginx')])
    check('APT several missing: one install per group, only the missing names, in order',
          rc == 0 and log == ['apt update', 'apt-get install -y nginx jq', 'apt-get install -y conntrack'], 'rc=%s log=%s' % (rc, log))
    present = [p for p in CORE + DEPS if p not in ('jq', 'conntrack', 'nginx')]
    check('APT no installed package is named in any install line', not any(p in l.split() for l in log if 'install' in l for p in present), str(log))
    rc, out, log = run_apt([p for p in CORE + DEPS if p != 'nginx'], config=['nginx'])
    check('APT a package removed but with its configuration files left ("deinstall ok config-files") counts as missing',
          rc == 0 and log == ['apt update', 'apt-get install -y nginx'], 'rc=%s log=%s' % (rc, log))
    rc, out, log = run_apt([])
    check('APT nothing installed: `apt update`, the plain install of the whole core set, then the dependencies',
          rc == 0 and log == ['apt update', 'apt install -y dnsmasq nginx php-fpm php-sqlite3 sqlite3 jq', 'apt-get install -y ' + ' '.join(DEPS)], 'rc=%s log=%s' % (rc, log))
    rc, out, log = run_apt([p for p in CORE + DEPS if p != 'nftables'], env={'APT_GET_FAIL': '1'})
    check('APT a dependency install that fails does not stop the installer (as before: || true)', rc == 0, 'rc=%s' % rc)
    rc, out, log = run_apt([p for p in CORE + DEPS if p != 'jq'], env={'APT_GET_FAIL': '1'})
    check('APT a core install that fails does stop the installer (set -e, as before)', rc != 0, 'rc=%s' % rc)
rmrf(SHIM + '/dpkg', SHIM + '/apt', SHIM + '/apt-get', '/tmp/pkgs-installed', '/tmp/pkgs-config', '/tmp/apt.log')

# ============================================================================== DB: dhcp.db backup and mode
WEB = '/var/www/irongate'
DB = WEB + '/dhcp.db'


def web_fresh():
    rmrf(WEB, '/etc/dnsmasq.d', '/etc/dnsmasq.conf')
    os.makedirs(WEB)
    os.makedirs('/etc/dnsmasq.d')
    write('/etc/dnsmasq.conf', '', 0o644)
    for f in ('api.php', 'index.php'):
        write(WEB + '/' + f, '<?php // %s\n' % f, 0o644)


def run_db(mode, created=False, umask='022', mutate=''):
    web_fresh()
    if not created:
        write(DB, 'SQLITE-CONTENT\n', mode)
    script = COLORS + 'set -e\n' + (need(WH, 'web helper')) + '\n'
    if created:
        script += 'IG_DB_MODE_BEFORE=""; IG_DB_CREATED=1; IG_DB_BACKUP=""\n'
        write(DB, 'SQLITE-CONTENT\n', 0o644)
    else:
        script += need(DBHEAD, 'db backup head') + '\n'
    script += mutate + need(W, 'permission step') + '\n' + need(DBPOST, 'dhcp.db mode block') + '\n'
    return sh(script, umask=umask)


def backups():
    return sorted(f for f in os.listdir(WEB) if f.startswith('dhcp.db.bak.'))


check('DB the dhcp.db backup head and the dhcp.db mode block are found in the installer', DBHEAD is not None and DBPOST is not None)
if DBHEAD is not None and DBPOST is not None and W is not None and WH is not None:
    for mode, want in ((0o640, '33:33:640'), (0o600, '33:33:600'), (0o644, '33:33:644'), (0o664, '33:33:664'), (0o660, '33:33:660')):
        rc, out = run_db(mode)
        check('DB existing dhcp.db %o keeps its mode through the permission step (www-data:www-data %s)' % (mode, want.split(':')[2]), rc == 0 and st(DB) == want, 'rc=%s now %s %s' % (rc, st(DB), out[-200:]))
    rc, out = run_db(0o666)
    check('DB an old world-writable dhcp.db (0666) comes out 0664, never world-writable', rc == 0 and st(DB) == '33:33:664', 'rc=%s %s' % (rc, st(DB)))
    rc, out = run_db(0o4755)
    check('DB a setuid bit on dhcp.db is not preserved', rc == 0 and st(DB) == '33:33:755', st(DB))
    rc, out = run_db(0o640)
    bk = backups()
    check('DB this run made exactly one backup, root:root 0600 (the permission step had made it 0755 www-data)',
          rc == 0 and len(bk) == 1 and st(WEB + '/' + bk[0]) == '0:0:600', 'rc=%s %s %s' % (rc, [(b, st(WEB + '/' + b)) for b in bk], out[-200:]))
    check('DB the backup holds the database content', len(bk) == 1 and read(WEB + '/' + bk[0]) == b'SQLITE-CONTENT\n')
    rc, out = run_db(0o640, umask='000')
    bk = backups()
    check('DB the backup is 0600 even under a caller umask of 000', rc == 0 and len(bk) == 1 and st(WEB + '/' + bk[0]) == '0:0:600', '%s' % [(b, st(WEB + '/' + b)) for b in bk])
    rc, out = run_db(0, created=True)
    check('DB a dhcp.db created by this run is 0660 www-data:www-data, and there is no backup', rc == 0 and st(DB) == '33:33:660' and backups() == [], 'rc=%s %s %s' % (rc, st(DB), backups()))
    # a link planted in place of the backup between the copy and the mode step: nothing it points at is touched
    write('/root/ig-victim', 'VICTIM\n', 0o600)
    rc, out = run_db(0o640, mutate='b=$(ls %s/dhcp.db.bak.* | head -1); rm -f "$b"; ln -s /root/ig-victim "$b"\n' % WEB)
    check('DB a backup replaced by a link to a root file: that file is not chowned/chmodded, the installer goes on, dhcp.db mode still restored',
          rc == 0 and st('/root/ig-victim') == '0:0:600' and st(DB) == '33:33:640', 'rc=%s victim=%s db=%s %s' % (rc, st('/root/ig-victim'), st(DB), out[-200:]))
    rmrf('/root/ig-victim')
rmrf(WEB, '/etc/dnsmasq.d', '/etc/dnsmasq.conf')

# ============================================================================== OPT: /opt/irongate mode pass
def opt_tree():
    rmrf('/opt/irongate')
    for d, m in (('', 0o700), ('/venv', 0o755), ('/venv/lib', 0o700), ('/sub777', 0o777), ('/.update', 0o700), ('/audit-bak', 0o755), ('/audit-bak/nested', 0o700)):
        os.makedirs('/opt/irongate' + d, exist_ok=True)
        os.chmod('/opt/irongate' + d, m)
    for f, m in (('/irongate.py', 0o666), ('/secret.bak', 0o600), ('/run.sh', 0o755), ('/venv/lib/x.py', 0o640), ('/sub777/w', 0o777), ('/.update/irongate-install.sh', 0o700),
                 ('/audit-bak/config.yaml.bak.1', 0o600), ('/audit-bak/loose', 0o666), ('/audit-bak/nested/key', 0o600)):
        write('/opt/irongate' + f, 'x\n', m)
    os.symlink('/etc/hostname', '/opt/irongate/link-to-outside')


def snap(root='/opt/irongate'):
    out = {}
    for dp, dn, fn in os.walk(root):
        for n in dn + fn:
            p = os.path.join(dp, n)
            if not os.path.islink(p):
                out[p] = stat.S_IMODE(os.lstat(p).st_mode)
    out[root] = stat.S_IMODE(os.lstat(root).st_mode)
    return out


check('OPT the /opt/irongate mode pass is found in the installer', OPT is not None and 'chmod -R 755 /opt/irongate' not in TEXT)
if OPT is not None:
    opt_tree()
    before = snap()
    host_before = st('/etc/hostname')
    rc, out = sh(COLORS + 'set -e\n' + OPT)
    after = snap()
    check('OPT the pass exits 0', rc == 0, out[-300:])
    gained = {p: (oct(before[p]), oct(after[p])) for p in before if p != '/opt/irongate' and p in after and (after[p] & ~before[p])}
    check('OPT no file or directory below /opt/irongate gains a permission bit it did not have', not gained, str(gained))
    check('OPT /opt/irongate itself is 0755', st('/opt/irongate') == '0:0:755', st('/opt/irongate'))
    check('OPT a 0600 file stays 0600 (a backup, anywhere)', st('/opt/irongate/secret.bak') == '0:0:600', st('/opt/irongate/secret.bak'))
    check('OPT the updater staging directory and the installer in it stay 0700', st('/opt/irongate/.update') == '0:0:700' and st('/opt/irongate/.update/irongate-install.sh') == '0:0:700')
    check('OPT directories lose group/other write only (700 stays 700, 755 stays 755, 777 -> 755)', st('/opt/irongate/venv/lib') == '0:0:700' and st('/opt/irongate/venv') == '0:0:755' and st('/opt/irongate/sub777') == '0:0:755',
          '%s %s %s' % (st('/opt/irongate/venv/lib'), st('/opt/irongate/venv'), st('/opt/irongate/sub777')))
    check('OPT files lose group/other write only (666 -> 644, 777 -> 755, 755 stays, 640 stays)',
          st('/opt/irongate/irongate.py') == '0:0:644' and st('/opt/irongate/sub777/w') == '0:0:755' and st('/opt/irongate/run.sh') == '0:0:755' and st('/opt/irongate/venv/lib/x.py') == '0:0:640',
          '%s %s' % (st('/opt/irongate/irongate.py'), st('/opt/irongate/sub777/w')))
    ab_before = {p: m for p, m in before.items() if p.startswith('/opt/irongate/audit-bak')}
    ab_after = {p: m for p, m in after.items() if p.startswith('/opt/irongate/audit-bak')}
    check('OPT /opt/irongate/audit-bak is not entered: every mode in it is exactly as it was (a 666 file stays 666, a 700 directory stays 700)', ab_before == ab_after, '%s -> %s' % (ab_before, ab_after))
    check('OPT a symlink in the tree is not followed (the file it points at keeps its mode)', st('/etc/hostname') == host_before)
rmrf('/opt/irongate')

# ============================================================================== E: /etc/irongate modes (A1-A3)
def meta(path):
    s_ = os.stat(path, follow_symlinks=False)
    return (s_.st_ino, s_.st_mtime_ns, s_.st_size, s_.st_uid, s_.st_gid, stat.S_IMODE(s_.st_mode))


def etc_dir(mode=None, owner=(0, 33)):
    rmrf('/etc/irongate', '/etc/.irongate-stage')
    if mode is not None:
        os.makedirs('/etc/irongate')
        os.chown('/etc/irongate', *owner)
        os.chmod('/etc/irongate', mode)


PRE = 'INTERFACE=eth0; CURRENT_IP=192.168.1.2; CURRENT_GATEWAY=192.168.1.1; ADMIN_LAN_IP=\nset -e\n'
check('E the /etc/irongate creation snippet is found in the installer (the installer of c866e4c has none: plain mkdir -p)', ETCDIR is not None)
check('E the permissions block and the config.yaml generation are found in the installer', PERM is not None and CFGGEN is not None and HELPERS is not None and AUTH is not None)
if PERM is not None and CFGGEN is not None and HELPERS is not None and AUTH is not None:
    # --- A1: the directory
    code = [l for l in PERM.split('\n') if l.strip() and not l.lstrip().startswith('#')]
    check('E A1 the permissions block never chmods /etc/irongate (no `chmod ... /etc/irongate` line, no 775 anywhere in its code)',
          not [l for l in code if re.match(r'^\s*chmod\b.*\s/etc/irongate\s*$', l)] and not [l for l in code if '775' in l], '\n'.join(code[-8:]))
    for um in ('022', '000', '077'):
        etc_dir()
        rc, out = sh(COLORS + 'set -e\n' + (ETCDIR or 'mkdir -p /etc/irongate\n'), umask=um)
        check('E A1 /etc/irongate is created root:www-data 0750 (caller umask %s)' % um, rc == 0 and st('/etc/irongate') == '0:33:750', 'rc=%s %s %s' % (rc, st('/etc/irongate'), out[-200:]))
    for mode, owner in ((0o775, (0, 33)), (0o755, (0, 0)), (0o700, (0, 0)), (0o750, (0, 33)), (0o2770, (0, 33)), (0o777, (0, 33))):
        etc_dir(mode, owner)
        rc, out = sh(COLORS + 'set -e\n' + (ETCDIR or 'mkdir -p /etc/irongate\n'))
        check('E A1 an existing /etc/irongate %o (owner %d:%d) is left as it is by the creation snippet' % (mode, owner[0], owner[1]), rc == 0 and st('/etc/irongate') == '%d:%d:%o' % (owner[0], owner[1], mode), 'rc=%s %s' % (rc, st('/etc/irongate')))
    for mode in (0o775, 0o755, 0o700, 0o750, 0o2770):
        etc_dir(mode, (0, 0))
        rc, out = sh(COLORS + 'set -e\n' + HELPERS + PERM)
        check('E A1 permissions block on an existing %o directory: root:www-data (as before), mode kept, never widened to 0775' % mode, rc == 0 and st('/etc/irongate') == '0:33:%o' % mode, 'rc=%s %s %s' % (rc, st('/etc/irongate'), out[-200:]))

    # --- A2, permissions block: config.yaml
    etc_dir(0o750)
    rc, out = sh(COLORS + 'set -e\n' + HELPERS + PERM)
    check('E A2 block B: no config.yaml -> an empty root:www-data 0640 placeholder', rc == 0 and st('/etc/irongate/config.yaml') == '0:33:640' and os.path.getsize('/etc/irongate/config.yaml') == 0, '%s %s' % (st('/etc/irongate/config.yaml'), out[-200:]))
    etc_dir(0o750)
    write('/etc/irongate/config.yaml', '', 0o600, 33, 33)
    rc, out = sh(COLORS + 'set -e\n' + HELPERS + PERM)
    check('E A2 block B: an existing empty config.yaml keeps its mode (0600), owner root:www-data', rc == 0 and st('/etc/irongate/config.yaml') == '0:33:600', st('/etc/irongate/config.yaml'))
    for mode in (0o400, 0o600, 0o640, 0o644, 0o660, 0o664, 0o666):
        etc_dir(0o750)
        write('/etc/irongate/config.yaml', 'mode: "single"\nkeep: me\n', mode, 33, 33)
        before = meta('/etc/irongate/config.yaml')
        rc, out = sh(COLORS + 'set -e\n' + HELPERS + PERM)
        after = meta('/etc/irongate/config.yaml')
        check('E A2 block B: a non-empty config.yaml %o keeps content, inode and mtime and loses every other bit (%o -> %o), owner root:www-data' % (mode, mode, mode & ~0o007),
              rc == 0 and read('/etc/irongate/config.yaml') == b'mode: "single"\nkeep: me\n' and after[:3] == before[:3] and after[3:] == (0, 33, mode & ~0o007), 'rc=%s %s -> %s %s' % (rc, before, after, out[-200:]))
    # NEW (operator ruling, item E): an existing 0640 config.yaml has no `other` bit to lose, so it stays
    # exactly 0640 -- owner, group, mode, inode, mtime and bytes are all untouched.
    etc_dir(0o750)
    write('/etc/irongate/config.yaml', 'mode: "single"\nkeep: me\n', 0o640, 0, 33)
    before = meta('/etc/irongate/config.yaml')
    rc, out = sh(COLORS + 'set -e\n' + HELPERS + PERM)
    after = meta('/etc/irongate/config.yaml')
    check('E A2 block B: an existing 0640 config.yaml stays exactly 0640 (owner, group, mode, inode, mtime, bytes)',
          rc == 0 and read('/etc/irongate/config.yaml') == b'mode: "single"\nkeep: me\n' and after == before and st('/etc/irongate/config.yaml') == '0:33:640', 'rc=%s %s -> %s %s' % (rc, before, after, out[-200:]))

    # --- A2, config.yaml generation
    def gen_cfg():
        return sh(COLORS + PRE + HELPERS + CFGGEN)
    etc_dir(0o750)
    rc, out = gen_cfg()
    check('E A2 block C: no config.yaml -> generated, root:www-data 0640, complete, no staging directory',
          rc == 0 and st('/etc/irongate/config.yaml') == '0:33:640' and b'# Irongate Configuration' in read('/etc/irongate/config.yaml') and b'devices: []' in read('/etc/irongate/config.yaml') and not os.path.exists('/etc/.irongate-stage'), '%s %s' % (st('/etc/irongate/config.yaml'), out[-200:]))
    check('E A1 block C leaves the directory as it is (0750)', st('/etc/irongate') == '0:33:750', st('/etc/irongate'))
    for mode in (0o600, 0o640, 0o660):
        etc_dir(0o750)
        write('/etc/irongate/config.yaml', '', mode, 33, 33)
        rc, out = gen_cfg()
        check('E A2 block C: an EMPTY config.yaml (%o, the installer\'s own placeholder) counts as absent: generated, root:www-data 0640' % mode,
              rc == 0 and st('/etc/irongate/config.yaml') == '0:33:640' and b'# Irongate Configuration' in read('/etc/irongate/config.yaml'), '%s %s' % (st('/etc/irongate/config.yaml'), out[-200:]))
    for content in (b'x', b'\n', b' ', b'# only a comment\n', b'mode: "single"\nnetwork:\n  interface: "wlan7"\nlayers:\n  arp_defense: false\ndevices:\n  - mac: "aa:bb:cc:dd:ee:ff"\n    ip: "10.0.0.9"\n    zone: "x"\n'):
        for mode, owner in ((0o600, (33, 33)), (0o640, (0, 33)), (0o664, (0, 33)), (0o666, (1000, 1000))):
            etc_dir(0o750)
            write('/etc/irongate/config.yaml', content, mode, *owner)
            before = meta('/etc/irongate/config.yaml')
            rc, out = gen_cfg()
            after = meta('/etc/irongate/config.yaml')
            check('E A2 block C: a non-empty config.yaml (%d bytes %r, %d:%d %o) is left byte for byte: same inode, mtime, owner and mode, nothing stray' % (len(content), content[:14], owner[0], owner[1], mode),
                  rc == 0 and read('/etc/irongate/config.yaml') == content and after == before and sorted(os.listdir('/etc/irongate')) == ['config.yaml'] and not os.path.exists('/etc/.irongate-stage'), 'rc=%s %s -> %s %s' % (rc, before, after, out[-200:]))

    # --- A3: auth.json (and access-control.json, which is unchanged: 0660)
    PHP_ENV = {'PATH': PHPSHIM + ':' + SHIM + ':/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
    os.makedirs(PHPSHIM, exist_ok=True)
    write(PHPSHIM + '/php', "#!/bin/bash\ncase \"$*\" in *password_hash*) printf '%s' '$2y$10$ShimHashShimHashShimHashShimHashShimHashShimHashSh' ;; *) printf '%s' '" + PW + "' ;; esac\n", 0o755)
    etc_dir(0o750)
    rc, out = sh(COLORS + PRE + HELPERS + AUTH, env=PHP_ENV)
    check('E A3 no auth.json -> created root:www-data 0640; access-control.json created 0660 (unchanged)', rc == 0 and st('/etc/irongate/auth.json') == '0:33:640' and st('/etc/irongate/access-control.json') == '0:33:660', '%s %s %s' % (st('/etc/irongate/auth.json'), st('/etc/irongate/access-control.json'), out[-200:]))
    check('E A1 the auth block leaves the directory as it is (0750)', st('/etc/irongate') == '0:33:750', st('/etc/irongate'))
    rmrf(PWFILE)
    for mode in (0o400, 0o600, 0o640, 0o644, 0o660, 0o664, 0o666):
        etc_dir(0o750)
        write('/etc/irongate/auth.json', '{"genuine":true}\n', mode, 33, 33)
        write('/etc/irongate/access-control.json', '{"acl":1}\n', mode, 33, 33)
        b_auth, b_acl = meta('/etc/irongate/auth.json'), meta('/etc/irongate/access-control.json')
        rc, out = sh(COLORS + PRE + HELPERS + AUTH, env=PHP_ENV)
        a_auth, a_acl = meta('/etc/irongate/auth.json'), meta('/etc/irongate/access-control.json')
        check('E A3 an existing auth.json %o keeps content, inode, mtime and mode (owner root:www-data)' % mode,
              rc == 0 and read('/etc/irongate/auth.json') == b'{"genuine":true}\n' and a_auth[:3] == b_auth[:3] and a_auth[3:] == (0, 33, mode), 'rc=%s %s -> %s %s' % (rc, b_auth, a_auth, out[-200:]))
        check('E A3 ... while an existing access-control.json (not part of item E) still ends root:www-data 0660 with its content (was %o)' % mode,
              rc == 0 and read('/etc/irongate/access-control.json') == b'{"acl":1}\n' and a_acl[3:] == (0, 33, 0o660), '%s' % (a_acl,))
    rmrf(PWFILE)

    # --- the whole sequence as the installer runs it, twice (an update is a re-run)
    etc_dir()
    seq = COLORS + PRE + HELPERS + (ETCDIR or 'mkdir -p /etc/irongate\n') + PERM + CFGGEN + AUTH
    rc1, out1 = sh(seq, env=PHP_ENV)
    first = {n: (meta('/etc/irongate/' + n), read('/etc/irongate/' + n)) for n in ('config.yaml', 'auth.json', 'access-control.json')} if rc1 == 0 else {}
    check('E first run on a machine without /etc/irongate: directory 0750, config.yaml/auth.json 0640, access-control.json 0660 (all root:www-data)',
          rc1 == 0 and st('/etc/irongate') == '0:33:750' and st('/etc/irongate/config.yaml') == '0:33:640' and st('/etc/irongate/auth.json') == '0:33:640' and st('/etc/irongate/access-control.json') == '0:33:660' and os.path.getsize('/etc/irongate/config.yaml') > 0,
          'rc=%s %s %s %s %s %s' % (rc1, st('/etc/irongate'), st('/etc/irongate/config.yaml'), st('/etc/irongate/auth.json'), st('/etc/irongate/access-control.json'), out1[-300:]))
    rmrf(PWFILE)
    rc2, out2 = sh(seq, env=PHP_ENV)
    second = {n: (meta('/etc/irongate/' + n), read('/etc/irongate/' + n)) for n in ('config.yaml', 'auth.json', 'access-control.json')} if rc2 == 0 else {}
    check('E re-run (the updater): config.yaml, auth.json and access-control.json are untouched (inode, mtime, mode, bytes), directory still 0750, nothing stray',
          rc2 == 0 and first and second == first and st('/etc/irongate') == '0:33:750' and sorted(os.listdir('/etc/irongate')) == ['access-control.json', 'auth.json', 'config.yaml'], 'rc=%s %s' % (rc2, out2[-300:]))
    # an operator who saved a config through the dashboard and tightened the directory to 0700: the next update changes neither
    write('/etc/irongate/config.yaml', 'dashboard: saved\n', 0o640, 0, 33)
    os.chmod('/etc/irongate', 0o700)
    m_before = meta('/etc/irongate/config.yaml')
    rc3, out3 = sh(seq, env=PHP_ENV)
    check('E re-run after a dashboard save and chmod 700 of the directory: both are kept', rc3 == 0 and read('/etc/irongate/config.yaml') == b'dashboard: saved\n' and meta('/etc/irongate/config.yaml') == m_before and st('/etc/irongate') == '0:33:700', 'rc=%s %s' % (rc3, out3[-300:]))
    rmrf('/etc/irongate', '/etc/.irongate-stage', PWFILE, PHPSHIM)

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
