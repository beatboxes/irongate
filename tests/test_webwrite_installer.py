#!/usr/bin/env python3
"""
irongate web tier root helper: the installer blocks.

Cuts the two blocks out of irongate-install.sh and runs them as root against the real paths (inside a
throw-away container):
  helper   /usr/local/sbin/irongate-webwrite is installed from its heredoc root:root 0755, and only replaced
           when the content differs (a re-run with the same bytes leaves the file's mtime alone); no temp file
           is left behind.
  lockout  /var/lib/irongate/lockout (www-data:www-data 0700) and lockout.json (www-data:www-data 0600, the
           zero state) are created only when absent; an existing directory, file or symlink is never touched;
           /var/lib/irongate's own mode is never changed.

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
        python:3.12-slim python3 -I tests/test_webwrite_installer.py irongate-install.sh

Exit status 0 = every case passed. Against the installer of bcab19c the blocks do not exist, so it fails.
"""

import os
import re
import shutil
import stat
import subprocess
import sys

if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
    sys.exit('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
if os.geteuid() != 0:
    sys.exit('must run as root')

INSTALLER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'irongate-install.sh')
with open(INSTALLER, encoding='utf-8', newline='') as fh:
    TEXT = fh.read()

HELPER = '/usr/local/sbin/irongate-webwrite'
NEW = '/usr/local/sbin/.irongate-webwrite.new'
LOCKDIR = '/var/lib/irongate/lockout'
LOCKFILE = LOCKDIR + '/lockout.json'
LIB = '/var/lib/irongate'
ZERO = '{"version":1,"failed_attempts":0,"first_failed_at":0,"locked_until":0}\n'

pass_n = fail_n = 0


def check(name, cond, detail=''):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print('PASS  ' + name)
    else:
        fail_n += 1
        print('FAIL  ' + name + ('  -- ' + detail if detail else ''))


def between(start, end):
    i = TEXT.find(start)
    j = TEXT.find(end, i + 1)
    if i < 0 or j < 0:
        return None
    return TEXT[i:j + len(end)]


def read(path):
    with open(path, 'rb') as fh:
        return fh.read()


def st(path):
    s = os.lstat(path)
    return '%d:%d:%o' % (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def run(block):
    return subprocess.run(['sh', '-c', 'set -e\n' + block], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


HELPER_BLOCK = between('# ---- web root helper: begin ----', '# ---- web root helper: end ----')
LOCKOUT_BLOCK = between('# ---- web lockout state: begin ----', '# ---- web lockout state: end ----')
check('installer has the web root helper block', HELPER_BLOCK is not None)
check('installer has the web lockout state block', LOCKOUT_BLOCK is not None)

# the heredoc body, exactly as the installer carries it
heredoc = None
if HELPER_BLOCK:
    m = re.search(r"cat > \"\$IG_WEBWRITE_NEW\" << 'IRONGATE_WEBWRITE'\n(.*?)\nIRONGATE_WEBWRITE\n", HELPER_BLOCK, re.S)
    if m:
        heredoc = (m.group(1) + '\n').encode()
check('the helper heredoc is present and non-empty', heredoc is not None and len(heredoc) > 1000,
      '%d bytes' % len(heredoc or b''))

# ============================================================================== helper install
if HELPER_BLOCK and heredoc:
    for path in (HELPER, NEW):
        if os.path.lexists(path):
            os.unlink(path)
    r = run(HELPER_BLOCK)
    check('helper block: first run installs %s root:root 0755' % HELPER,
          r.returncode == 0 and os.path.isfile(HELPER) and st(HELPER) == '0:0:755', r.stdout.decode()[-300:])
    check('helper block: the installed file is the heredoc byte for byte', os.path.isfile(HELPER) and read(HELPER) == heredoc)
    check('helper block: no temp file is left behind', not os.path.lexists(NEW))

    before = os.stat(HELPER).st_mtime_ns
    r = run(HELPER_BLOCK)
    check('helper block: a re-run with the same bytes leaves the file (and its mtime) alone',
          r.returncode == 0 and os.stat(HELPER).st_mtime_ns == before and read(HELPER) == heredoc, r.stdout.decode()[-300:])

    with open(HELPER, 'ab') as fh:
        fh.write(b'# stale\n')
    r = run(HELPER_BLOCK)
    check('helper block: a different file is replaced by the heredoc, still root:root 0755',
          r.returncode == 0 and read(HELPER) == heredoc and st(HELPER) == '0:0:755' and not os.path.lexists(NEW),
          r.stdout.decode()[-300:])

# ============================================================================== lockout state
if LOCKOUT_BLOCK:
    shutil.rmtree(LOCKDIR, ignore_errors=True)
    if os.path.exists(LIB):
        os.chmod(LIB, 0o711)
    else:
        os.makedirs(LIB, 0o711)
    os.chmod(LIB, 0o711)
    r = run(LOCKOUT_BLOCK)
    check('lockout block: first run creates the directory www-data:www-data 0700',
          r.returncode == 0 and os.path.isdir(LOCKDIR) and st(LOCKDIR) == '33:33:700', r.stdout.decode()[-300:])
    check('lockout block: first run creates lockout.json www-data:www-data 0600 with the zero state',
          os.path.isfile(LOCKFILE) and st(LOCKFILE) == '33:33:600' and read(LOCKFILE).decode() == ZERO,
          '%s %r' % (st(LOCKFILE) if os.path.exists(LOCKFILE) else 'missing', read(LOCKFILE)[:80] if os.path.exists(LOCKFILE) else b''))
    check('lockout block: /var/lib/irongate keeps its own mode', st(LIB) == '0:0:711', st(LIB))

    with open(LOCKFILE, 'wb') as fh:
        fh.write(b'{"version":1,"failed_attempts":4,"first_failed_at":123,"locked_until":0}\n')
    os.chmod(LOCKFILE, 0o644)
    os.chmod(LOCKDIR, 0o750)
    before = os.stat(LOCKFILE).st_mtime_ns
    r = run(LOCKOUT_BLOCK)
    check('lockout block: an existing file is never rewritten or re-moded',
          r.returncode == 0 and os.stat(LOCKFILE).st_mtime_ns == before and stat.S_IMODE(os.stat(LOCKFILE).st_mode) == 0o644
          and b'"failed_attempts":4' in read(LOCKFILE), r.stdout.decode()[-300:])
    check('lockout block: an existing directory is never re-moded', stat.S_IMODE(os.stat(LOCKDIR).st_mode) == 0o750)
    check('lockout block: /var/lib/irongate is still untouched', st(LIB) == '0:0:711', st(LIB))

    os.unlink(LOCKFILE)
    os.symlink('/tmp/webwrite-installer-target', LOCKFILE)
    with open('/tmp/webwrite-installer-target', 'wb') as fh:
        fh.write(b'not ours\n')
    r = run(LOCKOUT_BLOCK)
    check('lockout block: a planted symlink is not written through (and is left alone)',
          r.returncode == 0 and os.path.islink(LOCKFILE) and read('/tmp/webwrite-installer-target') == b'not ours\n',
          r.stdout.decode()[-300:])
    os.unlink(LOCKFILE)

# ============================================================================== sudoers lines
TREE = os.path.dirname(INSTALLER)
template_path = os.path.join(TREE, 'templates', 'sudoers-dnsmasq-web.template')
template = read(template_path).decode() if os.path.isfile(template_path) else ''
m = re.search(r'cat << EOF > "\$IG_SUDOERS_WEB_NEW"\n(.*?)\nEOF\n', TEXT, re.S)
sudo_heredoc = (m.group(1) + '\n') if m else ''
for label, body in (('template', template), ('installer heredoc', sudo_heredoc)):
    for verb in ('config-apply', 'auth-set-credentials', 'auth-set-username'):
        line = 'www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite ' + verb
        check('sudoers (%s): exactly one rule for %s, (root), exact path, no wildcard' % (label, verb),
              body.split('\n').count(line) == 1 and '*' not in line)
    check('sudoers (%s): no other irongate-webwrite rule' % label,
          sum(1 for l in body.split('\n') if 'irongate-webwrite' in l) == 3)

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
