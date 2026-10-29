#!/usr/bin/env python3
"""
Irongate installer hardening (item E): static and parity checks on irongate-install.sh and its extracted tree.

Nothing is executed and nothing is written, so this needs no root and no container, but it is run in one like the other
tests:

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w python:3.12-slim \
        python3 -I tests/test_item_e_static.py irongate-install.sh

What it pins
  parity   every runtime file the installer writes from a heredoc is byte-identical to its copy in the tree (api.php,
           index.php, session_check.php, irongate-updater.sh, the sudoers file and the new updater unit)
  sudoers  the dnsmasq-web sudoers file is exactly the expected 22 lines: the `--force` line is gone, the new line is the
           byte-exact operator-ruled one, in the old line's place, without a wildcard, and the command is the one api.php execs
  unit     irongate-updater-now.service is a oneshot that runs the updater with --force and has no [Install] section
  pip      every pip install of the installer is `--require-hashes -r <list>`; each list pins every package to ==version
           and at least one sha256
  curl     every curl of the installer and of the updater has --max-time
  secrets  the generated admin password is never echoed

Exit status 0 = every case passed. Against an installer from before the change (c866e4c) it fails.
"""
import os
import re
import subprocess
import sys

if os.environ.get('IRONGATE_TEST_SANDBOX') != '1':
    sys.exit('refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container')
INSTALLER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'irongate-install.sh')
TREE = os.path.dirname(INSTALLER)
TEXT = open(INSTALLER, encoding='utf-8', newline='').read()
LINES = TEXT.split('\n')

pass_n = fail_n = 0


def check(name, cond, detail=''):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print('PASS  ' + name)
    else:
        fail_n += 1
        print('FAIL  ' + name + ('  -- ' + detail if detail else ''))


def read(rel):
    with open(os.path.join(TREE, rel), encoding='utf-8', newline='') as fh:
        return fh.read()


# ---- heredocs of the installer: `cat > PATH << 'M'` and `cat << 'M' > PATH` (quoted or not) ----
FORM_A = re.compile(r"^\s*cat\s+>>?\s+(\S+)\s+<<\s+(')?([A-Za-z_][A-Za-z0-9_]*)\2?\s*$")
FORM_B = re.compile(r"^\s*cat\s+<<\s+(')?([A-Za-z_][A-Za-z0-9_]*)\1?\s+>>?\s+(\S+)\s*$")


def heredocs():
    out, i = [], 0
    while i < len(LINES):
        m = FORM_A.match(LINES[i])
        if m:
            target, marker = m.group(1), m.group(3)
        else:
            m = FORM_B.match(LINES[i])
            target, marker = (m.group(3), m.group(2)) if m else (None, None)
        if not target:
            i += 1
            continue
        j = i + 1
        body = []
        while j < len(LINES) and LINES[j] != marker:
            body.append(LINES[j])
            j += 1
        out.append((target.strip('"'), marker, '\n'.join(body) + '\n'))
        i = j + 1
    return out


HD = heredocs()


def heredoc(target_re):
    hits = [h for h in HD if re.fullmatch(target_re, h[0])]
    return hits[0][2] if len(hits) == 1 else None


# ============================================================================== parity
sync = subprocess.run([sys.executable, '-I', os.path.join(TREE, 'tools', 'heredoc_sync.py'), '--check'],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
check('parity: tools/heredoc_sync.py --check agrees', sync.returncode == 0, sync.stdout.decode()[-300:])

PAIRS = [
    ('api.php', r'/var/www/irongate/api\.php', 'web/api.php'),
    ('index.php', r'/var/www/irongate/index\.php', 'web/index.php'),
    ('session_check.php', r'/var/www/irongate/session_check\.php', 'web/session_check.php'),
    ('irongate-updater.sh', r'/opt/irongate/irongate-updater\.sh', 'src/irongate-updater.sh'),
    ('sudoers dnsmasq-web', r'/etc/sudoers\.d/dnsmasq-web|\$IG_SUDOERS_WEB_NEW', 'templates/sudoers-dnsmasq-web.template'),
    ('irongate-updater-now.service', r'/etc/systemd/system/irongate-updater-now\.service', 'templates/irongate-updater-now.service.template'),
]
for label, target_re, rel in PAIRS:
    body = heredoc(target_re)
    have = os.path.isfile(os.path.join(TREE, rel))
    check('parity: %s heredoc exists exactly once in the installer' % label, body is not None)
    check('parity: %s == %s byte for byte' % (rel, label + ' heredoc'), body is not None and have and read(rel) == body,
          'tree file %s, heredoc %s' % ('present' if have else 'MISSING', 'present' if body is not None else 'MISSING'))

# ============================================================================== sudoers
EXPECTED_SUDOERS = '''www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload dnsmasq
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop irongate
www-data ALL=(ALL) NOPASSWD: /bin/systemctl enable irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl disable irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl start irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop irongate-updater.timer
www-data ALL=(ALL) NOPASSWD: /usr/bin/pkill -9 dnsmasq
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown dnsmasq\\:nogroup /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 644 /var/lib/dnsmasq/dnsmasq.leases
www-data ALL=(ALL) NOPASSWD: /usr/bin/chmod 664 /var/log/dnsmasq.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u dnsmasq *
www-data ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u irongate *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/arping *
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block irongate-updater-now.service
www-data ALL=(ALL) NOPASSWD: /usr/bin/touch /var/log/irongate-update.log
www-data ALL=(ALL) NOPASSWD: /usr/bin/chown www-data /var/log/irongate-update.log
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite config-apply
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-credentials
www-data ALL=(root) NOPASSWD: /usr/local/sbin/irongate-webwrite auth-set-username
'''
NEW_LINE = 'www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block irongate-updater-now.service'
sud_hd = heredoc(r'/etc/sudoers\.d/dnsmasq-web|\$IG_SUDOERS_WEB_NEW') or ''
sud_tpl = read('templates/sudoers-dnsmasq-web.template')
for label, body in (('installer heredoc', sud_hd), ('template', sud_tpl)):
    check('sudoers (%s): exactly the expected lines - only the --force line changed, nothing else' % label, body == EXPECTED_SUDOERS,
          'differs: %s' % [l for l in body.split('\n') if l not in EXPECTED_SUDOERS.split('\n')][:3])
    check('sudoers (%s): the old `bash irongate-updater.sh --force` rule is gone' % label,
          'irongate-updater.sh' not in body and '/bin/bash' not in body)
    check('sudoers (%s): the new rule is present exactly once, byte-exact' % label, body.split('\n').count(NEW_LINE) == 1)
    new = [l for l in body.split('\n') if 'irongate-updater-now' in l]
    check('sudoers (%s): the new rule has no wildcard and exactly one command with fixed arguments' % label,
          len(new) == 1 and '*' not in new[0] and new[0].count('NOPASSWD:') == 1 and ',' not in new[0])
    ls = body.split('\n')
    check('sudoers (%s): the new rule sits where the old one was (between arping and touch)' % label,
          NEW_LINE in ls and ls.index(NEW_LINE) == ls.index('www-data ALL=(ALL) NOPASSWD: /usr/sbin/arping *') + 1
          and ls[ls.index(NEW_LINE) + 1].endswith('/usr/bin/touch /var/log/irongate-update.log'))
check('sudoers: the installer text no longer contains the old rule anywhere',
      'NOPASSWD: /bin/bash /opt/irongate/irongate-updater.sh' not in TEXT)

api = read('web/api.php')
m = re.search(r'exec\("sudo -n (/usr/bin/systemctl start --no-block irongate-updater-now\.service)", \$out, \$rc\);', api)
check('api.php update_now: execs `sudo -n <command>` with the exit status captured', m is not None)
sudo_cmd = NEW_LINE.split('NOPASSWD: ', 1)[1]
check('api.php command is byte-identical to the command of the sudoers rule', m is not None and m.group(1) == sudo_cmd,
      'api: %r sudoers: %r' % (m.group(1) if m else None, sudo_cmd))
check('api.php no longer launches the updater itself (no `irongate-updater.sh`, no backgrounded `&` exec)',
      'irongate-updater.sh' not in api.split("case 'update_now':", 1)[-1].split("case 'update_log':", 1)[0]
      and not re.search(r'exec\("sudo [^"]*&"\)', api))

# ============================================================================== the new unit
UNIT = '''[Unit]
Description=Irongate Auto-Updater (web-triggered)

[Service]
Type=oneshot
ExecStart=/opt/irongate/irongate-updater.sh --force
StandardOutput=journal
StandardError=journal
'''
unit = heredoc(r'/etc/systemd/system/irongate-updater-now\.service') or ''
check('unit: irongate-updater-now.service is exactly the specified oneshot', unit == UNIT, repr(unit[:200]))
check('unit: no [Install] section (never enabled)', '[Install]' not in unit and 'WantedBy' not in unit)
check('unit: the template in the tree is the same', read('templates/irongate-updater-now.service.template') == UNIT
      if os.path.isfile(os.path.join(TREE, 'templates/irongate-updater-now.service.template')) else False)

# ============================================================================== pip
pip_lines = [l for l in LINES if re.search(r'\bpip3?\s+install\b', l) and not l.lstrip().startswith('#') and 'Install with' not in l
             and 'Requirements:' not in l]
check('pip: the installer has pip install lines (control)', len(pip_lines) >= 3, '%d lines' % len(pip_lines))
check('pip: every pip install is --require-hashes -r <list> and none is unpinned',
      all('--require-hashes' in l and ' -r ' in l for l in pip_lines) and not any(re.search(r'\bpyyaml scapy netifaces\b', l) for l in pip_lines),
      '; '.join(l.strip() for l in pip_lines if '--require-hashes' not in l)[:300])


def requirement_list(marker):
    body = heredoc(r'"?\$IG_REQ_DIR/requirements-%s\.txt"?' % marker)
    if body is None:
        return None
    pkgs, cur = {}, None
    for line in body.split('\n'):
        if not line:
            continue
        pm = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.!+_-]*)( \\)?', line)
        hm = re.fullmatch(r'    --hash=sha256:([0-9a-f]{64})( \\)?', line)
        if pm:
            cur = pm.group(1)
            pkgs[cur] = {'version': pm.group(2), 'hashes': []}
        elif hm and cur:
            pkgs[cur]['hashes'].append(hm.group(1))
        else:
            return {'__bad__': line}
    return pkgs


for marker, expect in (('venv', {'cffi', 'docstring-parser', 'executing', 'msgpack', 'netifaces', 'py-algorand-sdk', 'pycparser',
                                  'pycryptodomex', 'PyNaCl', 'pyteal', 'PyYAML', 'scapy', 'semantic-version', 'tabulate'}),
                       ('system', {'netifaces', 'PyYAML', 'scapy'})):
    pk = requirement_list(marker)
    check('pip: the %s list is embedded in the installer and every line parses (pkg==version, sha256 lines)' % marker,
          pk is not None and '__bad__' not in pk, str(pk)[:200] if pk else 'no heredoc')
    check('pip: the %s list holds exactly the %d prescribed packages' % (marker, len(expect)), pk is not None and set(pk) == expect,
          'got %s' % (sorted(pk) if pk else None))
    check('pip: every package of the %s list has >= 1 sha256 and a pinned ==version' % marker,
          pk is not None and bool(pk) and all(v['hashes'] and v['version'] for v in pk.values() if isinstance(v, dict)))
    if pk and '__bad__' not in pk:
        check('pip: no hash is listed twice in the %s list' % marker, all(len(set(v['hashes'])) == len(v['hashes']) for v in pk.values()))

# ============================================================================== curl
def curl_lines(text):
    return [l for l in text.split('\n') if re.search(r'(^|[\s(`|;&])curl\s+-', l) and not l.lstrip().startswith('#')]


for label, text in (('installer', TEXT), ('src/irongate-updater.sh', read('src/irongate-updater.sh'))):
    cl = curl_lines(text)
    check('curl (%s): there are curl calls (control)' % label, len(cl) >= 1, '%d' % len(cl))
    check('curl (%s): every curl has --max-time N' % label, all(re.search(r'--max-time\s+[1-9][0-9]*\b', l) for l in cl),
          '; '.join(l.strip() for l in cl if not re.search(r'--max-time', l))[:300])

# ============================================================================== secrets
check('secrets: nothing echoes or prints the generated admin password',
      not any(re.search(r'(echo|printf)[^>|]*WEBAUTH_INIT_PASSWORD', l) and '>' not in l.split('WEBAUTH_INIT_PASSWORD')[-1] for l in LINES),
      '; '.join(l.strip() for l in LINES if re.search(r'(echo|printf)[^>|]*WEBAUTH_INIT_PASSWORD', l))[:200])
check('secrets: the password goes to a root-only file (umask 077 + noclobber, root:root 0600)',
      'umask 077; set -C' in TEXT and 'IG_ADMIN_PW_FILE=/root/irongate-initial-admin-password' in TEXT)

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
