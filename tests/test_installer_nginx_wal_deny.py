#!/usr/bin/env python3
"""
Irongate installer: the nginx artifact rule refuses the SQLite WAL and shared-memory sidecars as well as dhcp.db.

Nothing is executed and nothing is written, so this needs no root and no container:

    python3 -I tests/test_installer_nginx_wal_deny.py irongate-install.sh

What it pins
  deny   the artifact rule rendered by the unquoted heredoc - in the installer AND in
         templates/nginx-irongate.conf.template - lists db-sidecar, db-wal and db-shm next to db and db-journal,
         renders to exactly the expected live snippet, sits before `location ~ \\.php\\$` (nginx matches regex
         locations in order, so the php location would otherwise serve a sidecar as source), and really matches the
         names the installer writes (`dhcp.db-sidecar.<ts>-journal|wal|shm`) when run as a regex
  escape the rule keeps the heredoc's `\\$` escaping, so it renders to `$` and not to the installer's own variables
  parity tools/heredoc_sync.py --check is clean, and the UPDATER heredoc body is byte-identical to
         src/irongate-updater.sh (the read-back retry is in both copies)

Exit status 0 = every case passed. Against the installer of 8ed55cf it fails (no db-wal / db-shm alternative).
"""
import os
import re
import subprocess
import sys

INSTALLER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'irongate-install.sh')
TREE = os.path.dirname(INSTALLER)
TEXT = open(INSTALLER, encoding='utf-8', newline='').read()
LINES = TEXT.split('\n')
TEMPLATE = os.path.join(TREE, 'templates', 'nginx-irongate.conf.template')
UPDATER = os.path.join(TREE, 'src', 'irongate-updater.sh')

pass_n = fail_n = 0


def check(name, cond, detail=''):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print('PASS  ' + name)
    else:
        fail_n += 1
        print('FAIL  ' + name + ('  -- ' + detail if detail else ''))


def read(path):
    with open(path, encoding='utf-8', newline='') as fh:
        return fh.read()

# ---- heredocs of the installer: `cat > PATH << 'M'` and `cat << 'M' > PATH` (quoted or not) ----
FORM_A = re.compile(r"^\s*cat\s+>>?\s+(\S+)\s+<<\s+(')?([A-Za-z_][A-Za-z0-9_]*)\2?\s*$")
FORM_B = re.compile(r"^\s*cat\s+<<\s+(')?([A-Za-z_][A-Za-z0-9_]*)\1?\s+>>?\s+(\S+)\s*$")


def heredocs(text):
    lines = text.split('\n')
    out, i = [], 0
    while i < len(lines):
        m = FORM_A.match(lines[i])
        if m:
            target, marker = m.group(1), m.group(3)
        else:
            m = FORM_B.match(lines[i])
            target, marker = (m.group(3), m.group(2)) if m else (None, None)
        if not target:
            i += 1
            continue
        j = i + 1
        body = []
        while j < len(lines) and lines[j] != marker:
            body.append(lines[j])
            j += 1
        out.append((target.strip('"'), marker, '\n'.join(body) + '\n'))
        i = j + 1
    return out


HD = heredocs(TEXT)


def heredoc(target_re):
    hits = [h for h in HD if re.fullmatch(target_re, h[0])]
    return hits[0][2] if len(hits) == 1 else None

# ============================================================================== the artifact rule
# as written inside the unquoted heredocs (`\$` stays literal for the installer)
ARTIFACT_HEREDOC = (r'    location ~* \.(bak|orig|old|save|swp|db|db-sidecar|db-wal|db-shm|db-journal|sqlite|sqlite3|sql|tar|gz|zip)'
                    r'(\..*)?\$|~\$ { deny all; return 404; }')
# what the operator's live /etc/nginx/sites-available/irongate must carry after the heredoc expands it
ARTIFACT_LIVE = (r'    location ~* \.(bak|orig|old|save|swp|db|db-sidecar|db-wal|db-shm|db-journal|sqlite|sqlite3|sql|tar|gz|zip)'
                 r'(\..*)?$|~$ { deny all; return 404; }')
PHP = r'    location ~ \.php\$ {'

NGINX = heredoc(r'/etc/nginx/sites-available/irongate')
check('nginx: the server-block heredoc exists exactly once in the installer', NGINX is not None)
BLINES = (NGINX or '').split('\n')

check('nginx: the installer heredoc carries the widened artifact rule, byte-exact, exactly once',
      BLINES.count(ARTIFACT_HEREDOC) == 1, repr([l for l in BLINES if 'db-journal' in l]))
check('nginx: the installer heredoc carries db-sidecar, db-wal and db-shm as alternatives',
      all(tok in ARTIFACT_HEREDOC for tok in ('|db-sidecar|', '|db-wal|', '|db-shm|')) and
      any('|db-wal|' in l and '|db-shm|' in l and 'db-sidecar' in l and 'db-journal' in l for l in BLINES),
      repr([l for l in BLINES if 'db-journal' in l]))


def idx(line):
    hits = [i for i, l in enumerate(BLINES) if l == line]
    return hits[0] if len(hits) == 1 else -1


i_art, i_php = idx(ARTIFACT_HEREDOC), idx(PHP)
check('nginx: the php location is where it always was', i_php > 0, 'index %d' % i_php)
check('nginx: the artifact rule comes before `location ~ \\.php\\$`', 0 <= i_art < i_php,
      'artifact=%d php=%d' % (i_art, i_php))

# the heredoc is unquoted, so the `$` nginx must see cannot appear unescaped
check('nginx: the artifact rule has no unescaped `$` (the installer would expand it)',
      re.search(r'(?<!\\)\$', ARTIFACT_HEREDOC) is None, repr(ARTIFACT_HEREDOC))
check('nginx: the artifact rule has no backtick', '`' not in ARTIFACT_HEREDOC)
check('nginx: the rule renders (\\$ -> $) to exactly the expected live snippet',
      ARTIFACT_HEREDOC.replace('\\$', '$') == ARTIFACT_LIVE, repr(ARTIFACT_HEREDOC.replace('\\$', '$')))
check('nginx: the live snippet itself names db-sidecar, db-wal and db-shm and still ends with the ~$ alternative',
      '|db-sidecar|' in ARTIFACT_LIVE and '|db-wal|' in ARTIFACT_LIVE and '|db-shm|' in ARTIFACT_LIVE
      and ARTIFACT_LIVE.endswith('(\\..*)?$|~$ { deny all; return 404; }'))

# ---- the rule as nginx would evaluate it (`~*` = case-insensitive regex location) ----
LIVE_RE = re.match(r'^    location ~\* (.*) \{ deny all; return 404; \}$', ARTIFACT_LIVE)
check('nginx: the live rule parses as `location ~* <regex> { deny all; return 404; }`', LIVE_RE is not None, repr(ARTIFACT_LIVE))
if LIVE_RE:
    RX = re.compile(LIVE_RE.group(1), re.I)
    for uri in ('/dhcp.db-sidecar.1700000000-journal', '/dhcp.db-sidecar.1700000000-wal',
                '/dhcp.db-sidecar.1700000000-shm', '/dhcp.db-journal', '/dhcp.db-wal', '/dhcp.db-shm', '/dhcp.db',
                '/api.php.bak.1700000000.123'):
        check('nginx: the live rule DENIES %s' % uri, RX.search(uri) is not None, LIVE_RE.group(1))
    for uri in ('/index.php', '/api.php', '/login.php', '/.well-known/acme-challenge/x'):
        check('nginx: the live rule still allows %s' % uri, RX.search(uri) is None, LIVE_RE.group(1))

# ============================================================================== the extracted template
check('template: templates/nginx-irongate.conf.template exists', os.path.isfile(TEMPLATE))
if os.path.isfile(TEMPLATE):
    TPL = read(TEMPLATE)
    TLINES = TPL.split('\n')
    check('template: carries the widened artifact rule, byte-exact, exactly once',
          TLINES.count(ARTIFACT_HEREDOC) == 1, repr([l for l in TLINES if 'db-journal' in l]))
    check('template: is byte-identical to the installer heredoc', TPL == (NGINX or ''))
    t_i_art, t_i_php = TLINES.index(ARTIFACT_HEREDOC) if ARTIFACT_HEREDOC in TLINES else -1, \
        TLINES.index(PHP) if PHP in TLINES else -1
    check('template: the artifact rule comes before `location ~ \\.php\\$`', 0 <= t_i_art < t_i_php,
          'artifact=%d php=%d' % (t_i_art, t_i_php))

# the rule must not exist outside the server block (a stray copy would not be served by nginx)
outside = TEXT.replace(NGINX or '', '', 1)
check('nginx: the artifact rule text appears nowhere else in the installer',
      'db-wal' not in outside, repr([l for l in outside.split('\n') if 'db-wal' in l][:3]))

# ============================================================================== parity
UPD = heredoc(r'/opt/irongate/irongate-updater\.sh')
check('parity: the updater heredoc exists exactly once in the installer', UPD is not None)
have = os.path.isfile(UPDATER)
check('parity: src/irongate-updater.sh exists', have)
check('parity: src/irongate-updater.sh == the UPDATER heredoc byte for byte',
      UPD is not None and have and read(UPDATER) == UPD,
      'tree %s, heredoc %s' % ('present' if have else 'MISSING', 'present' if UPD is not None else 'MISSING'))
if UPD is not None:
    check('parity: both updater copies carry the read-back helper',
          UPD.count('ig_sqlite3_read()') == 1
          and UPD.count('STAMPED_COMMIT=$(ig_sqlite3_read "SELECT value FROM settings') == 1,
          'helper=%d call=%d' % (UPD.count('ig_sqlite3_read()'),
                                 UPD.count('STAMPED_COMMIT=$(ig_sqlite3_read "SELECT value FROM settings')))

sync = os.path.join(TREE, 'tools', 'heredoc_sync.py')
if os.path.isfile(sync):
    rc = subprocess.run([sys.executable, '-I', sync, '--check'], cwd=TREE,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check('parity: tools/heredoc_sync.py --check is clean', rc.returncode == 0,
          rc.stdout.decode('utf-8', 'replace')[-300:])
else:
    check('parity: tools/heredoc_sync.py exists', False, 'missing')

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
