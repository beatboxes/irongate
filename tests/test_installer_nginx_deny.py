#!/usr/bin/env python3
"""
Irongate installer: the nginx template refuses backup/source/database artifacts, and the embedded updater is the
updater in the tree.

Nothing is executed and nothing is written, so this needs no root and no container, but it is run in one like the other
tests:

    docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w python:3.12-slim \
        python3 -I tests/test_installer_nginx_deny.py irongate-install.sh

What it pins
  deny     the nginx server block carries the two widened rules - the dotfile rule (except /.well-known/) and the
           artifact rule that also covers `api.php.bak.<timestamp>.<pid>`, `*.db-journal`, `*~` and archives - each
           written with the heredoc's `\\$` escaping, exactly once, and BOTH of them before `location ~ \\.php\\$`
           (nginx matches regex locations in order, and the php location would otherwise serve the backup as source)
  narrow   the older narrow artifact rule is still there, unchanged, and the two new rules sit above it
  parity   the updater heredoc (`cat > /opt/irongate/irongate-updater.sh << 'UPDATER'`) is byte-identical to
           src/irongate-updater.sh, and the extracted nginx template is byte-identical to the server-block heredoc

Exit status 0 = every case passed. Against the installer of f1ef11e it fails.
"""
import os
import re
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
HD = []


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


# ============================================================================== the two rules
NGINX = heredoc(r'/etc/nginx/sites-available/irongate')
check('nginx: the server-block heredoc exists exactly once in the installer', NGINX is not None)
BODY = NGINX or ''
BLINES = BODY.split('\n')

DOTFILE = r'    location ~* (^|/)\.(?!well-known/) { deny all; return 404; }'
ARTIFACT = (r'    location ~* \.(bak|orig|old|save|swp|db|db-sidecar|db-wal|db-shm|db-journal|sqlite|sqlite3|sql|tar|gz|zip)'
            r'(\..*)?\$|~\$ { deny all; return 404; }')
NARROW = r'    location ~* \.(bak|old|orig|swp|save|sql|sqlite|sqlite3|db)(\.[0-9]+)?\$ {'
PHP = r'    location ~ \.php\$ {'

check('nginx: the dotfile rule is present, byte-exact, exactly once',
      BLINES.count(DOTFILE) == 1, repr([l for l in BLINES if 'well-known' in l]))
check('nginx: the artifact rule is present, byte-exact, exactly once',
      BLINES.count(ARTIFACT) == 1, repr([l for l in BLINES if 'db-journal' in l]))
check('nginx: the older narrow artifact rule is still there, unchanged',
      BLINES.count(NARROW) == 1, repr([l for l in BLINES if 'deny all' in l][:4]))


def idx(pattern):
    hits = [i for i, l in enumerate(BLINES) if l == pattern]
    return hits[0] if len(hits) == 1 else -1


i_dot, i_art, i_narrow, i_php = idx(DOTFILE), idx(ARTIFACT), idx(NARROW), idx(PHP)
check('nginx: the php location is where it always was', i_php > 0, 'index %d' % i_php)
check('nginx: the dotfile rule comes before `location ~ \\.php\\$`', 0 <= i_dot < i_php, 'dotfile=%d php=%d' % (i_dot, i_php))
check('nginx: the artifact rule comes before `location ~ \\.php\\$`', 0 <= i_art < i_php, 'artifact=%d php=%d' % (i_art, i_php))
check('nginx: both new rules sit above the narrow rule (nginx matches regex locations in order)',
      0 <= i_dot < i_narrow and 0 <= i_art < i_narrow, 'dotfile=%d artifact=%d narrow=%d' % (i_dot, i_art, i_narrow))

# the heredoc is an unquoted << EOF, so every `$` the installer must not expand has to be written `\$`
for label, rule in (('dotfile', DOTFILE), ('artifact', ARTIFACT)):
    check('nginx: the %s rule has no unescaped `$` (the heredoc would expand it)' % label,
          re.search(r'(?<!\\)\$', rule) is None, repr(rule))
    check('nginx: the %s rule has no backtick' % label, '`' not in rule)
# the body's only unescaped `$` are the two the installer fills in at install time
unescaped = [l for l in BLINES if re.search(r'(?<!\\)\$', l)]
check('nginx: only the installer-expanded variables keep an unescaped `$`',
      all(('listen $WEBUI_PORT' in l and l.count('$') == 1)
          or ('fastcgi_pass unix:$PHP_SOCK' in l and l.count('$') == 1) for l in unescaped),
      repr(unescaped))

# the rules must not exist outside the server block (a stray copy would not be served by nginx)
outside = TEXT.replace(BODY, '', 1)
check('nginx: neither rule text appears anywhere else in the installer',
      'db-journal' not in outside and 'well-known' not in outside, 'found outside the server block')

# the extracted template mirrors the block (tools/heredoc_sync.py --check asserts this too)
tpl = os.path.join(TREE, 'templates', 'nginx-irongate.conf.template')
if os.path.isfile(tpl):
    check('nginx: templates/nginx-irongate.conf.template is byte-identical to the heredoc', read('templates/nginx-irongate.conf.template') == BODY)
else:
    check('nginx: templates/nginx-irongate.conf.template exists', False, 'missing')

# ============================================================================== updater parity
UPD = heredoc(r'/opt/irongate/irongate-updater\.sh')
check('parity: the updater heredoc exists exactly once in the installer', UPD is not None)
upd_path = os.path.join(TREE, 'src', 'irongate-updater.sh')
have = os.path.isfile(upd_path)
check('parity: src/irongate-updater.sh exists', have)
check('parity: src/irongate-updater.sh == the UPDATER heredoc byte for byte',
      UPD is not None and have and read('src/irongate-updater.sh') == UPD,
      'tree %s, heredoc %s' % ('present' if have else 'MISSING', 'present' if UPD is not None else 'MISSING'))
if UPD is not None:
    check('parity: the embedded updater writes the database as www-data (the marker fix is in both copies)',
          UPD.count('"$DB_RUNUSER" -u www-data -- "$DB_SQLITE"') >= 2,
          '%d occurrences' % UPD.count('"$DB_RUNUSER" -u www-data -- "$DB_SQLITE"'))

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
