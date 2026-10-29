#!/usr/bin/env python3
"""
irongate web tier: the code under /var/www/irongate is root's, the runtime data is www-data's.

php-fpm runs as www-data, so if the PHP it executes belongs to www-data too, one bad request can rewrite the code
that the next request (and root's updater) runs. This is a static check of the installer's "Setting permissions"
block (block W, the one tests/test_installer_links.sh and tests/test_item_e_installer.py run as root):

  * the tree pass makes the tree root:www-data 0755, and the directory itself is root:www-data 1775 - the sticky
    bit stops www-data renaming or deleting the root-owned code, while the group-write bit keeps the SQLite
    rollback journal creatable there;
  * the five PHP files the installer writes (api.php, index.php, session_check.php, login.php, logout.php) are
    pinned root:www-data 0644, after the tree pass so the tree cannot undo them;
  * dhcp.db keeps www-data:www-data 0664 (the web API and root's sqlite3 both write it);
  * nothing in the installer does a recursive chown/chmod on the webroot, and the old www-data-owned tree call
    is gone (the block never loosens).

    python3 -I tests/test_webroot_ownership.py irongate-install.sh

Read-only: it only reads the installer, so it needs no container and no root. Exit status 0 = every case passed.
Against the installer of 5dfd152 it fails (the tree is www-data:www-data and the code files are not pinned).
"""

import os
import re
import sys

INSTALLER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else 'irongate-install.sh')
WEB = '/var/www/irongate'
CODE = ['api.php', 'index.php', 'session_check.php', 'login.php', 'logout.php']

with open(INSTALLER, encoding='utf-8', errors='replace', newline='') as fh:
    LINES = fh.read().split('\n')
TEXT = '\n'.join(LINES)

pass_n = fail_n = 0


def check(name, cond, detail=''):
    global pass_n, fail_n
    if cond:
        pass_n += 1
        print('PASS  ' + name)
    else:
        fail_n += 1
        print('FAIL  ' + name + ('  -- ' + detail if detail else ''))


def find(pattern):
    """All line indexes matching the regex."""
    rx = re.compile(pattern)
    return [i for i, line in enumerate(LINES) if rx.search(line)]


BLOCK_START = r'^echo -e "\$\{YELLOW\}Setting permissions\.\.\.\$\{NC\}"$'
BLOCK_END = r'^# Ensure lease file has proper ownership for dnsmasq to write$'
starts, ends = find(BLOCK_START), find(BLOCK_END)
BLOCK = None
if len(starts) == 1 and len(ends) == 1 and starts[0] < ends[0]:
    BLOCK = LINES[starts[0]:ends[0]]
BLINES = BLOCK or []
BTEXT = '\n'.join(BLINES)


def blk(pattern):
    rx = re.compile(pattern)
    return [i for i, line in enumerate(BLINES) if rx.search(line)]


TREE = r'^\s*ig_perm_fix tree ' + re.escape(WEB) + r' root www-data 755$'
DIRLINE = r'^\s*chown root:www-data ' + re.escape(WEB) + r' && chmod 1775 ' + re.escape(WEB) + r'$'
DBLINE = r'^\s*ig_perm_fix file ' + re.escape(WEB) + r'/dhcp\.db www-data www-data 664$'
LOOPHEAD = r'^\s*for IGWEB in (.*); do$'
LOOPBODY = r'^\s*ig_perm_fix file "' + re.escape(WEB) + r'/\$IGWEB" root www-data 644$'

check('W the "Setting permissions" block is in the installer', BLOCK is not None,
      'start=%d end=%d' % (len(starts), len(ends)))

tree = blk(TREE)
dirname = blk(DIRLINE)
dbl = blk(DBLINE)
loophead = blk(LOOPHEAD)
loopbody = blk(LOOPBODY)

check('W the web tree is chowned root:www-data and set 0755 by the helper',
      len(tree) == 1, 'found %d of "ig_perm_fix tree %s root www-data 755"' % (len(tree), WEB))
check('W the webroot itself is root:www-data 1775 (sticky: www-data cannot rename or delete the code)',
      len(dirname) == 1, 'found %d of "chown root:www-data %s && chmod 1775 %s"' % (len(dirname), WEB, WEB))
check('W dhcp.db is still www-data:www-data 0664 (the web API and root\'s sqlite3 both write it)',
      len(dbl) == 1, 'found %d of "ig_perm_fix file %s/dhcp.db www-data www-data 664"' % (len(dbl), WEB))
check('W exactly one `for IGWEB in ...; do` loop pins the code files', len(loophead) == 1,
      'found %d' % len(loophead))

names = []
if len(loophead) == 1:
    names = BLINES[loophead[0]].split(' in ', 1)[1].rsplit('; do', 1)[0].split()
check('W the loop names exactly the five PHP files the installer writes', sorted(names) == sorted(CODE),
      'names=%s' % names)
check('W every file the loop pins is root:www-data 0644 (one body line, and it is inside the loop)',
      len(loopbody) == 1 and len(loophead) == 1 and loopbody[0] > loophead[0],
      'found %d of \'ig_perm_fix file "%s/$IGWEB" root www-data 644\'' % (len(loopbody), WEB))

# The order matters: the tree pass would undo the pins if it ran after them.
order = (len(tree) == 1 and len(dirname) == 1 and len(dbl) == 1 and len(loophead) == 1 and len(loopbody) == 1
         and tree[0] < dirname[0] < dbl[0] < loophead[0] < loopbody[0])
check('W the tree pass runs first, then the directory mode, then dhcp.db, then the code pins', order,
      'tree=%s dir=%s dhcp.db=%s loop=%s body=%s' % (tree, dirname, dbl, loophead, loopbody))

# The policy is only as good as what is NOT there: the old www-data-owned tree call and any recursive pass.
loose = find(r'^\s*ig_perm_fix tree ' + re.escape(WEB) + r' www-data www-data 755$')
check('W the old www-data-owned tree call is gone (the block never loosens)', loose == [],
      'lines %s' % [i + 1 for i in loose])
recursive = find(r'\b(?:chown|chmod)\s+-R\b[^\n]*' + re.escape(WEB))
check('W no recursive chown/chmod is run on the webroot', recursive == [],
      'lines %s: %s' % ([i + 1 for i in recursive], [LINES[i].strip() for i in recursive]))

# No code file may be pinned to www-data anywhere in the installer (that would hand the code back to php-fpm).
owned = find(r'ig_perm_fix file "' + re.escape(WEB) + r'/\$IGWEB" www-data')
for name in CODE:
    owned += find(r'ig_perm_fix file ' + re.escape(WEB) + r'/' + re.escape(name) + r' www-data')
check('W no PHP file of the web tier is pinned to www-data', owned == [],
      'lines %s: %s' % ([i + 1 for i in owned], [LINES[i].strip() for i in owned]))

print()
print('%d passed, %d failed' % (pass_n, fail_n))
sys.exit(0 if fail_n == 0 else 1)
