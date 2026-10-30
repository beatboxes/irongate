#!/bin/bash
# Irongate installer: the dhcp.db restore path stops the install instead of rewriting the database in place, and a
# stale rollback journal / WAL / shared-memory file is moved aside before the backup is installed.
#
# The block between the `# >>> IG_DB_RESTORE` and `# <<< IG_DB_RESTORE` markers in irongate-install.sh is cut out and
# run VERBATIM, with /var/www/irongate rewritten to a scratch directory and the root-only steps shimmed, so what is
# tested is the installer's own text and not a copy that can drift:
#   T1  the restore never runs `cp ... dhcp.db`; it uses `install -o www-data -g www-data -m <mode>`, and an install
#       that fails makes the snippet exit non-zero with the error on stderr
#   T2  a hot dhcp.db-journal, and a dhcp.db-wal + dhcp.db-shm, left by a killed writer (real sqlite3, real files)
#       are moved to dhcp.db-sidecar.<stamp>-<suffix> BEFORE the install, nothing is deleted, no sidecar can match the
#       dhcp.db.bak.* backup glob, and the restored database passes PRAGMA integrity_check -> ok
#   T2d the same with a chmod that rejects -h exactly as GNU coreutils 9.4 (the target host) does: the sidecar's mode is
#       set with a plain `chmod 600`, and the installer text never asks chmod for -h
#   T3  a sidecar move that fails makes the snippet exit non-zero with the error, and dhcp.db's sha256 is unchanged
#   T4  a sidecar that is a SYMLINK (www-data owns the group-writable webroot) is refused before any move, and the file
#       it points at keeps its contents and mode - nothing is dereferenced
#   T5  a dhcp.db.bak.* that is a symlink is refused instead of being installed as the database
#   T6  the sidecar re-tighten block (after the tree permission pass) asks for root:root 0600 on each moved sidecar
#
# No root and no container: the shims record the owner/group the installer ASKS for (exFAT/uid 1000 cannot apply it).
# Real sqlite3 is used wherever a database is involved.
#
#   bash tests/test_installer_db_restore.sh irongate-install.sh
#
# Exit status 0 = every case passed. Against the installer of 8ed55cf it fails (no restore markers, `cp` in place,
# sidecars left where they are).

set -u
INSTALLER=${1:?usage: test_installer_db_restore.sh <irongate-install.sh>}
[ -f "$INSTALLER" ] || { echo "no such file: $INSTALLER" >&2; exit 2; }

REAL_SQLITE=$(command -v sqlite3 2>/dev/null || true)
[ -n "$REAL_SQLITE" ] && [ -x "$REAL_SQLITE" ] || { echo "refusing to run: no sqlite3 CLI" >&2; exit 2; }
REAL_INSTALL=$(command -v install) || { echo "refusing to run: no install(1)" >&2; exit 2; }
REAL_CP=$(command -v cp) || exit 2
REAL_MV=$(command -v mv) || exit 2
REAL_CHMOD=$(command -v chmod) || exit 2
REAL_PYTHON=$(command -v python3 2>/dev/null || true)

# the scratch dir must support symlinks (T4/T5 depend on it); exFAT, a common place for a USB worktree, does not
T=""
for base in "${IG_TEST_TMPDIR:-}" /tmp /var/tmp; do
    [ -n "$base" ] && [ -d "$base" ] || continue
    cand=$(mktemp -d "$base/irongate-db-restore.XXXXXX") || continue
    if ln -s probe "$cand/symlink-probe" 2>/dev/null; then T=$cand; rm -f "$cand/symlink-probe"; break; fi
    rm -rf "$cand"
done
[ -n "$T" ] || { echo "refusing to run: no scratch directory that supports symlinks (set IG_TEST_TMPDIR)" >&2; exit 2; }
WWW="$T/www"
mkdir -p "$WWW" "$T/bin"
TS=1700000000

pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}

# ---- the block under test, cut out of the installer ------------------------------------------------
SNIPPET=$(awk '/^ *# >>> IG_DB_RESTORE/{f=1; next} /^ *# <<< IG_DB_RESTORE/{f=0} f' "$INSTALLER")
MARKERS=$(grep -c -e '^ *# >>> IG_DB_RESTORE' -e '^ *# <<< IG_DB_RESTORE' "$INSTALLER")
check "the restore block is marked exactly once in the installer" $([ "$MARKERS" -eq 2 ] && [ -n "$SNIPPET" ]; echo $?) \
      "markers=$MARKERS block=${#SNIPPET} bytes"
if [ -z "$SNIPPET" ]; then
    # An installer without the markers (8ed55cf): fall back to the old verify/restore block so the cases below report
    # the real behaviour differences instead of stopping at extraction.
    SNIPPET=$( { echo 'if true; then'; sed -n '/Reservation count changed/,/^    fi$/p' "$INSTALLER"; } )
fi
[ -n "$SNIPPET" ] || { echo "FAIL  no verify/restore block found in $INSTALLER"; echo; echo "$pass passed, $((fail + 1)) failed"; rm -rf "$T"; exit 1; }
printf '%s\n' "$SNIPPET" | sed -e "s#/var/www/irongate#$WWW#g" > "$T/snippet.sh"
check "the block is rewritten to the scratch directory (no /var/www/irongate left)" \
      $(! grep -q '/var/www/irongate' "$T/snippet.sh"; echo $?) "$(grep -n '/var/www/irongate' "$T/snippet.sh" | head -3)"

# ---- shims: record what the root-only steps were asked to do, then do what a non-root run can -----
cat > "$T/bin/install" <<SH
#!/bin/bash
echo "INSTALL \$*" >> "\$T/install.args"
if [ -n "\${IG_INSTALL_FAIL:-}" ]; then exit "\$IG_INSTALL_FAIL"; fi
args=()
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o|-g) shift 2 ;;
        *) args+=("\$1"); shift ;;
    esac
done
exec $REAL_INSTALL "\${args[@]}"
SH
cat > "$T/bin/chown" <<SH
#!/bin/bash
echo "CHOWN \$*" >> "\$T/chown.args"
exit 0
SH
cat > "$T/bin/cp" <<SH
#!/bin/bash
echo "CP \$*" >> "\$T/cp.args"
exec $REAL_CP "\$@"
SH
cat > "$T/bin/chmod" <<SH
#!/bin/bash
echo "CHMOD \$*" >> "\$T/chmod.args"
exec $REAL_CHMOD "\$@"
SH
cat > "$T/bin/mv" <<SH
#!/bin/bash
echo "MV \$*" >> "\$T/mv.args"
if [ -n "\${IG_MV_FAIL:-}" ]; then exit 1; fi
exec $REAL_MV "\$@"
SH
chmod +x "$T/bin/install" "$T/bin/chown" "$T/bin/cp" "$T/bin/chmod" "$T/bin/mv"
export T WWW TS
PATH="$T/bin:$PATH"; export PATH

# ---- fixtures -------------------------------------------------------------------------------------
mkdb() {
    rm -f "$WWW"/dhcp.db "$WWW"/dhcp.db-* "$WWW"/dhcp.db-sidecar.* "$WWW"/dhcp.db.bak.*
    "$REAL_SQLITE" "$WWW/dhcp.db" "CREATE TABLE reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT NOT NULL, hostname TEXT);
        INSERT INTO reservations (mac, ip, hostname) VALUES ('aa:aa:aa:aa:aa:aa','10.0.0.1','a'), ('bb:bb:bb:bb:bb:bb','10.0.0.2','b'), ('cc:cc:cc:cc:cc:cc','10.0.0.3','c');"
}
backup() { "$REAL_CP" "$WWW/dhcp.db" "$WWW/dhcp.db.bak.$TS"; BACKUP_SHA=$(sha256sum "$WWW/dhcp.db.bak.$TS" | cut -d' ' -f1); }
hot_journal() {   # a real rollback journal left behind by a writer that died mid-transaction
    "$REAL_PYTHON" -I -c '
import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
c.execute("PRAGMA journal_mode=DELETE")
c.execute("BEGIN IMMEDIATE")
c.execute("INSERT INTO reservations (mac, ip) VALUES (?, ?)", ("ho:ho:ho:ho:ho:ho", "10.0.0.99"))
os._exit(3)' "$WWW/dhcp.db"
}
hot_wal() {       # a real WAL + shared-memory file left behind by a writer that died
    "$REAL_PYTHON" -I -c '
import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
c.execute("PRAGMA journal_mode=WAL")
c.execute("BEGIN IMMEDIATE")
c.execute("INSERT INTO reservations (mac, ip) VALUES (?, ?)", ("wa:wa:wa:wa:wa:wa", "10.0.0.98"))
os._exit(3)' "$WWW/dhcp.db"
}
reset_logs() { rm -f "$T/install.args" "$T/chown.args" "$T/chmod.args" "$T/cp.args" "$T/mv.args" "$T/stderr"; }
run_restore() {   # the installer block, in a subshell, exactly as written
    ( IG_DB_STAMP=$TS IG_DB_MODE_BEFORE=660 VERIFY_COUNT=0 DB_RESERVATION_COUNT=1
      RED=$'\033[0;31m' GREEN=$'\033[0;32m' YELLOW=$'\033[1;33m' NC=$'\033[0m'
      . "$T/snippet.sh" ) 2>"$T/stderr"
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# ============================ T1: install, never cp in place ============================
reset_logs; mkdb; backup
run_restore; RC=$?
check "T1 the restore succeeds (exit 0)" $([ "$RC" -eq 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T1 the database is installed with -o www-data -g www-data -m 660" \
      $(grep -qF -- "INSTALL -o www-data -g www-data -m 660 $WWW/dhcp.db.bak.$TS $WWW/dhcp.db" "$T/install.args" 2>/dev/null; echo $?) \
      "$(cat "$T/install.args" 2>/dev/null)"
check "T1 the restore never runs cp against dhcp.db" \
      $(! grep -qF 'dhcp.db' "$T/cp.args" 2>/dev/null; echo $?) "$(cat "$T/cp.args" 2>/dev/null)"
check "T1 the restored database is byte-identical to the backup" $([ "$(sha "$WWW/dhcp.db")" = "$BACKUP_SHA" ]; echo $?) \
      "db=$(sha "$WWW/dhcp.db") backup=$BACKUP_SHA"

reset_logs; mkdb; backup
"$REAL_SQLITE" "$WWW/dhcp.db" "INSERT INTO reservations (mac, ip) VALUES ('dd:dd:dd:dd:dd:dd','10.0.0.4');"
DB_SHA=$(sha "$WWW/dhcp.db")
export IG_INSTALL_FAIL=1
run_restore; RC=$?
unset IG_INSTALL_FAIL
check "T1 a failing install makes the restore exit non-zero" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC"
check "T1 a failing install prints the error on stderr" \
      $(grep -qF -- "ERROR: could not restore $WWW/dhcp.db.bak.$TS over $WWW/dhcp.db" "$T/stderr"; echo $?) "$(cat "$T/stderr")"
check "T1 a failing install leaves the mismatched dhcp.db as it was" $([ "$(sha "$WWW/dhcp.db")" = "$DB_SHA" ]; echo $?) \
      "db=$(sha "$WWW/dhcp.db") before=$DB_SHA backup=$BACKUP_SHA"

# ============================ T2: stale sidecars are moved aside first ============================
# (a) a hot rollback journal
reset_logs; mkdb; backup
hot_journal
JOURNAL_SHA=$(sha "$WWW/dhcp.db-journal")
check "T2a the fixture really left a dhcp.db-journal behind (control)" $([ -n "$JOURNAL_SHA" ]; echo $?) "ls=$(ls "$WWW")"
run_restore; RC=$?
check "T2a the restore succeeds with a stale journal present (exit 0)" $([ "$RC" -eq 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T2a the stale dhcp.db-journal is gone from the live path" $([ ! -e "$WWW/dhcp.db-journal" ]; echo $?) "$(ls "$WWW")"
check "T2a the journal was moved to dhcp.db-sidecar.$TS-journal, not deleted" \
      $([ "$(sha "$WWW/dhcp.db-sidecar.$TS-journal")" = "$JOURNAL_SHA" ]; echo $?) "$(ls "$WWW")"
check "T2a the sidecar is asked for root:root without following links (chown -h root:root)" \
      $(grep -qF -- "CHOWN -h root:root $WWW/dhcp.db-sidecar.$TS-journal" "$T/chown.args" 2>/dev/null; echo $?) "$(cat "$T/chown.args" 2>/dev/null)"
check "T2a the sidecar's mode is set with a plain chmod 600 (GNU chmod has no -h)" \
      $(grep -qF -- "CHMOD 600 $WWW/dhcp.db-sidecar.$TS-journal" "$T/chmod.args" 2>/dev/null \
        && ! grep -qE '^CHMOD -' "$T/chmod.args"; echo $?) "$(cat "$T/chmod.args" 2>/dev/null)"
check "T2a the backup was installed (dhcp.db == the backup)" $([ "$(sha "$WWW/dhcp.db")" = "$BACKUP_SHA" ]; echo $?) "db=$(sha "$WWW/dhcp.db")"
check "T2a the restored database passes PRAGMA integrity_check -> ok" \
      $([ "$("$REAL_SQLITE" "$WWW/dhcp.db" 'PRAGMA integrity_check;')" = "ok" ]; echo $?) \
      "$("$REAL_SQLITE" "$WWW/dhcp.db" 'PRAGMA integrity_check;' 2>&1)"
check "T2a the original backup is still there (nothing deleted)" $([ -f "$WWW/dhcp.db.bak.$TS" ]; echo $?) "$(ls "$WWW")"

# (b) a WAL and its shared-memory file
reset_logs; mkdb; backup
hot_wal
WAL_SHA=$(sha "$WWW/dhcp.db-wal"); SHM_SHA=$(sha "$WWW/dhcp.db-shm")
check "T2b the fixture really left dhcp.db-wal and dhcp.db-shm behind (control)" \
      $([ -n "$WAL_SHA" ] && [ -n "$SHM_SHA" ]; echo $?) "ls=$(ls "$WWW")"
run_restore; RC=$?
check "T2b the restore succeeds with a stale WAL present (exit 0)" $([ "$RC" -eq 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T2b the stale dhcp.db-wal and dhcp.db-shm are gone from the live path" \
      $([ ! -e "$WWW/dhcp.db-wal" ] && [ ! -e "$WWW/dhcp.db-shm" ]; echo $?) "$(ls "$WWW")"
check "T2b the WAL was moved to dhcp.db-sidecar.$TS-wal, not deleted" \
      $([ "$(sha "$WWW/dhcp.db-sidecar.$TS-wal")" = "$WAL_SHA" ]; echo $?) "$(ls "$WWW")"
check "T2b the shm was moved to dhcp.db-sidecar.$TS-shm, not deleted" \
      $([ "$(sha "$WWW/dhcp.db-sidecar.$TS-shm")" = "$SHM_SHA" ]; echo $?) "$(ls "$WWW")"
check "T2b the restored database passes PRAGMA integrity_check -> ok" \
      $([ "$("$REAL_SQLITE" "$WWW/dhcp.db" 'PRAGMA integrity_check;')" = "ok" ]; echo $?) \
      "$("$REAL_SQLITE" "$WWW/dhcp.db" 'PRAGMA integrity_check;' 2>&1)"
check "T2b no sidecar name can be picked as the backup (dhcp.db.bak.* does not match it)" \
      $(! compgen -G "$WWW/dhcp.db.bak.*" | grep -q sidecar; echo $?) "$(ls "$WWW")"

# (c) a lone shared-memory file
reset_logs; mkdb; backup
printf 'shm-only\n' > "$WWW/dhcp.db-shm"
SHM_SHA=$(sha "$WWW/dhcp.db-shm")
run_restore; RC=$?
check "T2c a lone dhcp.db-shm is moved aside as well (exit 0)" \
      $([ "$RC" -eq 0 ] && [ ! -e "$WWW/dhcp.db-shm" ] && [ "$(sha "$WWW/dhcp.db-sidecar.$TS-shm")" = "$SHM_SHA" ]; echo $?) \
      "rc=$RC $(ls "$WWW") $(cat "$T/stderr")"

# (d) the target's chmod. The build host runs uutils coreutils, whose chmod accepts -h; the host this installer runs on
# runs GNU coreutils 9.4, whose chmod has NO -h (it follows the link instead). A chmod that rejects -h exactly as GNU
# does is put in front of the real one, so the plain-`chmod 600` path is what is exercised.
mkdir -p "$T/gnubin"
cat > "$T/gnubin/chmod" <<SH
#!/bin/bash
echo "CHMOD \$*" >> "\$T/chmod.args"
for a in "\$@"; do
    case "\$a" in
        -h|--no-dereference) echo "chmod: invalid option -- 'h'" >&2; exit 1 ;;
    esac
done
exec $REAL_CHMOD "\$@"
SH
chmod +x "$T/gnubin/chmod"
reset_logs; mkdb; backup
hot_journal
SAVED_PATH=$PATH
PATH="$T/gnubin:$PATH"
run_restore; RC=$?
PATH=$SAVED_PATH
check "T2d the restore succeeds when chmod rejects -h exactly as GNU coreutils 9.4 does (exit 0)" \
      $([ "$RC" -eq 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T2d the strict chmod was never asked for an option (plain chmod 600)" \
      $(! grep -qE '^CHMOD -' "$T/chmod.args" 2>/dev/null; echo $?) "$(cat "$T/chmod.args" 2>/dev/null)"
check "T2d the sidecar is still moved aside and the backup installed" \
      $([ ! -e "$WWW/dhcp.db-journal" ] && [ "$(sha "$WWW/dhcp.db")" = "$BACKUP_SHA" ]; echo $?) \
      "rc=$RC $(ls "$WWW") $(cat "$T/stderr")"
check "the installer never calls \`chmod\` with \`-h\` (GNU chmod has no -h; it follows the link)" \
      $(! grep -qE '(^|[^a-z])chmod +-h' "$INSTALLER"; echo $?) \
      "$(grep -nE '(^|[^a-z])chmod +-h' "$INSTALLER" | head -3)"

# ============================ T3: a failed move stops the install, dhcp.db untouched ============================
reset_logs; mkdb; backup
hot_journal
DB_SHA=$(sha "$WWW/dhcp.db")
export IG_MV_FAIL=1
run_restore; RC=$?
unset IG_MV_FAIL
check "T3 a failed sidecar move makes the restore exit non-zero" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC"
check "T3 the failed move is reported on stderr" \
      $(grep -qF -- "ERROR: could not move the stale $WWW/dhcp.db-journal aside" "$T/stderr"; echo $?) "$(cat "$T/stderr")"
check "T3 dhcp.db's sha256 is unchanged (it was not installed over)" $([ "$(sha "$WWW/dhcp.db")" = "$DB_SHA" ]; echo $?) \
      "db=$(sha "$WWW/dhcp.db") before=$DB_SHA"
check "T3 nothing was deleted: the journal is still at its original path" $([ -e "$WWW/dhcp.db-journal" ]; echo $?) "$(ls "$WWW")"
check "T3 the installer was not reached" $([ ! -s "$T/install.args" ]; echo $?) "$(cat "$T/install.args" 2>/dev/null)"

# ============================ T4: a sidecar that is a symlink is refused, nothing is dereferenced ============================
reset_logs; mkdb; backup
printf 'VICTIM\n' > "$T/victim"; "$REAL_CHMOD" 644 "$T/victim"
VICTIM_SHA=$(sha "$T/victim")
ln -s "$T/victim" "$WWW/dhcp.db-journal"
DB_SHA=$(sha "$WWW/dhcp.db")
run_restore; RC=$?
check "T4 a symlinked dhcp.db-journal is refused (non-zero exit)" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T4 the refusal is reported on stderr" \
      $(grep -qF -- "ERROR: $WWW/dhcp.db-journal is a symlink - refusing to move it or touch what it points at" "$T/stderr"; echo $?) "$(cat "$T/stderr")"
check "T4 the file the link points at keeps its contents" $([ "$(sha "$T/victim")" = "$VICTIM_SHA" ]; echo $?) "victim=$(sha "$T/victim")"
check "T4 the file the link points at keeps its mode (never chowned/chmodded through the link)" \
      $([ "$(stat -c %a "$T/victim")" = "644" ]; echo $?) "mode=$(stat -c %a "$T/victim")"
check "T4 the link itself is still where it was (nothing moved, nothing deleted)" $([ -L "$WWW/dhcp.db-journal" ]; echo $?) "$(ls -l "$WWW")"
check "T4 nothing was chmodded at all through the link" $([ ! -s "$T/chmod.args" ]; echo $?) "$(cat "$T/chmod.args" 2>/dev/null)"
check "T4 no chown was attempted at all" $([ ! -s "$T/chown.args" ]; echo $?) "$(cat "$T/chown.args" 2>/dev/null)"
check "T4 dhcp.db was not restored over" $([ "$(sha "$WWW/dhcp.db")" = "$DB_SHA" ]; echo $?) "db=$(sha "$WWW/dhcp.db")"
check "T4 the installer was not reached" $([ ! -s "$T/install.args" ]; echo $?) "$(cat "$T/install.args" 2>/dev/null)"

# ============================ T5: a dhcp.db.bak.* that is a symlink is refused ============================
reset_logs; mkdb
printf 'NOT-A-DATABASE\n' > "$T/fake.db"
ln -s "$T/fake.db" "$WWW/dhcp.db.bak.$TS"
DB_SHA=$(sha "$WWW/dhcp.db")
run_restore; RC=$?
check "T5 a symlinked backup is refused (non-zero exit)" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC stderr=$(cat "$T/stderr")"
check "T5 the refusal is reported on stderr" \
      $(grep -qF -- "ERROR: $WWW/dhcp.db.bak.$TS is a symlink - refusing to restore the database from it" "$T/stderr"; echo $?) "$(cat "$T/stderr")"
check "T5 the link target was not installed as the database" $([ "$(sha "$WWW/dhcp.db")" = "$DB_SHA" ]; echo $?) "db=$(sha "$WWW/dhcp.db")"
check "T5 the installer was not reached" $([ ! -s "$T/install.args" ]; echo $?) "$(cat "$T/install.args" 2>/dev/null)"

# ============================ T6: the sidecars are re-tightened after the tree permission pass ============================
PERM_SNIPPET=$(awk '/^ *# >>> IG_DB_SIDECAR_PERM/{f=1; next} /^ *# <<< IG_DB_SIDECAR_PERM/{f=0} f' "$INSTALLER")
PERM_MARKERS=$(grep -c -e '^ *# >>> IG_DB_SIDECAR_PERM' -e '^ *# <<< IG_DB_SIDECAR_PERM' "$INSTALLER")
check "T6 the sidecar re-tighten block is marked exactly once in the installer" \
      $([ "$PERM_MARKERS" -eq 2 ] && [ -n "$PERM_SNIPPET" ]; echo $?) "markers=$PERM_MARKERS block=${#PERM_SNIPPET} bytes"
TREE_LINE=$(grep -n -F 'ig_perm_fix tree /var/www/irongate root www-data 755' "$INSTALLER" | cut -d: -f1)
PERM_LINE=$(grep -n -F '# >>> IG_DB_SIDECAR_PERM' "$INSTALLER" | cut -d: -f1)
check "T6 the re-tighten runs AFTER the tree permission pass" \
      $([ -n "$TREE_LINE" ] && [ -n "$PERM_LINE" ] && [ "$TREE_LINE" -lt "$PERM_LINE" ]; echo $?) \
      "tree=${TREE_LINE:-none} retighten=${PERM_LINE:-none}"
if [ -n "$PERM_SNIPPET" ]; then
    printf '%s\n' "$PERM_SNIPPET" | sed -e "s#/var/www/irongate#$WWW#g" > "$T/perm.sh"
    ig_perm_fix() { echo "PERMFIX $*" >> "$T/permfix.args"; }   # the real helper needs root; record the request
    reset_logs; mkdb
    : > "$WWW/dhcp.db-sidecar.$TS-journal"; : > "$WWW/dhcp.db-sidecar.$TS-shm"
    ( IG_DB_STAMP=$TS; . "$T/perm.sh" ) >/dev/null 2>&1
    check "T6 a moved journal sidecar is put back to root:root 0600" \
          $(grep -qF -- "PERMFIX file $WWW/dhcp.db-sidecar.$TS-journal root root 600" "$T/permfix.args" 2>/dev/null; echo $?) \
          "$(cat "$T/permfix.args" 2>/dev/null)"
    check "T6 a moved shm sidecar is put back to root:root 0600" \
          $(grep -qF -- "PERMFIX file $WWW/dhcp.db-sidecar.$TS-shm root root 600" "$T/permfix.args" 2>/dev/null; echo $?) \
          "$(cat "$T/permfix.args" 2>/dev/null)"
    check "T6 a sidecar that does not exist is not touched" \
          $(! grep -qF -- "dhcp.db-sidecar.$TS-wal" "$T/permfix.args" 2>/dev/null; echo $?) "$(cat "$T/permfix.args" 2>/dev/null)"
else
    check "T6 a moved journal sidecar is put back to root:root 0600" 1 "no IG_DB_SIDECAR_PERM block in $INSTALLER"
    check "T6 a moved shm sidecar is put back to root:root 0600" 1 "no IG_DB_SIDECAR_PERM block in $INSTALLER"
    check "T6 a sidecar that does not exist is not touched" 1 "no IG_DB_SIDECAR_PERM block in $INSTALLER"
fi

rm -rf "$T"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
