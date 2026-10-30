#!/bin/bash
# Irongate updater: the installed_commit read-back retries once when the database is busy, and a read-back that still
# fails is a loud failure.
#
# Runs src/irongate-updater.sh end to end with every path rewritten into a scratch dir and the root-only steps shimmed,
# like tests/test_updater_marker_wwwdata.sh, but with no root and no container: this host's uid cannot chown a file, so
# the pin-ownership check and the snapshot chown are answered by shims. The database shim ($IG_DB_SQLITE3) counts its
# invocations, so the behaviour is deterministic - no sleeping and no timing race:
#   R1  the read-back's FIRST attempt exits 5 (SQLITE_BUSY) and the second returns the value: the update succeeds
#       (exit 0, "Update complete!" logged) and the read was attempted exactly twice
#   R2  every read attempt exits 5: the updater exits non-zero, logs the read-back error, does NOT log
#       "Update complete!", and still attempted the read exactly twice (one retry, not a loop)
#
#   bash tests/test_updater_marker_readback.sh src/irongate-updater.sh
#
# Exit status 0 = every case passed. Against the updater of 8ed55cf it fails (no retry: R1 exits 1 after one attempt).

set -u
SRC=${1:?usage: test_updater_marker_readback.sh <irongate-updater.sh>}
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

REAL_SQLITE=$(command -v sqlite3 2>/dev/null || true)
[ -n "$REAL_SQLITE" ] && [ -x "$REAL_SQLITE" ] || { echo "refusing to run: no sqlite3 CLI" >&2; exit 2; }
REAL_STAT=$(command -v stat) || exit 2
REAL_TAR=$(command -v tar) || exit 2

T=$(mktemp -d "${IG_TEST_TMPDIR:-/tmp}/irongate-readback-test.XXXXXX") || exit 2
mkdir -p "$T/bin" "$T/db" "$T/stage"
export T
PINNED_COMMIT=d5bd2189ac571a0b3964ec67167f73a75e76386e
SHORT=${PINNED_COMMIT:0:7}

pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  --  $3"; fi
}

# ---- the updater under test: same code, scratch paths ---------------------------------------------
UPDATER="$T/updater.sh"
sed -e "s#/etc/irongate/updater-pin.conf#$T/pin.conf#g" \
    -e "s#/opt/irongate/.update#$T/stage#g" \
    -e "s#/var/www/irongate/dhcp.db#$T/db/dhcp.db#g" \
    -e "s#/run/irongate-updater.lock#$T/updater.lock#g" \
    -e "s#/var/log/irongate-update.log#$T/update.log#g" "$SRC" > "$UPDATER"
if grep -q -e '/etc/irongate' -e '/var/www/irongate' -e '/var/log/irongate' -e '/run/irongate' "$UPDATER"; then
    echo "path rewrite incomplete" >&2; exit 2
fi

# ---- shims ---------------------------------------------------------------------------------------
# runuser: record the call (evidence that the read runs as www-data) and run what it was given
cat > "$T/bin/runuser" <<'SH'
#!/bin/bash
echo "ARGS $*" >> "$T/runuser.args"
[ "${1:-}" = "-u" ] && shift 2
[ "${1:-}" = "--" ] && shift
exec "$@"
SH
# stat: the pin-file ownership check is the one call that must report root:root; everything else is the real stat
cat > "$T/bin/stat" <<SH
#!/bin/bash
case " \$* " in *" /dev/fd/3 "*) echo "0:0:644"; exit 0 ;; esac
exec $REAL_STAT "\$@"
SH
# chown: uid 1000 cannot change an owner, so record the request and succeed
cat > "$T/bin/chown" <<'SH'
#!/bin/bash
echo "CHOWN $*" >> "$T/chown.args"
exit 0
SH
cat > "$T/bin/curl" <<'SH'
#!/bin/bash
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out="$2"; shift ;; http*) url="$1" ;; esac
    shift
done
echo "$url" >> "$T/curl.log"
case "$url" in
    https://raw.githubusercontent.com/beatboxes/irongate/*/irongate-install.sh) cp "$T/served-installer" "$out" ;;
    *) exit 22 ;;
esac
SH
chmod +x "$T/bin/runuser" "$T/bin/stat" "$T/bin/chown" "$T/bin/curl"

# the database shim: counts read-back attempts and fails them on demand; every other statement is the real sqlite3
cat > "$T/bin/db-sqlite" <<SH
#!/bin/bash
sql="\${!#}"
case "\$sql" in
    "SELECT value FROM settings WHERE key='installed_commit';")
        n=\$(( \$(cat "$T/read.count" 2>/dev/null || echo 0) + 1 ))
        echo "\$n" > "$T/read.count"
        if [ -n "\${IG_READ_RC:-}" ]; then exit "\$IG_READ_RC"; fi
        [ "\$n" -eq 1 ] && exit 5
        exec $REAL_SQLITE "\$@"
        ;;
esac
exec $REAL_SQLITE "\$@"
SH
chmod +x "$T/bin/db-sqlite"
export IG_DB_RUNUSER="$T/bin/runuser" IG_DB_SQLITE3="$T/bin/db-sqlite" IG_DB_BUSY_MS=5000
PATH="$T/bin:$PATH"; export PATH

# ---- fixture installer (>= 100000 bytes, valid bash) ----------------------------------------------
{
    echo '#!/bin/bash'
    echo 'echo ran >> "$T/installer-ran"'
    yes '# padding to pass the updater size gate ------------------------------------' | head -n 1500
} > "$T/good-installer.sh"
GOOD_SHA=$(sha256sum "$T/good-installer.sh" | cut -d' ' -f1)

mkdb() {   # $1 = installed_commit
    rm -f "$T/db/dhcp.db"
    "$REAL_SQLITE" "$T/db/dhcp.db" "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
        INSERT OR REPLACE INTO settings VALUES ('auto_update_enabled', 'true');
        INSERT OR REPLACE INTO settings VALUES ('installed_commit', '$1');"
}
dbvalue() { "$REAL_SQLITE" "$T/db/dhcp.db" "SELECT value FROM settings WHERE key='installed_commit';"; }
reset() {   # $1 = installed_commit
    rm -rf "$T/stage" "$T/curl.log" "$T/update.log" "$T/pin.conf" "$T/runuser.args" "$T/chown.args" \
           "$T/installer-ran" "$T/updater.lock" "$T/stdout" "$T/read.count"
    mkdir -p "$T/stage"; : > "$T/curl.log"; : > "$T/update.log"
    mkdb "$1"; cp "$T/good-installer.sh" "$T/served-installer"
    printf "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$GOOD_SHA\n" > "$T/pin.conf"
}
run() { ( cd "$T" && bash "$UPDATER" "$@" ) > "$T/stdout" 2>&1; RC=$?; }
logged() { grep -q -- "$1" "$T/update.log"; }
read_attempts() { cat "$T/read.count" 2>/dev/null || echo 0; }
reads_as_wwwdata() { grep -F -- "ARGS -u www-data -- $T/bin/db-sqlite" "$T/runuser.args" 2>/dev/null \
                         | grep -cF -- "SELECT value FROM settings WHERE key='installed_commit';"; }

# ============================ R1: one busy read, then the value ============================
reset oldoldo; unset IG_READ_RC
run --force
check "R1 the update succeeds when the first read-back attempt is SQLITE_BUSY (exit 0)" \
      $([ "$RC" -eq 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "R1 the read-back was attempted exactly twice (one retry)" $([ "$(read_attempts)" -eq 2 ]; echo $?) "attempts=$(read_attempts)"
check "R1 both attempts went through runuser as www-data (never a bare root read)" \
      $([ "$(reads_as_wwwdata)" -eq 2 ]; echo $?) "$(cat "$T/runuser.args" 2>/dev/null | tr '\n' ' ')"
check "R1 installed_commit is the pinned short sha afterwards" $([ "$(dbvalue)" = "$SHORT" ]; echo $?) "installed_commit=$(dbvalue)"
check "R1 success is logged after the stamp" $(logged "Update complete"; echo $?) "$(tail -3 "$T/update.log")"
check "R1 no read-back error is logged" $(! logged "read-back failed"; echo $?) "$(tail -3 "$T/update.log")"

# ============================ R2: busy on both attempts ============================
reset oldoldo; export IG_READ_RC=5
run --force
unset IG_READ_RC
check "R2 busy on both attempts: the updater exits non-zero" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "R2 the failure is logged as a read-back error naming installed_commit" \
      $(logged "ERROR: installed_commit read-back failed"; echo $?) "$(tail -3 "$T/update.log")"
check "R2 'Update complete!' is NOT logged" $(! logged "Update complete"; echo $?) "$(tail -3 "$T/update.log")"
check "R2 the busy read was retried exactly once (two attempts, not a loop)" $([ "$(read_attempts)" -eq 2 ]; echo $?) \
      "attempts=$(read_attempts)"

# control: a read that fails with a status other than 5/6 is NOT retried
reset oldoldo; export IG_READ_RC=8
run --force
unset IG_READ_RC
check "R2 control: a read-back that exits 8 (not busy) is not retried" $([ "$RC" -ne 0 ] && [ "$(read_attempts)" -eq 1 ]; echo $?) \
      "rc=$RC attempts=$(read_attempts)"

rm -rf "$T"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
