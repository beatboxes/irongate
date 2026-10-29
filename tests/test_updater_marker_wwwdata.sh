#!/bin/bash
# Irongate updater: the installed_commit marker is written as www-data, read back, and a stamp that does not land is
# a failure.
#
# Runs src/irongate-updater.sh with every path rewritten to a scratch dir and curl replaced by a shim, like
# tests/test_updater.sh, and checks
#   M1  the marker write goes through $IG_DB_RUNUSER as www-data ("-u www-data -- <sqlite3>"), never through a bare
#       sqlite3 as root, and leaves installed_commit == cut -c1-7 of the pinned commit
#   M2  a write that fails (sqlite3 exit 8, SQLITE_READONLY) makes the updater exit non-zero, log an error, not log
#       "Update complete!" and leave installed_commit alone - and is NOT retried (only SQLITE_BUSY/SQLITE_LOCKED is)
#   M3  a marker value that is not 7 lowercase hex characters is refused before any write (non-zero exit, no write)
#   M4  LOCK CONTENTION, with the real sqlite3 CLI and a scratch database: a second connection holding the write lock
#       and releasing it inside $IG_DB_BUSY_MS lets the write through (one attempt, no retry); held past the timeout and
#       past the single retry it is a loud non-zero failure with no success line and installed_commit unchanged
#
# Needs root (the updater's pin file must be root:root) and a real sqlite3 CLI, so run it in a disposable container
# with no network; the host's sqlite3 and its libraries are mounted the way tests/test_installer_o4.py mounts visudo:
#
#   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro \
#       -v /usr/bin/sqlite3:/host-sqlite3:ro -v /lib/x86_64-linux-gnu:/hostlib:ro \
#       -w /w debian:bookworm-slim bash tests/test_updater_marker_wwwdata.sh src/irongate-updater.sh
#
# Exit status 0 = every case passed. Against the updater of f1ef11e it fails.

set -u
[ "${IRONGATE_TEST_SANDBOX:-}" = "1" ] || { echo "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 2; }
SRC=${1:?usage: test_updater_marker_wwwdata.sh <irongate-updater.sh>}
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

T=$(mktemp -d /tmp/irongate-marker-test.XXXXXX)
mkdir -p "$T/bin" "$T/rootbin" "$T/db" "$T/stage"
export T MARK="$T/installer-ran" UPDATER="$T/updater.sh"
PINNED_COMMIT=d5bd2189ac571a0b3964ec67167f73a75e76386e
SHORT=${PINNED_COMMIT:0:7}

# --- the real sqlite3 CLI: lock contention cannot be emulated ---------------------
if command -v sqlite3 >/dev/null 2>&1; then
    REAL_SQLITE=$(command -v sqlite3)
elif [ -x /host-sqlite3 ] && [ -x /hostlib/ld-linux-x86-64.so.2 ]; then
    REAL_SQLITE="$T/bin/sqlite3-real"
    printf '#!/bin/sh\nexec /hostlib/ld-linux-x86-64.so.2 --library-path /hostlib /host-sqlite3 "$@"\n' > "$REAL_SQLITE"
    chmod +x "$REAL_SQLITE"
else
    echo "refusing to run: no real sqlite3 CLI (mount the host's: -v /usr/bin/sqlite3:/host-sqlite3:ro -v /lib/x86_64-linux-gnu:/hostlib:ro)" >&2
    exit 2
fi
"$REAL_SQLITE" --version >/dev/null 2>&1 || { echo "the real sqlite3 CLI does not run: $REAL_SQLITE" >&2; exit 2; }

# --- updater under test: same code, scratch paths ------------------------------
sed -e "s#/etc/irongate/updater-pin.conf#$T/pin.conf#g" \
    -e "s#/opt/irongate/.update#$T/stage#g" \
    -e "s#/var/www/irongate/dhcp.db#$T/db/dhcp.db#g" \
    -e "s#/run/irongate-updater.lock#$T/updater.lock#g" \
    -e "s#/var/log/irongate-update.log#$T/update.log#g" "$SRC" > "$UPDATER"
if grep -q -e '/etc/irongate' -e '/var/www/irongate' -e '/var/log/irongate' -e '/run/irongate' "$UPDATER"; then
    echo "path rewrite incomplete" >&2; exit 2
fi

# --- shims -----------------------------------------------------------------------
# runuser: records its argv (that is the evidence that the write runs as www-data) and, unless IG_RUNUSER_RC is set,
# runs the command it was given. It does not drop privileges: the test proves the CALL SHAPE, not the kernel's answer.
cat > "$T/bin/runuser" <<'SH'
#!/bin/bash
echo "ARGS $*" >> "$T/runuser.args"
if [ -n "${IG_RUNUSER_RC:-}" ]; then exit "$IG_RUNUSER_RC"; fi
[ "${1:-}" = "-u" ] && shift 2
[ "${1:-}" = "--" ] && shift
exec "$@"
SH
# a bare `sqlite3` (what root would run) is recorded too, so "the marker never went through root" is checkable
cat > "$T/rootbin/sqlite3" <<SH
#!/bin/bash
echo "ROOT-SQLITE3 \$*" >> "\$T/root-sqlite3.args"
exec $REAL_SQLITE "\$@"
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
chmod +x "$T/bin/runuser" "$T/rootbin/sqlite3" "$T/bin/curl"
export IG_DB_RUNUSER="$T/bin/runuser" IG_DB_SQLITE3="$REAL_SQLITE" IG_DB_BUSY_MS=5000
export PATH="$T/rootbin:$T/bin:$PATH"

# --- fixture installer (>= 100000 bytes, valid bash, stamps nothing) --------------
{
    echo '#!/bin/bash'
    echo 'echo ran >> "$MARK"'
    yes '# padding to pass the updater size gate ------------------------------------' | head -n 1500
} > "$T/good-installer.sh"
GOOD_SHA=$(sha256sum "$T/good-installer.sh" | cut -d' ' -f1)

# --- helpers -----------------------------------------------------------------------
pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}
mkdb() {   # $1=installed_commit
    rm -f "$T/db/dhcp.db"
    "$REAL_SQLITE" "$T/db/dhcp.db" "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
        INSERT OR REPLACE INTO settings VALUES ('auto_update_enabled', 'true');
        INSERT OR REPLACE INTO settings VALUES ('installed_commit', '$1');"
}
dbvalue() { "$REAL_SQLITE" "$T/db/dhcp.db" "SELECT value FROM settings WHERE key='installed_commit';"; }
reset() {   # $1=installed_commit
    rm -rf "$T/stage" "$T/curl.log" "$T/update.log" "$T/pin.conf" "$T/runuser.args" "$T/root-sqlite3.args" \
           "$T/installer-ran" "$T/updater.lock" "$T/stdout" "$T/lockholder"
    mkdir -p "$T/stage"; : > "$T/curl.log"; : > "$T/update.log"
    mkdb "$1"; cp "$T/good-installer.sh" "$T/served-installer"
    printf "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$GOOD_SHA\n" > "$T/pin.conf"
    chown 0:0 "$T/pin.conf"; chmod 644 "$T/pin.conf"
}
run() { ( cd "$T" && bash "$UPDATER" "$@" ) > "$T/stdout" 2>&1; RC=$?; }
ran()   { [ -f "$MARK" ]; }
logged() { grep -q -- "$1" "$T/update.log"; }
# every write of the marker, as recorded on the runuser (www-data) path
marker_writes() { grep -F -- "ARGS -u www-data -- $REAL_SQLITE" "$T/runuser.args" 2>/dev/null \
                     | grep -cF -- "VALUES ('installed_commit', '"; }
# the same, for one exact value
marker_writes_of() { grep -F -- "ARGS -u www-data -- $REAL_SQLITE" "$T/runuser.args" 2>/dev/null \
                     | grep -F -- "VALUES ('installed_commit', '$1')" | wc -l; }
# what root's own sqlite3 was asked to do
root_sqlite_calls() { grep -c . "$T/root-sqlite3.args" 2>/dev/null || true; }
root_marker_write() { grep -F -- "ROOT-SQLITE3" "$T/root-sqlite3.args" 2>/dev/null \
                     | grep -cF -- "VALUES ('installed_commit', '"; }
hold_write_lock() {   # $1 = seconds to hold the write lock; sets HOLDER
    ( printf 'BEGIN IMMEDIATE;\nINSERT OR REPLACE INTO settings VALUES(%slock%s,%s1%s);\n' "'" "'" "'" "'"
      sleep "$1"
      printf 'COMMIT;\n' ) | "$REAL_SQLITE" "$T/db/dhcp.db" >/dev/null 2>&1 &
    HOLDER=$!
}
wait_for_write_lock() {   # poll until another writer really holds it (a probe write must fail)
    local i
    for i in $(seq 1 50); do
        if ! "$REAL_SQLITE" -cmd ".timeout 0" "$T/db/dhcp.db" "INSERT OR REPLACE INTO settings VALUES('probe','x');" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ============================ M1: the marker write runs as www-data ============================
reset oldoldo; run --force
check "M1 the update succeeds (exit 0)" $([ "$RC" -eq 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "M1 the marker write goes through $IG_DB_RUNUSER as www-data (one INSERT, correct value)" \
      $([ "$(marker_writes_of "$SHORT")" -eq 1 ]; echo $?) "runuser args: $(grep -F -- "installed_commit" "$T/runuser.args" 2>/dev/null | tr '\n' ' ')"
check "M1 the write command is -u www-data -- <sqlite3> -cmd .timeout N <db> <sql>" \
      $(grep -F -- "ARGS -u www-data -- $REAL_SQLITE -cmd .timeout" "$T/runuser.args" 2>/dev/null | grep -qF -- "VALUES ('installed_commit', '$SHORT')"; echo $?) \
      "$(head -2 "$T/runuser.args" 2>/dev/null)"
check "M1 installed_commit is cut -c1-7 of the pin afterwards" $([ "$(dbvalue)" = "$SHORT" ]; echo $?) "installed_commit=$(dbvalue)"
check "M1 control: root's own sqlite3 WAS used for the reads (so the check below is not vacuous)" \
      $([ "$(root_sqlite_calls)" -ge 1 ]; echo $?) "root calls: $(cat "$T/root-sqlite3.args" 2>/dev/null | tr '\n' ' ')"
check "M1 no bare root sqlite3 wrote installed_commit" $([ "$(root_marker_write)" -eq 0 ]; echo $?) "root writes: $(grep -F -- "installed_commit" "$T/root-sqlite3.args" 2>/dev/null)"
check "M1 success is logged after the stamp" $(logged "Update complete"; echo $?) "$(tail -3 "$T/update.log")"

# ============================ M2: a write that does not land is a failure ============================
reset oldoldo; IG_RUNUSER_RC=8 run --force
check "M2 sqlite3 exit 8 (SQLITE_READONLY): the updater exits non-zero" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "M2 the failure is logged as an error naming installed_commit" $(logged "ERROR: could not record installed_commit"; echo $?) "$(tail -3 "$T/update.log")"
check "M2 'Update complete!' is NOT logged" $(! logged "Update complete"; echo $?) "$(tail -3 "$T/update.log")"
check "M2 installed_commit is left as it was" $([ "$(dbvalue)" = oldoldo ]; echo $?) "installed_commit=$(dbvalue)"
check "M2 a non-busy failure is NOT retried (exactly one attempt)" $([ "$(marker_writes)" -eq 1 ]; echo $?) "attempts=$(marker_writes) $(cat "$T/runuser.args" 2>/dev/null | tr '\n' ' ')"

# ============================ M3: the marker value must be 7 lowercase hex ============================
for bad in ZZZZZZZ abc123 01234567 ''; do
    reset oldoldo
    sed "s|^TARGET_COMMIT=.*|TARGET_COMMIT=$bad|" "$UPDATER" > "$T/updater-badmarker.sh"
    ( cd "$T" && bash "$T/updater-badmarker.sh" --force ) > "$T/stdout" 2>&1; RC=$?
    check "M3 marker value '${bad:-<empty>}' is refused (non-zero exit)" $([ "$RC" -ne 0 ]; echo $?) "rc=$RC log=$(tail -2 "$T/update.log")"
    check "M3 marker value '${bad:-<empty>}' is refused before any write" $([ "$(marker_writes)" -eq 0 ] && [ "$(root_marker_write)" -eq 0 ]; echo $?) "runuser=$(cat "$T/runuser.args" 2>/dev/null | tr '\n' ' ')"
    check "M3 marker value '${bad:-<empty>}': installed_commit unchanged, no success line" \
          $([ "$(dbvalue)" = oldoldo ] && ! logged "Update complete"; echo $?) "installed_commit=$(dbvalue)"
done

# ============================ M4: lock contention with the real sqlite3 ============================
# (a) the other writer releases the lock inside the busy timeout: the write goes through, on its first attempt
reset oldoldo
hold_write_lock 2
wait_for_write_lock || echo "WARNING: the probe never saw the write lock (timing)" >&2
IG_DB_BUSY_MS=6000 run --force
wait "$HOLDER"
check "M4a lock released inside the timeout: the update succeeds (exit 0)" $([ "$RC" -eq 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "M4a installed_commit is the pinned short sha" $([ "$(dbvalue)" = "$SHORT" ]; echo $?) "installed_commit=$(dbvalue)"
check "M4a the waiting write went in on its first attempt (the timeout, not the retry)" \
      $([ "$(grep -F -- "ARGS -u www-data -- $REAL_SQLITE" "$T/runuser.args" 2>/dev/null | grep -cF -- "VALUES ('last_update_check', datetime")" -eq 1 ]; echo $?) \
      "$(cat "$T/runuser.args" 2>/dev/null | tr '\n' ' ')"

# (b) the other writer holds the lock past the timeout and past the single retry: a loud failure, nothing stamped
reset oldoldo
hold_write_lock 8
wait_for_write_lock || echo "WARNING: the probe never saw the write lock (timing)" >&2
IG_DB_BUSY_MS=500 run --force
STILL_LOCKED_RC=$RC
check "M4b lock held past the timeout and the retry: the updater exits non-zero" $([ "$STILL_LOCKED_RC" -ne 0 ]; echo $?) "rc=$STILL_LOCKED_RC log=$(tail -3 "$T/update.log")"
check "M4b the contention is logged as an error naming installed_commit" $(logged "ERROR: could not record installed_commit"; echo $?) "$(tail -3 "$T/update.log")"
check "M4b 'Update complete!' is NOT logged" $(! logged "Update complete"; echo $?) "$(tail -3 "$T/update.log")"
check "M4b installed_commit is left as it was" $([ "$(dbvalue)" = oldoldo ]; echo $?) "installed_commit=$(dbvalue)"
check "M4b the busy write was retried exactly once (two attempts)" $([ "$(marker_writes)" -eq 2 ]; echo $?) "attempts=$(marker_writes)"
wait "$HOLDER"
# control: the same run, with nothing holding the database, succeeds - so M4b measured the contention
reset oldoldo; run --force
check "M4b control: after the lock is released the same update succeeds and stamps the pin" \
      $([ "$RC" -eq 0 ] && [ "$(dbvalue)" = "$SHORT" ]; echo $?) "rc=$RC installed_commit=$(dbvalue)"

rm -rf "$T"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
