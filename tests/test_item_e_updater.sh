#!/bin/bash
# Irongate updater hardening (item E): one update at a time, --force at the pinned commit is a no-op, and a failed
# installer cannot leave the configuration directory half rewritten.
#
# Runs src/irongate-updater.sh with every path rewritten to a scratch dir and curl, sqlite3 replaced by shims (like
# tests/test_updater.sh) and checks
#   B1  a second run while the lock is held logs "another update is running" and exits non-zero, runs and downloads nothing;
#       the lock is not sticky; the installer does not inherit the lock descriptor; a lock file the updater creates is
#       root-only (0600) and an existing lock file keeps its mode
#   B2  --force when installed_commit == the pinned commit logs "installed == pin", exits 0 and downloads nothing
#   B3  before the installer runs the configuration directory (the pin file's directory) is snapshotted to a root:root 0600
#       tarball; a failing installer's changes are undone from it (content, owner, mode, deleted files), the run exits 1 and
#       logs it; a snapshot that cannot be taken stops the run before the installer; success removes the snapshot
#   A11 the download has --max-time
#
# Needs root (owners are checked), so run it in a disposable container with no network:
#
#   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
#       python:3.12-slim bash tests/test_item_e_updater.sh src/irongate-updater.sh
#
# Exit status 0 = every case passed. Against the updater of c866e4c it fails.

set -u
[ "${IRONGATE_TEST_SANDBOX:-}" = "1" ] || { echo "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 2; }
SRC=${1:?usage: test_item_e_updater.sh <irongate-updater.sh>}
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

T=$(mktemp -d /tmp/irongate-item-e-updater.XXXXXX)
mkdir -p "$T/bin" "$T/db" "$T/stage" "$T/etc"
export T MARK="$T/installer-ran" UPDATER="$T/updater.sh"
PINNED_COMMIT=d5bd2189ac571a0b3964ec67167f73a75e76386e
SHORT=${PINNED_COMMIT:0:7}
ETC=$T/etc                      # stands for /etc/irongate: the pin file's directory
LOCK=$T/updater.lock            # stands for /run/irongate-updater.lock

# --- updater under test: same code, scratch paths ------------------------------
sed -e "s#/etc/irongate/updater-pin.conf#$ETC/updater-pin.conf#g" \
    -e "s#/opt/irongate/.update#$T/stage#g" \
    -e "s#/var/www/irongate/dhcp.db#$T/db/dhcp.db#g" \
    -e "s#/run/irongate-updater.lock#$LOCK#g" \
    -e "s#/var/log/irongate-update.log#$T/update.log#g" "$SRC" > "$UPDATER"
if grep -q -e '/etc/irongate' -e '/var/www/irongate' -e '/var/log/irongate' -e '/run/irongate' "$UPDATER"; then
    echo "path rewrite incomplete" >&2; exit 2
fi

# --- shims -----------------------------------------------------------------------
cat > "$T/bin/sqlite3" <<'SH'
#!/bin/bash
sql="$2"
if [[ "$sql" =~ SELECT\ value\ FROM\ settings\ WHERE\ key=\'([a-z_]+)\' ]]; then
    f="$T/db/${BASH_REMATCH[1]}"; [ -f "$f" ] && cat "$f"; exit 0
elif [[ "$sql" =~ VALUES\ \(\'([a-z_]+)\',\ \'([^\']*)\'\) ]]; then
    printf '%s\n' "${BASH_REMATCH[2]}" > "$T/db/${BASH_REMATCH[1]}"; exit 0
elif [[ "$sql" =~ VALUES\ \(\'([a-z_]+)\',\ datetime ]]; then
    echo now > "$T/db/${BASH_REMATCH[1]}"; exit 0
fi
exit 0
SH
cat > "$T/bin/curl" <<'SH'
#!/bin/bash
url=""; out=""
echo "ARGS $*" >> "$T/curl.args"
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
# tar: fails on request (IG_TAR_FAIL=create|extract), otherwise the real one
REAL_TAR=$(command -v tar)
cat > "$T/bin/tar" <<SH
#!/bin/bash
case " \$* " in
    *" -cpf "*|*" -c "*) [ "\${IG_TAR_FAIL:-}" = create ] && { echo "tar: simulated failure" >&2; exit 2; } ;;
    *" -xf "*) [ "\${IG_TAR_FAIL:-}" = extract ] && { echo "tar: simulated failure" >&2; exit 2; } ;;
esac
exec $REAL_TAR "\$@"
SH
chmod +x "$T/bin/sqlite3" "$T/bin/curl" "$T/bin/tar"
export PATH="$T/bin:$PATH"

# --- fixture installers (>= 100000 bytes, valid bash) -----------------------------
# Every fixture records what the updater left for it: the snapshot's owner:group:mode and file list, whether the lock
# descriptor leaked into it, and the configuration directory as it found it.
make_installer() {   # $1=file $2=extra body
    {
        echo '#!/bin/bash'
        echo 'echo ran >> "$MARK"'
        echo 'SNAP="$T/stage/conf-snapshot.tar"'
        echo 'stat -c "%u:%g:%a" "$SNAP" > "$MARK.snapstat" 2>/dev/null || echo missing > "$MARK.snapstat"'
        echo 'tar -tf "$SNAP" > "$MARK.snaplist" 2>/dev/null || : > "$MARK.snaplist"'
        echo '[ -e /proc/self/fd/9 ] && echo leaked > "$MARK.fd9" || echo closed > "$MARK.fd9"'
        printf '%s\n' "$2"
        yes '# padding to pass the updater size gate ------------------------------------' | head -n 1500
    } > "$1"
}
make_installer "$T/good.sh" ''
make_installer "$T/fail-mutating.sh" 'echo "REWRITTEN BY INSTALLER" > "$ETC/config.yaml"; chmod 666 "$ETC/config.yaml"; chown 0:0 "$ETC/config.yaml"
rm -f "$ETC/auth.json"; echo new > "$ETC/created-by-installer"; chmod 000 "$ETC/access-control.json"; exit 3'
make_installer "$T/good-mutating.sh" 'echo "REWRITTEN BY INSTALLER" > "$ETC/config.yaml"; echo new > "$ETC/created-by-installer"'
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
GOOD_SHA=$(sha_of "$T/good.sh"); FAILM_SHA=$(sha_of "$T/fail-mutating.sh"); GOODM_SHA=$(sha_of "$T/good-mutating.sh")
export ETC

# --- helpers -----------------------------------------------------------------------
pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}
reset() {   # $1=installed_commit
    rm -rf "$T/stage" "$T/curl.log" "$T/curl.args" "$T/update.log" "$ETC" "$T/db"/* "$MARK" "$MARK".* "$LOCK"
    mkdir -p "$T/stage" "$ETC"; : > "$T/curl.log"; : > "$T/update.log"; : > "$T/curl.args"
    echo true > "$T/db/auto_update_enabled"; echo "$1" > "$T/db/installed_commit"
    # a configuration directory as the web tier leaves it: root:www-data (33), group-writable, several owners and modes
    chown 0:33 "$ETC"; chmod 775 "$ETC"
    printf 'genuine config\n' > "$ETC/config.yaml"; chown 0:33 "$ETC/config.yaml"; chmod 664 "$ETC/config.yaml"
    printf '{"genuine":true}\n' > "$ETC/auth.json"; chown 33:33 "$ETC/auth.json"; chmod 640 "$ETC/auth.json"
    printf '{"acl":1}\n' > "$ETC/access-control.json"; chown 0:33 "$ETC/access-control.json"; chmod 660 "$ETC/access-control.json"
}
goodpin() {   # $1=sha
    printf "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$1\n" > "$ETC/updater-pin.conf"; chown 0:0 "$ETC/updater-pin.conf"; chmod 644 "$ETC/updater-pin.conf"
}
run() { ( cd "$T" && bash "$UPDATER" "$@" ) > "$T/stdout" 2>&1; RC=$?; }
ran()   { [ -f "$MARK" ]; }
logged() { grep -q -- "$1" "$T/update.log"; }
curled() { grep -q -- "$1" "$T/curl.log"; }
installed() { cat "$T/db/installed_commit" 2>/dev/null; }
st() { stat -c '%u:%g:%a' "$1" 2>/dev/null || echo missing; }

# ============================ B1: one update at a time ============================
reset oldoldo; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"
( exec 8>>"$LOCK"; flock -n 8 || exit 9; run --force; echo "$RC" > "$T/rc.locked" )
RCL=$(cat "$T/rc.locked" 2>/dev/null)
check "B1 lock held by another run: exit non-zero" $([ -n "$RCL" ] && [ "$RCL" -ne 0 ]; echo $?) "rc=$RCL"
check "B1 lock held: the log says 'another update is running'" $(logged "another update is running"; echo $?) "log: $(tail -3 "$T/update.log")"
check "B1 lock held: nothing downloaded, installer not run, installed_commit untouched" $(! ran && [ ! -s "$T/curl.log" ] && [ "$(installed)" = oldoldo ]; echo $?) "ran=$(ran && echo y) curl=$(cat "$T/curl.log")"
run --force
check "B1 control: once the other run is gone the lock is free and the update runs (exit 0)" $(ran && [ $RC -eq 0 ] && [ "$(installed)" = "$SHORT" ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "B1 the installer does not inherit the lock descriptor (fd 9 closed)" $([ "$(cat "$MARK.fd9" 2>/dev/null)" = closed ]; echo $?) "fd9: $(cat "$MARK.fd9" 2>/dev/null)"
# reset removes the lock file, so this run has to create it itself
reset oldoldo; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"
run --force
check "B1 a lock file the updater creates is root-only (root:root 0600)" $([ $RC -eq 0 ] && [ "$(st "$LOCK")" = "0:0:600" ]; echo $?) "rc=$RC lock stat: $(st "$LOCK")"
( umask 022; : > "$LOCK" ); chmod 0644 "$LOCK"   # control: a pre-existing lock file, world-readable
run --force
check "B1 control: a pre-existing lock file keeps the mode it had (0644 stays 0644)" $([ $RC -eq 0 ] && [ "$(st "$LOCK")" = "0:0:644" ]; echo $?) "lock stat: $(st "$LOCK")"
reset oldoldo; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"; rm -rf "$LOCK"; mkdir "$LOCK"   # lock path unusable (a directory)
run --force
check "B1 a lock file that cannot be opened stops the run (fail closed, logged), installer not run" $(! ran && [ $RC -ne 0 ] && logged "lock"; echo $?) "rc=$RC ran=$(ran && echo y) log=$(tail -2 "$T/update.log")"
rm -rf "$LOCK"

# ============================ B2: --force at the pinned commit is a no-op ============================
reset "$SHORT"; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"; run --force
check "B2 --force at installed == pin: exit 0" $([ $RC -eq 0 ]; echo $?) "rc=$RC"
check "B2 --force at installed == pin: the log says 'installed == pin'" $(logged "installed == pin"; echo $?) "log: $(tail -3 "$T/update.log")"
check "B2 --force at installed == pin: nothing downloaded, installer not run" $(! ran && [ ! -s "$T/curl.log" ] && ! curled raw.githubusercontent; echo $?) "ran=$(ran && echo y) curl=$(cat "$T/curl.log")"
check "B2 --force at installed == pin: installed_commit unchanged" $([ "$(installed)" = "$SHORT" ]; echo $?) "now $(installed)"
reset oldoldo; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"; run --force
check "B2 control: --force with another installed commit still installs the pinned one" $(ran && [ $RC -eq 0 ] && [ "$(installed)" = "$SHORT" ]; echo $?) "rc=$RC installed=$(installed)"
reset "$SHORT"; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"; run
check "B2 control: no --force at installed == pin is still 'Already up to date'" $(! ran && [ $RC -eq 0 ] && logged "Already up to date"; echo $?) "rc=$RC"

# ============================ B3: snapshot and restore ============================
reset oldoldo; goodpin "$GOOD_SHA"; cp "$T/good.sh" "$T/served-installer"; run --force
check "B3 snapshot exists while the installer runs and is root:root 0600" $([ "$(cat "$MARK.snapstat" 2>/dev/null)" = "0:0:600" ]; echo $?) "snapshot stat: $(cat "$MARK.snapstat" 2>/dev/null)"
snaplist_ok() { local f; for f in config.yaml auth.json access-control.json updater-pin.conf; do grep -q "^\./$f$" "$MARK.snaplist" 2>/dev/null || return 1; done; }
check "B3 snapshot holds the configuration directory (config.yaml, auth.json, access-control.json, the pin)" $(snaplist_ok; echo $?) "list: $(tr '\n' ' ' < "$MARK.snaplist" 2>/dev/null)"
check "B3 snapshot is not served from the world-readable parts: it sits in the root-only staging directory" $([ "$(st "$T/stage")" = "0:0:700" ]; echo $?) "stage $(st "$T/stage")"
check "B3 successful installer: snapshot removed afterwards, logged" $([ ! -e "$T/stage/conf-snapshot.tar" ] && logged "snapshot removed"; echo $?) "stage: $(ls "$T/stage")"

reset oldoldo; cp "$T/fail-mutating.sh" "$T/served-installer"; goodpin "$FAILM_SHA"
cfg_sum=$(sha256sum < "$ETC/config.yaml"); auth_sum=$(sha256sum < "$ETC/auth.json"); acl_sum=$(sha256sum < "$ETC/access-control.json")
run --force
check "B3 failing installer: updater exits 1 and logs the installer's status" $(ran && [ $RC -eq 1 ] && logged "exited with status 3"; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "B3 failing installer: config.yaml is back, byte for byte" $([ "$(sha256sum < "$ETC/config.yaml")" = "$cfg_sum" ]; echo $?) "now: $(cat "$ETC/config.yaml")"
check "B3 failing installer: config.yaml owner and mode are back (root:www-data 0664)" $([ "$(st "$ETC/config.yaml")" = "0:33:664" ]; echo $?) "now $(st "$ETC/config.yaml")"
check "B3 failing installer: auth.json the installer deleted is restored with its owner and mode (www-data 0640)" $([ "$(sha256sum < "$ETC/auth.json" 2>/dev/null)" = "$auth_sum" ] && [ "$(st "$ETC/auth.json")" = "33:33:640" ]; echo $?) "now $(st "$ETC/auth.json")"
check "B3 failing installer: access-control.json the installer chmod 000'ed is back (root:www-data 0660, same bytes)" $([ "$(st "$ETC/access-control.json")" = "0:33:660" ] && [ "$(sha256sum < "$ETC/access-control.json")" = "$acl_sum" ]; echo $?) "now $(st "$ETC/access-control.json")"
check "B3 failing installer: the directory itself is back to root:www-data 0775" $([ "$(st "$ETC")" = "0:33:775" ]; echo $?) "now $(st "$ETC")"
check "B3 failing installer: the restore is logged" $(logged "restored from the snapshot"; echo $?) "log: $(tail -3 "$T/update.log")"
check "B3 failing installer: installed_commit not advanced, snapshot removed after a good restore" $([ "$(installed)" = oldoldo ] && [ ! -e "$T/stage/conf-snapshot.tar" ]; echo $?) "installed=$(installed) stage=$(ls "$T/stage")"

reset oldoldo; cp "$T/fail-mutating.sh" "$T/served-installer"; goodpin "$FAILM_SHA"
IG_TAR_FAIL=extract run --force
check "B3 restore that fails: exit 1, the failure is logged and the snapshot is kept for the operator" $([ $RC -eq 1 ] && logged "restoring .* failed" && [ -s "$T/stage/conf-snapshot.tar" ]; echo $?) "rc=$RC stage=$(ls "$T/stage") log=$(tail -2 "$T/update.log")"

reset oldoldo; cp "$T/good.sh" "$T/served-installer"; goodpin "$GOOD_SHA"
IG_TAR_FAIL=create run --force
check "B3 snapshot that cannot be taken: the installer does not run, exit 1, logged" $(! ran && [ $RC -eq 1 ] && logged "cannot snapshot"; echo $?) "rc=$RC ran=$(ran && echo y) log=$(tail -2 "$T/update.log")"
check "B3 snapshot that cannot be taken: nothing left in the staging directory" $([ ! -e "$T/stage/conf-snapshot.tar" ]; echo $?) "stage: $(ls "$T/stage")"

reset oldoldo; cp "$T/good-mutating.sh" "$T/served-installer"; goodpin "$GOODM_SHA"; run --force
check "B3 successful installer: what it changed is kept (not rolled back)" $([ "$(cat "$ETC/config.yaml")" = "REWRITTEN BY INSTALLER" ] && [ -e "$ETC/created-by-installer" ] && [ $RC -eq 0 ]; echo $?) "rc=$RC config=$(cat "$ETC/config.yaml")"

# ============================ A11 ============================
reset oldoldo; cp "$T/good.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run --force
check "A11 the installer download has --max-time N" $(grep -Eq -- '--max-time [1-9][0-9]*( |$)' "$T/curl.args"; echo $?) "curl args: $(cat "$T/curl.args")"

rm -rf "$T"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
