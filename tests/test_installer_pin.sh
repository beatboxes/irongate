#!/bin/bash
# Irongate installer: the updater's pin file must never be "laundered" into a trusted file (V4 follow-up).
#
# The installer runs `chown -R root:www-data /etc/irongate` (the web tier must write config.yaml) and must
# keep /etc/irongate/updater-pin.conf, the updater's trust root, out of that. www-data can create, replace
# and symlink files in /etc/irongate (the directory is 0775 root:www-data), so the installer must never
# hand root:root ownership to a file the web tier could have planted, and never chown/chmod through a
# symlink the web tier could have placed there.
#
# The test cuts the real "permissions" block out of the installer (from the "IMPORTANT: www-data needs to write
# to config.yaml" comment to the line before "# Create Python virtual environment") and runs it as root on scratch /etc/irongate trees.
# It overwrites /etc/irongate, so it refuses to run outside a throw-away container:
#
#   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
#       python:3.12-slim bash tests/test_installer_pin.sh irongate-install.sh
#
# Exit status 0 = every case passed. Run it against an installer from before the fix to see it fail.

set -u
[ "${IRONGATE_TEST_SANDBOX:-}" = "1" ] || { echo "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 2; }
INSTALLER=${1:?usage: test_installer_pin.sh <irongate-install.sh>}
[ -f "$INSTALLER" ] || { echo "no such file: $INSTALLER" >&2; exit 2; }
getent passwd www-data >/dev/null || { echo "needs a www-data user" >&2; exit 2; }
for d in /etc/irongate /opt/irongate /var/log/irongate; do
    [ -e "$d" ] && { echo "refusing to run: $d already exists" >&2; exit 2; }
done

T=$(mktemp -d /tmp/irongate-installer-test.XXXXXX)
SEG="$T/segment.sh"
PIN=/etc/irongate/updater-pin.conf
TGT=/var/tmp/irongate-pin-target

START_RE='^# IMPORTANT: www-data needs to write to config.yaml from the web UI$'
n_start=$(grep -c "$START_RE" "$INSTALLER"); n_end=$(grep -c '^# Create Python virtual environment$' "$INSTALLER")
[ "$n_start" = 1 ] && [ "$n_end" = 1 ] || { echo "cannot locate the permissions block in $INSTALLER (start=$n_start end=$n_end)" >&2; exit 2; }
start=$(grep -n "$START_RE" "$INSTALLER" | cut -d: -f1)
end=$(grep -n '^# Create Python virtual environment$' "$INSTALLER" | cut -d: -f1)
sed -n "${start},$((end - 1))p" "$INSTALLER" > "$SEG"
bash -n "$SEG" || { echo "extracted block does not parse" >&2; exit 2; }
grep -q 'chown -R\|chown' "$SEG" || { echo "extracted block has no chown: wrong block?" >&2; exit 2; }

pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}
fresh() { rm -rf /etc/irongate /opt/irongate /var/log/irongate "$TGT"; mkdir -p /etc/irongate; }
st() { stat -c '%u:%g:%a:%F' "$1" 2>/dev/null | sed 's/regular empty file/regular file/' | grep . || echo missing; }
lst() { find /etc/irongate "$TGT" -printf '%p %u:%g %m %y %l\n' 2>/dev/null | sort; }
run_block() { bash "$SEG" > "$T/block.out" 2>&1; }
# what irongate-updater.sh's load_pin() demands of the pin file
updater_accepts() {
    [ -f "$PIN" ] && [ ! -L "$PIN" ] || return 1
    local s; s=$(stat -L -c '%u:%g:%a' "$PIN")
    [ "$s" = "0:0:644" ] || [ "$s" = "0:0:600" ]
}
plant() {   # $1=owner $2=mode : a pin file the web tier could have created (content is irrelevant here)
    printf 'PINNED_COMMIT=%s\nPINNED_INSTALLER_SHA256=%s\n' "$(printf '%040d' 1)" "$(printf '%064d' 2)" > "$PIN"
    chown "$1" "$PIN"; chmod "$2" "$PIN"
}

# 1. a genuine pin (regular file, root:root) survives the installer unchanged
fresh; plant 0:0 644; run_block
check "root:root 0644 pin stays root:root 0644 and is still accepted by the updater" $([ "$(st $PIN)" = "0:0:644:regular file" ] && updater_accepts; echo $?) "now $(st $PIN)"
fresh; plant 0:0 600; run_block
check "root:root 0600 pin keeps its 0600 (no widening)" $([ "$(st $PIN)" = "0:0:600:regular file" ]; echo $?) "now $(st $PIN)"

# 2. a pin the web tier planted is NOT promoted to root:root
fresh; plant 33:33 644; run_block
check "pin created by www-data is not laundered into root:root" $(! updater_accepts; echo $?) "now $(st $PIN)"
fresh; plant 33:33 666; run_block
check "world-writable pin created by www-data is not laundered" $(! updater_accepts; echo $?) "now $(st $PIN)"
fresh; plant 0:33 664; run_block
check "pin that is root:www-data (group-writable) is not laundered into root:root" $(! updater_accepts; echo $?) "now $(st $PIN)"

# 3. a symlink in the pin's place is never followed by chown/chmod
fresh; echo secret > "$TGT"; chown 33:33 "$TGT"; chmod 640 "$TGT"; ln -s "$TGT" "$PIN"; run_block
check "symlink pin -> www-data file: target ownership and mode untouched" $([ "$(st $TGT)" = "33:33:640:regular file" ]; echo $?) "target now $(st $TGT)"
check "symlink pin stays a symlink and is not accepted by the updater" $([ -L "$PIN" ] && ! updater_accepts; echo $?) "pin now $(st $PIN)"
fresh; echo secret > "$TGT"; chown 0:0 "$TGT"; chmod 600 "$TGT"; ln -s "$TGT" "$PIN"; run_block
check "symlink pin -> root-owned 0600 file: target not chmod'ed/chown'ed" $([ "$(st $TGT)" = "0:0:600:regular file" ]; echo $?) "target now $(st $TGT)"

# 4. no pin: none is created
fresh; run_block
check "no pin file before: none is created" $([ ! -e "$PIN" ] && [ ! -L "$PIN" ]; echo $?) "now $(st $PIN)"

# 5. nothing else changes: same result as the plain recursive chown for every other path
mktree() {
    fresh
    mkdir -p /etc/irongate/sub/deep
    echo a > /etc/irongate/auth.json; chown 33:33 /etc/irongate/auth.json; chmod 600 /etc/irongate/auth.json
    echo b > /etc/irongate/sub/deep/x; chown 1000:1000 /etc/irongate/sub/deep/x; chmod 640 /etc/irongate/sub/deep/x
    echo t > "$TGT"; chown 33:33 "$TGT"; chmod 640 "$TGT"; ln -s "$TGT" /etc/irongate/sub/link
    plant 0:0 644
}
mktree
chown -R root:www-data /etc/irongate; chmod 775 /etc/irongate
touch /etc/irongate/config.yaml; chown root:www-data /etc/irongate/config.yaml; chmod 664 /etc/irongate/config.yaml
lst | grep -v '^/etc/irongate/updater-pin.conf ' > "$T/reference.lst"
mktree; run_block
lst | grep -v '^/etc/irongate/updater-pin.conf ' > "$T/actual.lst"
check "every path other than the pin gets exactly the ownership/mode of the plain recursive chown" $(diff -q "$T/reference.lst" "$T/actual.lst" >/dev/null; echo $?) "$(diff "$T/reference.lst" "$T/actual.lst" | head -6)"
check "config.yaml is root:www-data 0664 and /etc/irongate is root:www-data 0775 (web UI can still save config)" $([ "$(st /etc/irongate/config.yaml)" = "0:33:664:regular file" ] && [ "$(st /etc/irongate)" = "0:33:775:directory" ]; echo $?) "$(st /etc/irongate/config.yaml) $(st /etc/irongate)"
check "linked file outside /etc/irongate keeps its ownership (chown does not follow symlinks)" $([ "$(st $TGT)" = "33:33:640:regular file" ]; echo $?) "$(st $TGT)"

rm -rf /etc/irongate /opt/irongate /var/log/irongate "$TGT"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
