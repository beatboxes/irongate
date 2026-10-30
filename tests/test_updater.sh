#!/bin/bash
# Irongate updater supply-chain tests (V4: pinned commit + installer sha256).
#
# Runs src/irongate-updater.sh (paths rewritten to a scratch dir, curl and sqlite3
# replaced by shims) and checks that it installs ONLY what the root-owned pin file
# names, and refuses everything else. Needs root (to create root/non-root owned pin
# files), so run it in a disposable container with no network:
#
#   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
#       python:3.12-slim bash tests/test_updater.sh src/irongate-updater.sh
#
# Exit status 0 = every case passed. Run it against the pre-fix updater to see it fail.

set -u
[ "${IRONGATE_TEST_SANDBOX:-}" = "1" ] || { echo "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 2; }
SRC=${1:?usage: test_updater.sh <irongate-updater.sh>}
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 2; }

T=$(mktemp -d /tmp/irongate-updater-test.XXXXXX)
mkdir -p "$T/bin" "$T/db" "$T/stage"
export T MARK="$T/installer-ran" UPDATER="$T/updater.sh"
PINNED_COMMIT=d5bd2189ac571a0b3964ec67167f73a75e76386e
MAINSHA=0123456789abcdef0123456789abcdef01234567

# --- updater under test: same code, scratch paths ------------------------------
sed -e "s#/etc/irongate/updater-pin.conf#$T/pin.conf#g" \
    -e "s#/opt/irongate/.update#$T/stage#g" \
    -e "s#/var/www/irongate/dhcp.db#$T/db/dhcp.db#g" \
    -e "s#/var/log/irongate-update.log#$T/update.log#g" "$SRC" > "$UPDATER"
if grep -q -e '/etc/irongate' -e '/var/www/irongate' -e '/var/log/irongate' "$UPDATER"; then
    echo "path rewrite incomplete" >&2; exit 2
fi

# --- shims -----------------------------------------------------------------------
cat > "$T/bin/sqlite3" <<'SH'
#!/bin/bash
# minimal settings-table emulation: SELECT value ... key='K' / INSERT OR REPLACE ... ('K', 'V' | datetime('now'))
# the SQL is the last argument (the updater runs `... -cmd ".timeout N" DB SQL` as www-data)
sql="${!#}"
if [[ "$sql" =~ SELECT\ value\ FROM\ settings\ WHERE\ key=\'([a-z_]+)\' ]]; then
    f="$T/db/${BASH_REMATCH[1]}"; [ -f "$f" ] && cat "$f"; exit 0
elif [[ "$sql" =~ VALUES\ \(\'([a-z_]+)\',\ \'([^\']*)\'\) ]]; then
    printf '%s\n' "${BASH_REMATCH[2]}" > "$T/db/${BASH_REMATCH[1]}"; exit 0
elif [[ "$sql" =~ VALUES\ \(\'([a-z_]+)\',\ datetime ]]; then
    echo now > "$T/db/${BASH_REMATCH[1]}"; exit 0
fi
exit 0
SH
# runuser: the updater writes the settings table as www-data (php-fpm owns the DB), so it goes through
# `runuser -u www-data -- sqlite3`. The shim drops that prefix and runs the command it was given, so the write
# under test is still the sqlite3 shim above.
cat > "$T/bin/runuser" <<'SH'
#!/bin/bash
echo "ARGS $*" >> "$T/runuser.args"
[ "${1:-}" = "-u" ] && shift 2
[ "${1:-}" = "--" ] && shift
exec "$@"
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
    https://api.github.com/*) printf '{\n  "sha": "%s",\n  "node_id": "x"\n}\n' "$MAINSHA_FOR_SHIM" ;;
    https://raw.githubusercontent.com/beatboxes/irongate/*/irongate-install.sh) cp "$T/served-installer" "$out" ;;
    *) exit 22 ;;
esac
SH
chmod +x "$T/bin/sqlite3" "$T/bin/runuser" "$T/bin/curl"
export MAINSHA_FOR_SHIM="$MAINSHA" PATH="$T/bin:$PATH"
# the updater's database writes run as www-data through runuser; point both at the shims
export IG_DB_RUNUSER="$T/bin/runuser" IG_DB_SQLITE3="$T/bin/sqlite3" IG_DB_BUSY_MS=5000

# --- fixture installers (>= 100000 bytes, valid bash) -----------------------------
make_installer() {   # $1=file $2=extra body
    {
        echo '#!/bin/bash'
        echo 'echo ran >> "$MARK"'
        echo 'echo mainhd0 > "$T/db/installed_commit"   # the real installer stamps main HEAD'
        printf '%s\n' "$2"
        yes '# padding to pass the updater size gate ------------------------------------' | head -n 1500
    } > "$1"
}
GOOD_BODY=''
# a real installer rewrites the updater in place (cat > file): simulate that, with
# trailing junk that would execute if the updater kept reading its own file
SELFWRITE_BODY='{ echo "#!/bin/bash"; echo "echo REWRITTEN >> \"$MARK.garbage\""; yes "echo GARBAGE >> \"$MARK.garbage\"" | head -n 400; } > "$UPDATER"'
make_installer "$T/good-installer.sh" "$GOOD_BODY"
make_installer "$T/evil-installer.sh" 'echo pwned >> "$MARK.evil"'
make_installer "$T/failing-installer.sh" 'exit 3'
make_installer "$T/selfwrite-installer.sh" "$SELFWRITE_BODY"
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
GOOD_SHA=$(sha_of "$T/good-installer.sh")
SELF_SHA=$(sha_of "$T/selfwrite-installer.sh")
FAIL_SHA=$(sha_of "$T/failing-installer.sh")

# --- helpers -----------------------------------------------------------------------
pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}
reset() {   # $1=auto_update_enabled $2=installed_commit
    rm -rf "$T/stage" "$T/curl.log" "$T/update.log" "$T/pin.conf" "$T/db"/* "$MARK" "$MARK.evil" "$MARK.garbage"
    mkdir -p "$T/stage"; : > "$T/curl.log"; : > "$T/update.log"
    echo "$1" > "$T/db/auto_update_enabled"; echo "$2" > "$T/db/installed_commit"
}
mkpin() {   # $1=file content (printf format)  $2=owner  $3=mode
    printf "$1" > "$T/pin.conf"; chown "${2:-0:0}" "$T/pin.conf"; chmod "${3:-644}" "$T/pin.conf"
}
goodpin() { mkpin "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=${1:-$GOOD_SHA}\n" "${2:-0:0}" "${3:-644}"; }
run() { ( cd "$T" && bash "$UPDATER" "$@" ) > "$T/stdout" 2>&1; RC=$?; }
ran()   { [ -f "$MARK" ]; }
logged() { grep -q -- "$1" "$T/update.log"; }
curled() { grep -q -- "$1" "$T/curl.log"; }
installed() { cat "$T/db/installed_commit" 2>/dev/null; }

# ---- refusals: pin file problems ---------------------------------------------------
reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"
run --force
check "no pin file: refuse, exit 1, nothing downloaded or run" $(! ran && [ $RC -eq 1 ] && ! curled raw.githubusercontent && ! curled api.github.com; echo $?) "rc=$RC ran=$(ran && echo y) curl=$(cat "$T/curl.log")"
check "no pin file: reason logged" $(logged "pin file .* missing"; echo $?) "$(cat "$T/update.log")"

reset true oldoldo; goodpin "$GOOD_SHA" 1000:1000 644; run --force
check "pin owned by non-root: refuse" $(! ran && [ $RC -eq 1 ] && logged "must be root:root"; echo $?) "rc=$RC log=$(tail -2 "$T/update.log")"

reset true oldoldo; goodpin "$GOOD_SHA" 0:1000 644; run --force
check "pin with non-root group: refuse" $(! ran && [ $RC -eq 1 ] && logged "must be root:root"; echo $?) "rc=$RC"

for mode in 666 664 660 640 755 444; do
    reset true oldoldo; goodpin "$GOOD_SHA" 0:0 $mode; run --force
    check "pin mode $mode: refuse" $(! ran && [ $RC -eq 1 ] && logged "mode 0644 or 0600"; echo $?) "rc=$RC"
done

reset true oldoldo; goodpin "$GOOD_SHA" 0:0 644; mv "$T/pin.conf" "$T/real-pin.conf"; ln -s "$T/real-pin.conf" "$T/pin.conf"; run --force
check "pin is a symlink: refuse" $(! ran && [ $RC -eq 1 ] && logged "missing or not a regular file"; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=${PINNED_COMMIT:0:7}\nPINNED_INSTALLER_SHA256=$GOOD_SHA\n"; run --force
check "pin with 7-char commit: refuse" $(! ran && [ $RC -eq 1 ] && logged "not valid"; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=${PINNED_COMMIT^^}\nPINNED_INSTALLER_SHA256=$GOOD_SHA\n"; run --force
check "pin with uppercase hex: refuse" $(! ran && [ $RC -eq 1 ]; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=$PINNED_COMMIT\n"; run --force
check "pin without sha256: refuse" $(! ran && [ $RC -eq 1 ] && logged "must define"; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_INSTALLER_SHA256=$GOOD_SHA\n"; run --force
check "pin without commit: refuse" $(! ran && [ $RC -eq 1 ] && logged "must define"; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$GOOD_SHA\n"; run --force
check "pin with duplicate key: refuse" $(! ran && [ $RC -eq 1 ]; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$GOOD_SHA\nEXTRA=\$(touch $T/injected)\n"; run --force
check "pin with extra/injected line: refuse, never evaluated" $(! ran && [ $RC -eq 1 ] && [ ! -e "$T/injected" ]; echo $?) "rc=$RC"

reset true oldoldo; mkpin "PINNED_COMMIT=$PINNED_COMMIT\r\nPINNED_INSTALLER_SHA256=$GOOD_SHA\r\n"; run --force
check "pin with CRLF line endings: refuse" $(! ran && [ $RC -eq 1 ]; echo $?) "rc=$RC"

# ---- refusals: installer does not match the pin ------------------------------------
reset true oldoldo; cp "$T/evil-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run --force
check "installer sha256 differs from pin: refuse, exit 1, not executed" $(! ran && [ ! -e "$MARK.evil" ] && [ $RC -eq 1 ] && logged "does not match pin"; echo $?) "rc=$RC log=$(tail -2 "$T/update.log")"
check "installer sha256 mismatch: staged file removed" $([ ! -e "$T/stage/irongate-install.sh" ]; echo $?) "$(ls "$T/stage")"
check "installer sha256 mismatch: installed_commit not advanced" $([ "$(installed)" = oldoldo ]; echo $?) "installed_commit=$(installed)"

# The pinned hash must be compared in full: a hash that agrees with the installer's on a prefix
# (or on everything but one hex digit) is a different file and must be refused.
flip() {   # $1=hex string $2=0-based index -> the same string with that one hex digit changed
    local c=${1:$2:1} n; [ "$c" = "0" ] && n=1 || n=0
    printf '%s%s%s' "${1:0:$2}" "$n" "${1:$(($2 + 1))}"
}
for idx in 63 40 8 0; do
    reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$(flip "$GOOD_SHA" $idx)"; run --force
    check "pinned sha256 differs from the installer's in hex digit #$idx only: refuse, not executed" $(! ran && [ $RC -eq 1 ] && logged "does not match pin" && [ "$(installed)" = oldoldo ]; echo $?) "rc=$RC ran=$(ran && echo y) installed=$(installed)"
done

reset true oldoldo; : > "$T/served-installer"; goodpin "$GOOD_SHA"; run --force
check "empty download: refuse" $(! ran && [ $RC -eq 1 ]; echo $?) "rc=$RC"

# ---- success path --------------------------------------------------------------------
reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run --force
check "valid pin + matching installer (--force): installer runs, exit 0" $(ran && [ $RC -eq 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"
check "download URL is the pinned commit, not main" $(curled "irongate/$PINNED_COMMIT/irongate-install.sh" && ! curled "/main/" && ! curled "$MAINSHA"; echo $?) "$(cat "$T/curl.log")"
check "GitHub API / moving HEAD is not consulted" $(! curled api.github.com; echo $?) "$(cat "$T/curl.log")"
check "installed_commit is the pinned short sha after install" $([ "$(installed)" = "${PINNED_COMMIT:0:7}" ]; echo $?) "installed_commit=$(installed)"

reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; mkpin "# reviewed 2026-10-27\n\nPINNED_COMMIT=$PINNED_COMMIT\nPINNED_INSTALLER_SHA256=$GOOD_SHA" 0:0 600; run --force
check "comments, blank lines, no trailing newline, mode 0600: accepted" $(ran && [ $RC -eq 0 ]; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"

# ---- auto_update_enabled semantics unchanged -------------------------------------------
reset false oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; run
check "auto_update_enabled=false, no --force, no pin: skip quietly, exit 0" $(! ran && [ $RC -eq 0 ] && logged "disabled" && ! curled http; echo $?) "rc=$RC"

reset false oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run
check "auto_update_enabled=false, no --force, valid pin: still skipped" $(! ran && [ $RC -eq 0 ]; echo $?) "rc=$RC"

reset true "${PINNED_COMMIT:0:7}"; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run
check "enabled, already at pinned commit, no --force: nothing to do" $(! ran && [ $RC -eq 0 ] && logged "Already up to date" && ! curled raw.githubusercontent; echo $?) "rc=$RC"

reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run
check "enabled, installed differs from pin, no --force: installs pinned" $(ran && [ $RC -eq 0 ] && [ "$(installed)" = "${PINNED_COMMIT:0:7}" ]; echo $?) "rc=$RC installed=$(installed)"

reset true unknown; cp "$T/good-installer.sh" "$T/served-installer"; goodpin "$GOOD_SHA"; run
check "installed_commit=unknown, no --force: not installed (unchanged semantics)" $(! ran && [ $RC -eq 0 ]; echo $?) "rc=$RC"

reset true oldoldo; cp "$T/good-installer.sh" "$T/served-installer"; run
check "enabled, scheduled run (no --force), no pin: refuse, exit 1" $(! ran && [ $RC -eq 1 ]; echo $?) "rc=$RC"

# ---- installer behaviour ------------------------------------------------------------------
reset true oldoldo; cp "$T/failing-installer.sh" "$T/served-installer"; goodpin "$FAIL_SHA"; run --force
check "installer exits non-zero: updater reports failure (exit 1)" $(ran && [ $RC -eq 1 ] && logged "exited with status 3" && ! logged "Update complete"; echo $?) "rc=$RC log=$(tail -3 "$T/update.log")"

reset true oldoldo; cp "$T/selfwrite-installer.sh" "$T/served-installer"; goodpin "$SELF_SHA"; run --force
check "installer rewrites the updater in place: no stray code executed afterwards" $(ran && [ $RC -eq 0 ] && [ ! -e "$MARK.garbage" ] && logged "Update complete"; echo $?) "rc=$RC garbage=$(cat "$MARK.garbage" 2>/dev/null | wc -l) log=$(tail -3 "$T/update.log")"

# ---- O6: installed_commit is stamped only after the installer has exited 0 ------------------------------------------
# A failed installer must not leave the pinned commit recorded as installed: the next scheduled run would answer
# "Already up to date" and never retry. These fixtures do NOT stamp installed_commit themselves (the real installer
# stamps main HEAD part-way through), so whatever the updater leaves behind is the updater's own doing, and each one
# records what installed_commit held at the moment the installer started.
make_plain_installer() {   # $1=file $2=extra body
    {
        echo '#!/bin/bash'
        echo 'echo ran >> "$MARK"'
        echo 'cat "$T/db/installed_commit" > "$MARK.seen"'
        printf '%s\n' "$2"
        yes '# padding to pass the updater size gate ------------------------------------' | head -n 1500
    } > "$1"
}
# The case just above let a fixture installer overwrite $UPDATER (it simulates the real installer rewriting the
# updater in place), so build the copy under test again from the same source with the same path rewrites.
sed -e "s#/etc/irongate/updater-pin.conf#$T/pin.conf#g" \
    -e "s#/opt/irongate/.update#$T/stage#g" \
    -e "s#/var/www/irongate/dhcp.db#$T/db/dhcp.db#g" \
    -e "s#/var/log/irongate-update.log#$T/update.log#g" "$SRC" > "$UPDATER"
make_plain_installer "$T/plain-good.sh" ''
make_plain_installer "$T/plain-fail.sh" 'exit 3'
PGOOD_SHA=$(sha_of "$T/plain-good.sh"); PFAIL_SHA=$(sha_of "$T/plain-fail.sh")

reset true oldoldo; rm -f "$MARK.seen"; cp "$T/plain-fail.sh" "$T/served-installer"; goodpin "$PFAIL_SHA"; run --force
check "O6 failed installer (--force): updater exits 1 and installed_commit is NOT advanced to the pinned commit" $(ran && [ $RC -eq 1 ] && [ "$(installed)" = oldoldo ]; echo $?) "rc=$RC installed_commit=$(installed)"
check "O6 failed installer: the installer itself saw the OLD installed_commit while it ran (nothing stamped in advance)" $([ "$(cat "$MARK.seen" 2>/dev/null)" = oldoldo ]; echo $?) "installer saw: $(cat "$MARK.seen" 2>/dev/null)"
rm -f "$MARK"; run
check "O6 after a failed run the next scheduled run (no --force) tries again instead of 'Already up to date'" $(ran && ! logged "Already up to date"; echo $?) "rc=$RC ran=$(ran && echo y) log=$(tail -3 "$T/update.log")"

reset true oldoldo; rm -f "$MARK.seen"; cp "$T/plain-good.sh" "$T/served-installer"; goodpin "$PGOOD_SHA"; run --force
check "O6 successful installer: installed_commit is the pinned short sha afterwards" $(ran && [ $RC -eq 0 ] && [ "$(installed)" = "${PINNED_COMMIT:0:7}" ]; echo $?) "rc=$RC installed_commit=$(installed)"
check "O6 successful installer: it also saw the OLD installed_commit while it ran" $([ "$(cat "$MARK.seen" 2>/dev/null)" = oldoldo ]; echo $?) "installer saw: $(cat "$MARK.seen" 2>/dev/null)"
rm -f "$MARK"; run
check "O6 after a successful run the next scheduled run has nothing to do" $(! ran && [ $RC -eq 0 ] && logged "Already up to date"; echo $?) "rc=$RC ran=$(ran && echo y)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
