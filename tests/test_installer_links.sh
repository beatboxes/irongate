#!/bin/bash
# Irongate installer: root must never follow a link (or race a rename) in /etc/irongate.
#
# /etc/irongate is root:www-data 0775 on purpose (the web UI rewrites config.yaml), so a compromised web tier
# can create, rename and symlink entries there at any moment, also WHILE the installer runs as root. This test
# cuts the real pieces of the installer that touch /etc/irongate out of irongate-install.sh and runs them as root
# on scratch trees:
#   B  the permissions block (recursive chown, config.yaml ownership)
#   C  the config.yaml generation
#   D  the access-control.json / auth.json creation ("preserved across re-runs")
# plus, when the installer has them, the fixed-file helpers that B, C and D call.
#
#   F-A    `find ... -exec chown` resolves each path again at chown time; a subdirectory swapped for a symlink in
#          between sends root's chown outside /etc/irongate. -execdir chown -h works relative to the directory fd.
#   OOS-1  chown/chmod/touch/`cat >` on the fixed files must not follow a planted symlink, must not hang on a
#          FIFO and must not create the target of a dangling link; a swap between check and use must not matter.
#
# It overwrites /etc/irongate, so it refuses to run outside a throw-away container:
#
#   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
#       python:3.12-slim bash tests/test_installer_links.sh irongate-install.sh
#
# Exit status 0 = every case passed. Run it against an installer from before the fix to see it fail.

set -u
[ "${IRONGATE_TEST_SANDBOX:-}" = "1" ] || { echo "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "must run as root" >&2; exit 2; }
INSTALLER=${1:?usage: test_installer_links.sh <irongate-install.sh>}
[ -f "$INSTALLER" ] || { echo "no such file: $INSTALLER" >&2; exit 2; }
getent passwd www-data >/dev/null || { echo "needs a www-data user" >&2; exit 2; }
for d in /etc/irongate /etc/.irongate-stage /opt/irongate /var/log/irongate /var/tmp/ig-victim; do
    [ -e "$d" ] || [ -L "$d" ] && { echo "refusing to run: $d already exists" >&2; exit 2; }
done

T=$(mktemp -d /tmp/irongate-links-test.XXXXXX)
V=/var/tmp/ig-victim            # everything the attacker points at lives here (outside /etc/irongate)
SHIM=$T/shim; PHPSHIM=$T/phpshim; mkdir -p "$SHIM" "$PHPSHIM"
REAL_CHOWN=$(command -v chown); REAL_CHMOD=$(command -v chmod)

# ---- cut the pieces out of the installer ---------------------------------------------------------------
segment() {   # name start-regex end-regex(exclusive) -> $T/<name>.sh ; both patterns must match exactly once
    local n_s n_e s e
    n_s=$(grep -c -- "$2" "$INSTALLER"); n_e=$(grep -c -- "$3" "$INSTALLER")
    [ "$n_s" = 1 ] && [ "$n_e" = 1 ] || { echo "cannot locate segment $1 in $INSTALLER (start=$n_s end=$n_e)" >&2; exit 2; }
    s=$(grep -n -- "$2" "$INSTALLER" | cut -d: -f1); e=$(grep -n -- "$3" "$INSTALLER" | cut -d: -f1)
    [ "$s" -lt "$e" ] || { echo "segment $1 markers are out of order" >&2; exit 2; }
    sed -n "${s},$((e - 1))p" "$INSTALLER" > "$T/$1.sh"
    bash -n "$T/$1.sh" || { echo "segment $1 does not parse" >&2; exit 2; }
}
segment B '^# IMPORTANT: www-data needs to write to config.yaml from the web UI$' '^# Create Python virtual environment$'
segment C '^# Create config from database (includes any existing devices)$' '^chown -R root:root /opt/irongate$'
segment D '^# access-control.json — preserved across re-runs$' '^# Generate the nginx allow-list snippet now'
if grep -q '^# ---- /etc/irongate fixed-file helpers: begin ----$' "$INSTALLER" && grep -q '^# ---- /etc/irongate fixed-file helpers: end ----$' "$INSTALLER"; then
    segment H '^# ---- /etc/irongate fixed-file helpers: begin ----$' '^# ---- /etc/irongate fixed-file helpers: end ----$'
    HAVE_HELPERS=1
else
    : > "$T/H.sh"; HAVE_HELPERS=0
fi
echo "segments: B=$(wc -l < "$T/B.sh") C=$(wc -l < "$T/C.sh") D=$(wc -l < "$T/D.sh") helpers=$(wc -l < "$T/H.sh") lines (fixed-file helpers in installer: $HAVE_HELPERS)"

# ---- shims ------------------------------------------------------------------------------------------
# php: the real one is not in the test image; D only needs a random password and a bcrypt-looking hash.
cat > "$PHPSHIM/php" <<'EOF'
#!/bin/bash
case "$*" in *password_hash*) printf '%s' '$2y$10$ShimHashShimHashShimHashShimHashShimHashShimHashSh' ;; *) printf '%s' '0123456789abcdef0123' ;; esac
EOF
# chown/chmod: swap an entry of /etc/irongate for a symlink to $V/target right before the real command runs -
# exactly the window between "the installer looked" and "chown/chmod resolves the path" (once per run).
#   IG_SWAP_DIR=sub   : mode dir  - swap the subdirectory sub (fires on the first chown), as for `find -exec`
#   IG_SWAP_FILE=NAME : mode file - swap NAME when chown/chmod is asked to act on an ABSOLUTE path whose basename
#                       starts with NAME (the installer's own fix-up, not find's relative ./NAME arguments)
for tool in chown chmod; do
    real=$REAL_CHOWN; [ $tool = chmod ] && real=$REAL_CHMOD
    cat > "$SHIM/$tool" <<EOF
#!/bin/bash
flag=/tmp/ig-swapped
if [ ! -e \$flag ]; then
  if [ -n "\${IG_SWAP_DIR:-}" ] && [ "$tool" = chown ]; then
    : > \$flag
    mv /etc/irongate/\$IG_SWAP_DIR /etc/irongate/\$IG_SWAP_DIR.orig && ln -s $V/targetdir /etc/irongate/\$IG_SWAP_DIR
  elif [ -n "\${IG_SWAP_FILE:-}" ]; then
    last=\${@: -1}
    case "\$last" in /*) b=\$(basename -- "\$last")
      case "\$b" in "\$IG_SWAP_FILE"*)
        : > \$flag
        mv /etc/irongate/\$IG_SWAP_FILE /etc/irongate/\$IG_SWAP_FILE.orig 2>/dev/null && ln -s $V/target /etc/irongate/\$IG_SWAP_FILE ;;
      esac ;;
    esac
  fi
fi
exec $real "\$@"
EOF
done
# install: swap NAME on the IG_SWAP_NTH-th `install -m ... /etc/.irongate-stage` call (the installer's ig_stage, which
# runs in the window between its "is NAME a regular file" check and the link(2) pin of NAME).
cat > "$SHIM/install" <<EOF
#!/bin/bash
if [ -n "\${IG_SWAP_NTH:-}" ] && [ "\${*: -1}" = /etc/.irongate-stage ] && [ ! -e /tmp/ig-swapped ]; then
  n=\$(( \$(cat /tmp/ig-install-count 2>/dev/null || echo 0) + 1 )); echo \$n > /tmp/ig-install-count
  if [ \$n -eq \$IG_SWAP_NTH ]; then
    : > /tmp/ig-swapped
    mv /etc/irongate/\$IG_SWAP_FILE /etc/irongate/\$IG_SWAP_FILE.orig && ln -s $V/target /etc/irongate/\$IG_SWAP_FILE
  fi
fi
exec $(command -v install) "\$@"
EOF
chmod +x "$PHPSHIM/php" "$SHIM/chown" "$SHIM/chmod" "$SHIM/install"

pass=0; fail=0
check() {   # name, condition-exit-status, detail
    if [ "$2" -eq 0 ]; then pass=$((pass + 1)); echo "PASS  $1"; else fail=$((fail + 1)); echo "FAIL  $1  -- $3"; fi
}
st() { stat -c '%u:%g:%a:%F' "$1" 2>/dev/null | sed 's/regular empty file/regular file/' | grep . || echo missing; }
fresh() { rm -rf /etc/irongate /etc/.irongate-stage "$V" /tmp/ig-swapped /tmp/ig-install-count; mkdir -p /etc/irongate "$V"; chown 0:33 /etc/irongate; chmod 775 /etc/irongate; }
victim() {   # a root-only secret outside /etc/irongate that must never be touched; $V/target
    echo "root secret" > "$V/target"; chown 0:0 "$V/target"; chmod 0600 "$V/target"
}
vstate() { echo "$(st "$V/target") sha=$(sha256sum < "$V/target" 2>/dev/null | cut -c1-12)"; }
VICTIM_OK="0:0:600:regular file sha=$(printf 'root secret\n' | sha256sum | cut -c1-12)"

# run one segment the way the installer does: sourced into a `set -e` shell, helpers loaded first
run() {   # segment ; SWAP=1 puts the chown/chmod swap shims first on PATH, IG_SWAP_DIR / IG_SWAP_FILE configure them
    timeout 60 env PATH="${SWAP:+$SHIM:}$PHPSHIM:$PATH" bash -c "
        set -e
        RED=; GREEN=; YELLOW=; CYAN=; NC=
        INTERFACE=eth0; CURRENT_IP=192.168.1.2; CURRENT_GATEWAY=192.168.1.1; ADMIN_LAN_IP=\${ADMIN_LAN_IP:-}
        . $T/H.sh
        . $T/$1.sh" > "$T/run.out" 2>&1
    RC=$?
}

if [ "$HAVE_HELPERS" = 1 ]; then
    fresh; bash -c ". $T/H.sh; RED=; NC=; ig_stage"
    check "staging directory is root:root 0700 (the web tier cannot enter it)" $([ "$(st /etc/.irongate-stage)" = "0:0:700:directory" ]; echo $?) "now $(st /etc/.irongate-stage)"
fi

# ======================= F-A: find -exec vs -execdir (swap of a subdirectory) =======================
fresh; victim; mkdir -p /etc/irongate/sub "$V/targetdir"; echo x > /etc/irongate/sub/victim
echo "dir secret" > "$V/targetdir/victim"; chown 0:0 "$V/targetdir/victim"; chmod 0600 "$V/targetdir/victim"
export IG_SWAP_DIR=sub; SWAP=1 run B; unset IG_SWAP_DIR
check "F-A shim fired (control: the swap really happened between find and chown)" $([ -e /tmp/ig-swapped ] && [ -L /etc/irongate/sub ]; echo $?) "no swap: sub=$(st /etc/irongate/sub)"
check "F-A swapped subdirectory: root does not chown a file outside /etc/irongate" $([ "$(st $V/targetdir/victim)" = "0:0:600:regular file" ]; echo $?) "outside file now $(st $V/targetdir/victim)"
check "F-A the swap is not silently ignored: the real directory was chowned, or the block stopped with an error" $([ "$(st /etc/irongate/sub.orig/victim)" = "0:33:644:regular file" ] || [ $RC -ne 0 ]; echo $?) "rc=$RC sub.orig/victim $(st /etc/irongate/sub.orig/victim)"

# ======================= OOS-1, block B: config.yaml early site =======================
CFG=/etc/irongate/config.yaml
fresh; victim; ln -s "$V/target" $CFG; run B
check "B symlink config.yaml -> root file: target untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
check "B symlink config.yaml: replaced by a regular root:www-data 0664 file" $([ "$(st $CFG)" = "0:33:664:regular file" ]; echo $?) "config.yaml now $(st $CFG)"
check "B symlink config.yaml: the planted link is kept aside, still pointing at the target (evidence)" $([ "$(ls /etc/irongate | grep -c '^config.yaml.refused\.')" = 1 ] && [ "$(readlink /etc/irongate/config.yaml.refused.* 2>/dev/null)" = "$V/target" ]; echo $?) "ls: $(ls /etc/irongate | tr '\n' ' ')"
check "B symlink config.yaml: installer block still exits 0" $([ $RC -eq 0 ]; echo $?) "rc=$RC $(tail -3 $T/run.out)"

fresh; ln -s "$V/created-by-touch" $CFG; run B
check "B dangling symlink config.yaml: the target is not created" $([ ! -e "$V/created-by-touch" ] && [ ! -L "$V/created-by-touch" ]; echo $?) "target now $(st $V/created-by-touch)"
check "B dangling symlink config.yaml: a regular file takes its place" $([ "$(st $CFG)" = "0:33:664:regular file" ]; echo $?) "config.yaml now $(st $CFG)"

fresh; mkdir "$V/dir"; echo keep > "$V/dir/f"; chown 77:77 "$V/dir" "$V/dir/f"; ln -s "$V/dir" $CFG; run B
check "B symlink config.yaml -> directory: directory and its content untouched" $([ "$(st $V/dir)" = "77:77:755:directory" ] && [ "$(st $V/dir/f)" = "77:77:644:regular file" ]; echo $?) "dir $(st $V/dir) f $(st $V/dir/f)"

fresh; mkdir $CFG; echo x > $CFG/inner; run B
check "B directory at config.yaml: moved aside, regular file in its place" $([ "$(st $CFG)" = "0:33:664:regular file" ] && [ "$(ls /etc/irongate | grep -c '^config.yaml.refused\.')" = 1 ]; echo $?) "config.yaml $(st $CFG) ls: $(ls /etc/irongate | tr '\n' ' ')"

fresh; victim; echo "genuine config" > $CFG; chown 33:33 $CFG; chmod 666 $CFG
export IG_SWAP_FILE=config.yaml; SWAP=1 run B; unset IG_SWAP_FILE
check "B race: config.yaml swapped for a symlink right before the fix-up chmod/chown (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "shim did not fire"
check "B race: target of the swapped-in symlink untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"

if [ "$HAVE_HELPERS" = 1 ]; then
    fresh; victim; echo "genuine config" > $CFG; chown 33:33 $CFG; chmod 666 $CFG
    export IG_SWAP_FILE=config.yaml IG_SWAP_NTH=1; SWAP=1 run B; unset IG_SWAP_FILE IG_SWAP_NTH
    check "B race: config.yaml swapped for a symlink between the regular-file check and the pin (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "shim did not fire (rc=$RC)"
    check "B race: ... the pin links the symlink itself, so the target is untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
fi

# genuine file: unchanged content, root:www-data 0664
fresh; echo "genuine config" > $CFG; chown 33:33 $CFG; chmod 666 $CFG; ino=$(stat -c %i $CFG); run B
check "B genuine config.yaml: content kept, becomes root:www-data 0664, no staging directory left" $([ "$(st $CFG)" = "0:33:664:regular file" ] && [ "$(cat $CFG)" = "genuine config" ] && [ ! -e /etc/.irongate-stage ]; echo $?) "now $(st $CFG) $(cat $CFG) stage=$(ls -d /etc/.irongate-stage 2>&1)"
fresh; run B
check "B no config.yaml: an empty root:www-data 0664 file is created, no staging directory left" $([ "$(st $CFG)" = "0:33:664:regular file" ] && [ ! -s $CFG ] && [ ! -e /etc/.irongate-stage ]; echo $?) "now $(st $CFG) stage=$(ls -d /etc/.irongate-stage 2>&1)"

# ======================= OOS-1, block C: config.yaml generation =======================
fresh; victim; ln -s "$V/target" $CFG; run C
check "C symlink config.yaml -> root file: target not overwritten, not chowned/chmodded" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
check "C symlink config.yaml: a regular file with the generated config is written instead" $([ "$(st $CFG)" = "0:33:664:regular file" ] && grep -q '^# Irongate Configuration$' $CFG && grep -q '^devices: \[\]$' $CFG; echo $?) "config.yaml $(st $CFG) rc=$RC"
fresh; ln -s "$V/created-by-cat" $CFG; run C
check "C dangling symlink config.yaml: the target is not created" $([ ! -e "$V/created-by-cat" ] && [ ! -L "$V/created-by-cat" ]; echo $?) "target now $(st $V/created-by-cat)"
fresh; mkfifo $CFG; run C
check "C FIFO at config.yaml: no hang (60 s timeout = hang), replaced by a regular file" $([ $RC -ne 124 ] && [ "$(st $CFG)" = "0:33:664:regular file" ]; echo $?) "rc=$RC config.yaml $(st $CFG)"
fresh; victim; echo "old config" > $CFG; chown 33:33 $CFG; chmod 600 $CFG
export IG_SWAP_FILE=config.yaml; SWAP=1 run C; unset IG_SWAP_FILE
check "C race: config.yaml swapped for a symlink during the installer's own chown/chmod (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "shim did not fire (rc=$RC)"
check "C race: target of the swapped-in symlink untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
fresh; echo "old config" > $CFG; chown 33:33 $CFG; chmod 600 $CFG; run C
check "C genuine config.yaml: regenerated, root:www-data 0664, nothing stray left in /etc/irongate or /etc" $([ "$(st $CFG)" = "0:33:664:regular file" ] && ! grep -q 'old config' $CFG && [ "$(ls -A /etc/irongate)" = "config.yaml" ] && [ ! -e /etc/.irongate-stage ]; echo $?) "now $(st $CFG) ls: $(ls -A /etc/irongate | tr '\n' ' ')"
check "C the generated config is complete (header, layers, blockchain, devices)" $(grep -q '^mode: "single"$' $CFG && grep -q '^  interface: "eth0"$' $CFG && grep -q '^layers:$' $CFG && grep -q '^blockchain:$' $CFG && grep -q '^  fallback_allow: true$' $CFG; echo $?) "$(head -5 $CFG)"

# ======================= OOS-1, block D: access-control.json / auth.json =======================
ACL=/etc/irongate/access-control.json; AUTH=/etc/irongate/auth.json
for f in $ACL $AUTH; do
    n=$(basename $f)
    fresh; victim; ln -s "$V/target" $f; run D
    check "D symlink $n -> root file: target untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
    check "D symlink $n: replaced by a fresh regular root:www-data 0660 file" $([ "$(st $f)" = "0:33:660:regular file" ] && grep -q '^{$' $f; echo $?) "$n now $(st $f) rc=$RC"
    fresh; ln -s "$V/created-by-cat" $f; run D
    check "D dangling symlink $n: the target is not created" $([ ! -e "$V/created-by-cat" ] && [ ! -L "$V/created-by-cat" ]; echo $?) "target now $(st $V/created-by-cat)"
    fresh; mkfifo $f; run D
    check "D FIFO at $n: no hang, replaced by a regular file" $([ $RC -ne 124 ] && [ "$(st $f)" = "0:33:660:regular file" ]; echo $?) "rc=$RC $n $(st $f)"
    fresh; mkdir $f; echo x > $f/inner; run D
    check "D directory at $n: moved aside, regular file in its place" $([ "$(st $f)" = "0:33:660:regular file" ] && [ "$(ls /etc/irongate | grep -c "^$n.refused\.")" = 1 ]; echo $?) "$n $(st $f) rc=$RC"
    # race on the PRESERVED genuine file: chown/chmod must not be redirected by a swap
    fresh; victim; echo '{"genuine":true}' > $f; chown 33:33 $f; chmod 600 $f
    export IG_SWAP_FILE=$n; SWAP=1 run D; unset IG_SWAP_FILE
    check "D race: $n swapped for a symlink right before the installer's chown/chmod (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "shim did not fire (rc=$RC)"
    check "D race: $n - target of the swapped-in symlink untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
    if [ "$HAVE_HELPERS" = 1 ]; then
        fresh; victim; echo '{"genuine":true}' > $f; chown 33:33 $f; chmod 600 $f
        export IG_SWAP_FILE=$n IG_SWAP_NTH=2; SWAP=1 run D; unset IG_SWAP_FILE IG_SWAP_NTH
        check "D race: $n swapped for a symlink between the regular-file check and the pin (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "shim did not fire (rc=$RC)"
        check "D race: $n - the pin links the symlink itself, so the target is untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
    fi
    # genuine preserved file
    fresh; echo '{"genuine":true}' > $f; chown 33:33 $f; chmod 600 $f; run D
    check "D genuine $n is preserved byte for byte and becomes root:www-data 0660" $([ "$(st $f)" = "0:33:660:regular file" ] && [ "$(cat $f)" = '{"genuine":true}' ]; echo $?) "$n now $(st $f): $(cat $f)"
    fresh; run D
    check "D no $n: created root:www-data 0660" $([ "$(st $f)" = "0:33:660:regular file" ]; echo $?) "$n now $(st $f)"
done
fresh; ADMIN_LAN_IP=192.168.1.77 run D
check "D fresh install: access-control.json lists loopback, tailnet and the admin LAN IP" $(grep -q '"127.0.0.1"' $ACL && grep -q '"100.64.0.0/10"' $ACL && grep -q '"192.168.1.77"' $ACL && grep -q '"enabled": true' $ACL; echo $?) "$(cat $ACL)"
check "D fresh install: auth.json holds the admin user and the bcrypt hash" $(grep -q '"username": "admin"' $AUTH && grep -q '"password_hash": "\$2y\$10\$' $AUTH && grep -q '"locked_until": 0' $AUTH; echo $?) "$(cat $AUTH)"
check "D fresh install: nothing but the two files in /etc/irongate, no staging directory left" $([ "$(ls -A /etc/irongate | sort | tr '\n' ' ')" = "access-control.json auth.json " ] && [ ! -e /etc/.irongate-stage ]; echo $?) "ls: $(ls -A /etc/irongate | tr '\n' ' ') stage: $(ls -A /etc/.irongate-stage 2>/dev/null | tr '\n' ' ')"

rm -rf /etc/irongate /etc/.irongate-stage /opt/irongate /var/log/irongate "$V" /tmp/ig-swapped /tmp/ig-install-count
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
