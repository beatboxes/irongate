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
#   R3-1   `find -execdir` (F-A) refuses to run when PATH holds "." or an empty or relative entry: the installer
#          pins an absolute PATH.
#   R3-2   the rename into place must replace a symlink to a DIRECTORY, not move the file into that directory.
#   O1     root's chown/chmod in the web-writable trees (/var/www/irongate, /etc/dnsmasq.d) must not follow a link,
#          not even one swapped in between the check and the change; dhcp.db is 0664, not 0666.
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
for d in /var/www/irongate /etc/dnsmasq.d /etc/dnsmasq.conf; do
    [ -e "$d" ] || [ -L "$d" ] && { echo "refusing to run: $d already exists" >&2; exit 2; }
done
# the installer's fixed PATH (R3-1) and the web-tree permissions (O1: block W, helper WH); an installer from before
# the fix has no PATH segment and no helper, and the checks below then fail instead of being skipped
if grep -q '^# ---- installer PATH: begin ----$' "$INSTALLER"; then
    segment P '^# ---- installer PATH: begin ----$' '^# ---- installer PATH: end ----$'; HAVE_PATHSEG=1
else
    : > "$T/P.sh"; HAVE_PATHSEG=0
fi
segment W '^echo -e "\${YELLOW}Setting permissions\.\.\.\${NC}"$' '^# Ensure lease file has proper ownership for dnsmasq to write$'
if grep -q '^# ---- web-tree permission helper: begin ----$' "$INSTALLER"; then
    segment WH '^# ---- web-tree permission helper: begin ----$' '^# ---- web-tree permission helper: end ----$'; HAVE_WH=1
else
    : > "$T/WH.sh"; HAVE_WH=0
fi
echo "segments: PATH=$(wc -l < "$T/P.sh") web-permissions=$(wc -l < "$T/W.sh") web-helper=$(wc -l < "$T/WH.sh") lines (installer PATH: $HAVE_PATHSEG, web helper: $HAVE_WH)"

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

# R3-2: chmod shim for the commit rename. It swaps NAME for a symlink to a DIRECTORY right before the real chmod of the
# STAGED file (the last command before `mv -fT staged /etc/irongate/NAME`), once per run, when IG_SWAP_COMMIT=NAME.
XSHIM=$T/xshim; mkdir -p "$XSHIM"
cat > "$XSHIM/chmod" <<EOF2
#!/bin/bash
if [ -n "\${IG_SWAP_COMMIT:-}" ] && [ "\${*: -1}" = "/etc/.irongate-stage/\$IG_SWAP_COMMIT" ] && [ ! -e /tmp/ig-swapped ]; then
  : > /tmp/ig-swapped
  if [ -e /etc/irongate/\$IG_SWAP_COMMIT ] || [ -L /etc/irongate/\$IG_SWAP_COMMIT ]; then mv /etc/irongate/\$IG_SWAP_COMMIT /etc/irongate/\$IG_SWAP_COMMIT.orig; fi
  ln -s $V/targetdir /etc/irongate/\$IG_SWAP_COMMIT
fi
exec $REAL_CHMOD "\$@"
EOF2
chmod +x "$XSHIM/chmod"

# O1: the web-tree helper is Python (fchown/fchmod on files opened O_NOFOLLOW), so the races are staged by a python3
# shim: `python3 -I - args` (how the installer calls it) runs under $T/hook.py, which wraps the os functions. It can
# swap an entry for a symlink right before the helper changes it (IG_HOOK_SWAP_DIR/_NAME/_TO; _AT=chown: right before
# a chown/chmod of that very inode or path, _AT=open: right before the helper opens it) and sleep before every file
# operation (IG_HOOK_DELAY) to widen race windows.
REAL_PY=$(command -v python3); PYSHIM=$T/pyshim; mkdir -p "$PYSHIM"
cat > "$T/hook.py" <<'EOF2'
import os, sys, time
swap_dir = os.environ.get('IG_HOOK_SWAP_DIR'); swap_name = os.environ.get('IG_HOOK_SWAP_NAME'); swap_to = os.environ.get('IG_HOOK_SWAP_TO')
swap_at = os.environ.get('IG_HOOK_SWAP_AT', 'chown')
delay = float(os.environ.get('IG_HOOK_DELAY') or 0)
flag = '/tmp/ig-swapped'
real = dict((n, getattr(os, n)) for n in ('open', 'fstat', 'stat', 'lstat', 'listdir', 'fchown', 'fchmod', 'chown', 'chmod', 'lchown'))

def swap():
    if swap_name and not os.path.exists(flag):
        open(flag, 'w').close()
        p = os.path.join(swap_dir, swap_name)
        os.rename(p, p + '.orig')
        os.symlink(swap_to, p)

def denotes(arg):          # is arg (an fd or a path) the entry that is to be swapped?
    try:
        if isinstance(arg, int):
            st, cur = real['fstat'](arg), real['lstat'](os.path.join(swap_dir, swap_name))
            return (st.st_dev, st.st_ino) == (cur.st_dev, cur.st_ino)
        return os.path.basename(os.fspath(arg)) == swap_name
    except OSError:
        return False

def wrap(name, hook):
    r = real[name]
    def f(*a, **k):
        if delay:
            time.sleep(delay)
        hook(a)
        return r(*a, **k)
    setattr(os, name, f)

def on_change(a):
    if swap_name and swap_at == 'chown' and a and denotes(a[0]):
        swap()

def on_open(a):
    if swap_name and swap_at == 'open' and a and os.path.basename(os.fspath(a[0])) == swap_name:
        swap()

for n in ('fchown', 'fchmod', 'chown', 'chmod', 'lchown'):
    wrap(n, on_change)
wrap('open', on_open)
for n in ('fstat', 'stat', 'lstat', 'listdir'):
    wrap(n, lambda a: None)
exec(compile(sys.stdin.read(), '<ig_perm_fix>', 'exec'), {'__name__': '__main__'})
EOF2
cat > "$PYSHIM/python3" <<EOF2
#!/bin/bash
if [ "\$1" = -I ] && [ "\$2" = - ]; then shift 2; exec $REAL_PY -I $T/hook.py "\$@"; fi
exec $REAL_PY "\$@"
EOF2
chmod +x "$PYSHIM/python3"

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

# ======================= R3-1: a caller PATH with ".", an empty or a relative entry =======================
# `find -execdir` (the F-A fix) refuses to run when PATH has such an entry and, under `set -e`, that stops the
# installer. The installer therefore pins a fixed absolute PATH at the very top; block B is run here the way the
# installer reaches it (P first, then the helpers and B) under a polluted caller PATH.
runp() {   # $1 = caller PATH, $2... = segments, sourced in order after the PATH segment
    local p="$1"; shift
    timeout 60 env PATH="$p" "$BASH" -c "
        set -e
        RED=; GREEN=; YELLOW=; CYAN=; NC=
        . $T/P.sh
        for s in $*; do . \$s; done" > "$T/run.out" 2>&1
    RC=$?
}
check "R3-1 the installer pins an absolute PATH at its top (segment found)" $([ "$HAVE_PATHSEG" = 1 ]; echo $?) "no '# ---- installer PATH: begin ----' block in the installer"
for CALLERPATH in ".:/usr/local/bin:/usr/bin:/bin" ":/usr/local/bin:/usr/bin:/bin" "/usr/bin::/bin" "/usr/bin:/bin:" "bin:/usr/bin:/bin" "relative/dir:/usr/bin:/bin"; do
    fresh; runp "$CALLERPATH" "$T/H.sh" "$T/B.sh"
    check "R3-1 caller PATH='$CALLERPATH': block B (find -execdir) still completes" $([ $RC -eq 0 ] && [ "$(st /etc/irongate/config.yaml)" = "0:33:664:regular file" ]; echo $?) "rc=$RC $(tail -2 $T/run.out | cut -c1-200)"
done
fresh; got=$(env PATH=".:/x:" "$BASH" -c ". $T/P.sh; printf '%s' \"\$PATH\"")
check "R3-1 after the PATH segment PATH is exactly the fixed absolute list" $([ "$got" = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ]; echo $?) "PATH=$got"
got=$(env PATH=".:/x:" "$BASH" -c ". $T/P.sh; env | grep '^PATH='")
check "R3-1 ... and it is exported (children see it)" $([ "$got" = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ]; echo $?) "env: $got"

# ======================= R3-2: NAME swapped for a symlink to a DIRECTORY between the check and the commit =======================
# ig_etc_commit ends in `mv -fT staged /etc/irongate/NAME`. -T makes mv rename ONTO the name (replacing a symlink);
# without it a symlink to a directory is a target directory and the staged file would be moved INTO that directory.
runx() {   # like run(), with the commit-swap chmod shim first on PATH
    timeout 60 env PATH="$XSHIM:$PHPSHIM:$PATH" bash -c "
        set -e
        RED=; GREEN=; YELLOW=; CYAN=; NC=
        INTERFACE=eth0; CURRENT_IP=192.168.1.2; CURRENT_GATEWAY=192.168.1.1; ADMIN_LAN_IP=\${ADMIN_LAN_IP:-}
        . $T/H.sh
        . $T/$1.sh" > "$T/run.out" 2>&1
    RC=$?
}
for spec in "B config.yaml 664" "C config.yaml 664" "D access-control.json 660" "D auth.json 660"; do
    set -- $spec; blk=$1; nm=$2; mode=$3
    fresh; mkdir -p "$V/targetdir"; export IG_SWAP_COMMIT=$nm; runx $blk; unset IG_SWAP_COMMIT
    check "R3-2 block $blk: $nm swapped for a symlink to a directory right before the commit rename (shim fired)" $([ -e /tmp/ig-swapped ]; echo $?) "no swap: rc=$RC $(tail -2 $T/run.out | cut -c1-160)"
    check "R3-2 block $blk: ... the directory behind the link stays empty (renamed onto the name, not into the directory)" $([ -z "$(ls -A "$V/targetdir")" ]; echo $?) "targetdir now holds: $(ls -A "$V/targetdir" | tr '\n' ' ')"
    check "R3-2 block $blk: ... and $nm is the new regular root:www-data $mode file, block exits 0" $([ "$(st /etc/irongate/$nm)" = "0:33:$mode:regular file" ] && [ $RC -eq 0 ]; echo $?) "$nm now $(st /etc/irongate/$nm) rc=$RC"
done

# ======================= O1: root's chown/chmod in /var/www/irongate and /etc/dnsmasq.d never follow a link =======================
# Both trees belong to www-data (the web UI writes there), so the web tier can plant, swap and rename entries in them
# while the installer runs as root. Block W is the installer's "Setting permissions" block, run as root.
WEB=/var/www/irongate; DNS=/etc/dnsmasq.d
freshweb() { rm -rf $WEB $DNS /etc/dnsmasq.conf "$V" /tmp/ig-swapped; mkdir -p $WEB $DNS "$V"; : > /etc/dnsmasq.conf; chmod 755 $WEB $DNS; }
mkweb() {   # what the installer finds: files it wrote as root, the DB, a backup, a subdirectory, dnsmasq fragments
    freshweb
    for f in api.php index.php login.php; do echo "<?php // $f" > $WEB/$f; done
    echo db > $WEB/dhcp.db; echo bak > $WEB/dhcp.db.bak.1700000000
    mkdir -p $WEB/sub; echo s > $WEB/sub/x.php
    echo r > $DNS/reservations.conf; echo a > $DNS/extra.conf
}
wst() { stat -c '%u:%g:%a' "$1" 2>/dev/null || echo missing; }
lstw() { find $WEB $DNS /etc/dnsmasq.conf -printf '%p %u:%g %m %y %l\n' 2>/dev/null | sort; }
runw() {   # block W as root, helper loaded first; HOOK=1 runs the helper under the race hook (python3 shim first on PATH)
    timeout 120 env PATH="${HOOK:+$PYSHIM:}$PATH" bash -c "
        set -e
        RED=; GREEN=; YELLOW=; CYAN=; NC=
        . $T/WH.sh
        . $T/W.sh" > "$T/runw.out" 2>&1
    RCW=$?
}
runh() {   # $1 = shell command that uses the helper, run as root under the race hook (python3 shim first on PATH)
    timeout 120 env PATH="$PYSHIM:$PATH" bash -c "
        set -e
        RED=; GREEN=; YELLOW=; CYAN=; NC=
        . $T/WH.sh
        $1" > "$T/runw.out" 2>&1
    RCW=$?
}
check "O1 the web-tree permission helper is in the installer" $([ "$HAVE_WH" = 1 ]; echo $?) "no '# ---- web-tree permission helper: begin ----' block in the installer"

# --- genuine trees
mkweb; runw
check "O1 genuine tree: block W exits 0" $([ $RCW -eq 0 ]; echo $?) "rc=$RCW $(tail -3 $T/runw.out | cut -c1-200)"
check "O1 dhcp.db becomes www-data:www-data 0664 (it was 0666: writable by every local user)" $([ "$(wst $WEB/dhcp.db)" = "33:33:664" ]; echo $?) "dhcp.db now $(wst $WEB/dhcp.db)"
check "O1 the web tree: directory, files, backup and subdirectory are www-data:www-data 0755 as before" $([ "$(wst $WEB)" = 33:33:755 ] && [ "$(wst $WEB/api.php)" = 33:33:755 ] && [ "$(wst $WEB/dhcp.db.bak.1700000000)" = 33:33:755 ] && [ "$(wst $WEB/sub)" = 33:33:755 ] && [ "$(wst $WEB/sub/x.php)" = 33:33:755 ]; echo $?) "$(lstw | head -4)"
check "O1 /etc/dnsmasq.d is www-data:www-data 0775 with its files, /etc/dnsmasq.conf www-data:www-data 0664" $([ "$(wst $DNS)" = 33:33:775 ] && [ "$(wst $DNS/extra.conf)" = 33:33:775 ] && [ "$(wst /etc/dnsmasq.conf)" = 33:33:664 ]; echo $?) "$(wst $DNS) $(wst $DNS/extra.conf) $(wst /etc/dnsmasq.conf)"

# --- same result as the plain recursive chown/chmod it replaces, for odd owners and modes (dhcp.db differs by design)
oddweb() {
    mkweb; chmod 600 $WEB/api.php; chmod 4755 $WEB/index.php; chown 1000:1000 $WEB/login.php; chmod 000 $WEB/sub/x.php
    mkdir -m 2750 $WEB/setgid; echo y > $WEB/setgid/f; chmod 1777 $WEB/setgid/f; mkdir -m 700 $DNS/priv; echo z > $DNS/priv/z; chown 5:5 $DNS/priv/z
    mkdir -p $WEB/sub/deep/er; echo d > $WEB/sub/deep/er/f; chown 1000:1000 $WEB/sub/deep; chmod 700 $WEB/sub/deep; chmod 4755 $WEB/sub/deep/er/f
    chown 7:7 /etc/dnsmasq.conf; chmod 600 /etc/dnsmasq.conf
}
oddweb
chown -R www-data:www-data $WEB; chmod -R 755 $WEB; chown www-data:www-data /etc/dnsmasq.conf; chmod 664 /etc/dnsmasq.conf; chown -R www-data:www-data $DNS; chmod -R 775 $DNS
lstw | grep -v '^/var/www/irongate/dhcp.db ' > "$T/web-ref.lst"
oddweb; runw
lstw | grep -v '^/var/www/irongate/dhcp.db ' > "$T/web-new.lst"
check "O1 every path other than dhcp.db gets exactly what chown -R / chmod -R 755|775 gave it (odd owners, modes, setuid, setgid dir)" $(diff -q "$T/web-ref.lst" "$T/web-new.lst" >/dev/null; echo $?) "$(diff "$T/web-ref.lst" "$T/web-new.lst" | head -6)"

# --- a planted symlink at dhcp.db: the reviewer's reproduction (root:root 0600 -> 0666 through chmod 666)
mkweb; victim; rm $WEB/dhcp.db; ln -s "$V/target" $WEB/dhcp.db; runw
check "O1 symlink dhcp.db -> root-only file: the target keeps root:root 0600 (chmod 666 used to follow the link)" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
check "O1 symlink dhcp.db: refused, block exits non-zero (and does not hang)" $([ $RCW -ne 0 ] && [ $RCW -ne 124 ]; echo $?) "rc=$RCW"
check "O1 symlink dhcp.db: the refusal says why and names the file" $(grep -q 'dhcp.db is a symlink' "$T/runw.out"; echo $?) "$(tail -2 $T/runw.out | cut -c1-200)"
check "O1 symlink dhcp.db: the planted link is left where it is, still pointing at the target (evidence)" $([ "$(readlink $WEB/dhcp.db)" = "$V/target" ]; echo $?) "dhcp.db is now $(st $WEB/dhcp.db)"
mkweb; rm $WEB/dhcp.db; mkfifo $WEB/dhcp.db; runw
check "O1 FIFO at dhcp.db: refused without hanging" $([ $RCW -ne 0 ] && [ $RCW -ne 124 ]; echo $?) "rc=$RCW"
mkweb; rm $WEB/dhcp.db; mkdir $WEB/dhcp.db; runw
check "O1 directory at dhcp.db: refused" $([ $RCW -ne 0 ] && [ $RCW -ne 124 ] && [ "$(wst $WEB/dhcp.db)" != "33:33:664" ]; echo $?) "rc=$RCW dhcp.db $(wst $WEB/dhcp.db)"
mkweb; rm $WEB/dhcp.db; runw
check "O1 no dhcp.db at all: the block stops (as the failing chmod always did)" $([ $RCW -ne 0 ] && [ $RCW -ne 124 ]; echo $?) "rc=$RCW"
mkweb; victim; rm $WEB/dhcp.db; ln "$V/target" $WEB/dhcp.db; runw
check "O1 dhcp.db that is a hard link to a root-only file: refused, the file keeps root:root 0600" $([ $RCW -ne 0 ] && [ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "rc=$RCW victim now $(vstate)"

# --- planted links elsewhere in the trees (GNU chown -R / chmod -R already skipped planted links: these pass before and after)
mkweb; victim; ln -s "$V/target" $WEB/link.php; ln -s "$V/target" $DNS/link.conf; mkdir "$V/dir"; echo k > "$V/dir/f"; chown 77:77 "$V/dir" "$V/dir/f"
ln -s "$V/dir" $WEB/dirlink; ln -s "$V/dir" $DNS/dirlink; ln -s "$V/dangling" $WEB/dangling; runw
check "O1 symlinks inside the trees (file, directory and dangling links): targets untouched, nothing created" $([ "$(vstate)" = "$VICTIM_OK" ] && [ "$(st $V/dir)" = "77:77:755:directory" ] && [ "$(st $V/dir/f)" = "77:77:644:regular file" ] && [ ! -e "$V/dangling" ]; echo $?) "victim $(vstate) dir $(st $V/dir) f $(st $V/dir/f)"
check "O1 ... and the run still succeeds, the other entries are fixed" $([ $RCW -eq 0 ] && [ "$(wst $WEB/api.php)" = 33:33:755 ] && [ "$(wst $DNS/extra.conf)" = 33:33:775 ]; echo $?) "rc=$RCW $(tail -2 $T/runw.out | cut -c1-200)"
mkweb; mkfifo $WEB/fifo $DNS/fifo; runw
check "O1 FIFOs inside the trees: no hang, run succeeds" $([ $RCW -eq 0 ]; echo $?) "rc=$RCW"

# --- a regular file with a second hard link (the web tier cannot make one to a root-only file while
#     fs.protected_hardlinks=1, but with =0 chown/chmod would hit the shared inode): left alone
mkweb; victim; ln "$V/target" $WEB/hl.php; ln "$V/target" $DNS/hl.conf; runw
check "O1 hard-linked files in the trees (here: links to a root-only file) are left alone" $([ "$(vstate)" = "$VICTIM_OK" ] && [ $RCW -eq 0 ]; echo $?) "rc=$RCW victim now $(vstate)"

# --- over-deep tree: bounded, no crash (an attacker can nest directories without limit)
mkweb; ( cd $WEB && for i in $(seq 1 1100); do mkdir d && cd d || exit 1; done )
runw
check "O1 a 1100-level directory nest in the web tree: no crash, normal entries still fixed" $([ $RCW -eq 0 ] && [ "$(wst $WEB/api.php)" = 33:33:755 ]; echo $?) "rc=$RCW $(tail -2 $T/runw.out | cut -c1-200)"

# --- races: the entry is swapped for a symlink to a root-only file right before the helper changes it
swaprace() {   # $1=dir $2=name $3=AT [$4=what the entry is swapped for, default the root-only file]; runs block W under the hook
    export IG_HOOK_SWAP_DIR=$1 IG_HOOK_SWAP_NAME=$2 IG_HOOK_SWAP_TO="${4:-$V/target}" IG_HOOK_SWAP_AT=$3
    HOOK=1 runw
    unset IG_HOOK_SWAP_DIR IG_HOOK_SWAP_NAME IG_HOOK_SWAP_TO IG_HOOK_SWAP_AT
}
mkweb; victim; swaprace $WEB dhcp.db chown
check "O1 race (tree pass): dhcp.db swapped for a symlink right before the chown/chmod (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW) $(tail -2 $T/runw.out | cut -c1-160)"
check "O1 race (tree pass): dhcp.db - the target of the swapped-in link is untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
check "O1 race (tree pass): the inode that was checked (now dhcp.db.orig) got the tree's www-data 0755, and the dhcp.db pass then refuses the link" $([ "$(wst $WEB/dhcp.db.orig)" = 33:33:755 ] && [ $RCW -ne 0 ] && [ $RCW -ne 124 ]; echo $?) "dhcp.db.orig $(wst $WEB/dhcp.db.orig) rc=$RCW"
mkweb; victim; export IG_HOOK_SWAP_DIR=$WEB IG_HOOK_SWAP_NAME=dhcp.db IG_HOOK_SWAP_TO="$V/target" IG_HOOK_SWAP_AT=chown
runh "ig_perm_fix file $WEB/dhcp.db www-data www-data 664"; unset IG_HOOK_SWAP_DIR IG_HOOK_SWAP_NAME IG_HOOK_SWAP_TO IG_HOOK_SWAP_AT
check "O1 race (file pass): dhcp.db swapped for a symlink right before the chown/chmod (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW) $(tail -2 $T/runw.out | cut -c1-160)"
check "O1 race (file pass): the target of the swapped-in link is untouched" $([ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "victim now $(vstate)"
check "O1 race (file pass): the inode that was checked (now dhcp.db.orig) is the one that got www-data 0664" $([ "$(wst $WEB/dhcp.db.orig)" = 33:33:664 ] && [ $RCW -eq 0 ]; echo $?) "dhcp.db.orig $(wst $WEB/dhcp.db.orig) rc=$RCW"
mkweb; victim; swaprace $WEB dhcp.db open
check "O1 race: dhcp.db swapped for a symlink right before the helper opens it (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW)"
check "O1 race: dhcp.db - O_NOFOLLOW refuses the link: target untouched, block exits non-zero" $([ "$(vstate)" = "$VICTIM_OK" ] && [ $RCW -ne 0 ] && [ $RCW -ne 124 ]; echo $?) "rc=$RCW victim now $(vstate)"
mkweb; victim; swaprace $WEB api.php chown
check "O1 race: web tree entry swapped for a symlink right before the chown/chmod (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW)"
check "O1 race: web tree entry - target untouched, the checked inode got www-data 0755" $([ "$(vstate)" = "$VICTIM_OK" ] && [ "$(wst $WEB/api.php.orig)" = 33:33:755 ]; echo $?) "victim $(vstate) api.php.orig $(wst $WEB/api.php.orig)"
mkweb; victim; swaprace $DNS extra.conf chown
check "O1 race: /etc/dnsmasq.d entry swapped right before the chown/chmod (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW)"
check "O1 race: /etc/dnsmasq.d entry - target untouched, the checked inode got www-data 0775" $([ "$(vstate)" = "$VICTIM_OK" ] && [ "$(wst $DNS/extra.conf.orig)" = 33:33:775 ]; echo $?) "victim $(vstate) extra.conf.orig $(wst $DNS/extra.conf.orig)"
mkweb; victim; mkdir "$V/dir"; echo k > "$V/dir/f"; chown 77:77 "$V/dir" "$V/dir/f"; chmod 600 "$V/dir/f"; swaprace $WEB sub open "$V/dir"
check "O1 race: subdirectory swapped for a symlink to a directory right before the helper opens it (hook fired)" $([ -e /tmp/ig-swapped ]; echo $?) "hook did not fire (rc=$RCW)"
check "O1 race: ... the walk does not enter the linked directory (victim directory and file untouched)" $([ "$(st $V/dir)" = "77:77:755:directory" ] && [ "$(st $V/dir/f)" = "77:77:600:regular file" ] && [ "$(vstate)" = "$VICTIM_OK" ]; echo $?) "dir $(st $V/dir) f $(st $V/dir/f)"

rm -rf $WEB $DNS /etc/dnsmasq.conf /tmp/ig-swapped

rm -rf /etc/irongate /etc/.irongate-stage /opt/irongate /var/log/irongate "$V" /tmp/ig-swapped /tmp/ig-install-count
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
