#!/bin/bash
# Irongate Auto-Updater (pinned commit)
#
# Runs as root. The web interface may TRIGGER an update (--force) but never
# supplies the code: this script installs ONLY the commit named in the
# root-owned pin file, and only if the downloaded installer's sha256 equals the
# pin. It never follows the moving main branch.
#
# Pin file (operator-maintained, root:root, mode 0644 or 0600):
#   /etc/irongate/updater-pin.conf
#     PINNED_COMMIT=<40 hex chars>
#     PINNED_INSTALLER_SHA256=<64 hex chars>   # sha256 of irongate-install.sh at that commit
# Update the pin (after reviewing the new commit) to roll out a new version.

REPO_RAW_BASE="https://raw.githubusercontent.com/beatboxes/irongate"
PIN_FILE="/etc/irongate/updater-pin.conf"
STAGE_DIR="/opt/irongate/.update"
MIN_INSTALLER_BYTES=100000
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
DB_PATH="/var/www/irongate/dhcp.db"
LOG_FILE="/var/log/irongate-update.log"

# The database is www-data-owned and php-fpm writes it on every dashboard save,
# while root's own write to it fails on the live host. Every write below runs as
# www-data through runuser; sqlite3 exiting 5 (SQLITE_BUSY) or 6 (SQLITE_LOCKED)
# means another writer holds it, which is expected and is retried once.
DB_RUNUSER="${IG_DB_RUNUSER:-/usr/sbin/runuser}"
DB_SQLITE="${IG_DB_SQLITE3:-/usr/bin/sqlite3}"
DB_BUSY_MS="${IG_DB_BUSY_MS:-5000}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Run exactly one SQL statement against $DB_PATH as www-data and return sqlite3's
# exit status. A busy or locked database is retried once; every other non-zero
# status is returned to the caller without a retry.
ig_sqlite3_write() {
    local sql="$1" rc
    "$DB_RUNUSER" -u www-data -- "$DB_SQLITE" -cmd ".timeout $DB_BUSY_MS" "$DB_PATH" "$sql"
    rc=$?
    if [ "$rc" -eq 5 ] || [ "$rc" -eq 6 ]; then
        "$DB_RUNUSER" -u www-data -- "$DB_SQLITE" -cmd ".timeout $DB_BUSY_MS" "$DB_PATH" "$sql"
        rc=$?
    fi
    return "$rc"
}

# Read one SQL statement the same way: the query result goes to stdout and sqlite3's exit status is returned. Another
# writer holding the database makes a read exit 5 (SQLITE_BUSY) or 6 (SQLITE_LOCKED) too, so the read is retried once.
ig_sqlite3_read() {
    local sql="$1" out rc
    out=$("$DB_RUNUSER" -u www-data -- "$DB_SQLITE" -cmd ".timeout $DB_BUSY_MS" "$DB_PATH" "$sql")
    rc=$?
    if [ "$rc" -eq 5 ] || [ "$rc" -eq 6 ]; then
        out=$("$DB_RUNUSER" -u www-data -- "$DB_SQLITE" -cmd ".timeout $DB_BUSY_MS" "$DB_PATH" "$sql")
        rc=$?
    fi
    printf '%s\n' "$out"
    return "$rc"
}

# One update at a time (the daily timer, the dashboard's "Update now" and an operator can all start this script): the
# second one logs it and exits non-zero. The lock is held on fd 9 until this process exits (the installer it runs gets
# fd 9 closed, so nothing it leaves running can keep the lock).
LOCK_FILE="/run/irongate-updater.lock"
# The lock file is created root-only (0600) by opening it under a restricted umask; an existing lock file keeps its
# mode. fd 9 must stay open in THIS shell, so the umask applies only in a subshell that touches the creation.
if ! { ( umask 077; : >>"$LOCK_FILE" ) && exec 9>>"$LOCK_FILE"; } 2>/dev/null; then
    log "ERROR: cannot open lock file $LOCK_FILE - refusing to update"
    exit 1
fi
if ! flock -n 9; then
    log "another update is running (lock $LOCK_FILE is held) - exiting"
    exit 1
fi

# Load and validate the pin file. Sets PINNED_COMMIT and PINNED_INSTALLER_SHA256,
# or returns 1 after logging why. The file is opened once and that open file is
# inspected and read, so a swap between the check and the read cannot matter.
load_pin() {
    local LC_ALL=C line pin_stat pin_uid pin_gid pin_mode n=0
    PINNED_COMMIT=""
    PINNED_INSTALLER_SHA256=""
    if [ -L "$PIN_FILE" ] || [ ! -f "$PIN_FILE" ]; then
        log "ERROR: pin file $PIN_FILE is missing or not a regular file - refusing to update"
        return 1
    fi
    if ! exec 3< "$PIN_FILE"; then
        log "ERROR: cannot open pin file $PIN_FILE - refusing to update"
        return 1
    fi
    pin_stat=$(stat -L -c '%u:%g:%a' /dev/fd/3 2>/dev/null)
    IFS=: read -r pin_uid pin_gid pin_mode <<< "$pin_stat"
    if [ "$pin_uid" != "0" ] || [ "$pin_gid" != "0" ] \
        || { [ "$pin_mode" != "644" ] && [ "$pin_mode" != "600" ]; }; then
        log "ERROR: pin file $PIN_FILE must be root:root with mode 0644 or 0600 (found uid:gid:mode ${pin_stat:-unknown}) - refusing to update"
        exec 3<&-
        return 1
    fi
    while IFS= read -r line <&3 || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in ''|'#'*) continue ;; esac
        if [[ "$line" =~ ^PINNED_COMMIT=([0-9a-f]{40})$ ]] && [ -z "$PINNED_COMMIT" ]; then
            PINNED_COMMIT="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^PINNED_INSTALLER_SHA256=([0-9a-f]{64})$ ]] && [ -z "$PINNED_INSTALLER_SHA256" ]; then
            PINNED_INSTALLER_SHA256="${BASH_REMATCH[1]}"
        else
            log "ERROR: pin file $PIN_FILE line $n is not valid - refusing to update"
            exec 3<&-
            return 1
        fi
    done
    exec 3<&-
    if [ -z "$PINNED_COMMIT" ] || [ -z "$PINNED_INSTALLER_SHA256" ]; then
        log "ERROR: pin file $PIN_FILE must define PINNED_COMMIT (40 hex) and PINNED_INSTALLER_SHA256 (64 hex) - refusing to update"
        return 1
    fi
    return 0
}

# Check if auto-update is enabled
AUTO_UPDATE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE" != "true" ] && [ "$FORCE" -ne 1 ]; then
    log "Auto-update is disabled, skipping"
    exit 0
fi

log "Starting update check..."

# The pin is the only source of truth for what may be installed.
if ! load_pin; then
    exit 1
fi
TARGET_SHA="$PINNED_COMMIT"
TARGET_COMMIT=$(printf '%s' "$TARGET_SHA" | cut -c1-7)

# Get current commit from database
CURRENT_COMMIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null || echo "unknown")

log "Current: $CURRENT_COMMIT, Pinned: $TARGET_COMMIT"

# Update last check time. It must not stop the update when it fails, but it must
# not be silent either (the old 2>/dev/null hid every failure).
ig_sqlite3_write "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));"
DB_RC=$?
if [ "$DB_RC" -ne 0 ]; then
    log "ERROR: could not record last_update_check in $DB_PATH (sqlite3 status $DB_RC) - continuing"
fi

# --force re-runs nothing that is already installed: at the pinned commit it is a logged no-op (nothing is downloaded)
if [ "$FORCE" -eq 1 ] && [ "$CURRENT_COMMIT" = "$TARGET_COMMIT" ]; then
    log "--force: installed == pin ($TARGET_COMMIT), nothing to do - not downloading"
    log "Update check finished"
    exit 0
fi

# Compare commits
if [ "$FORCE" -eq 1 ] || { [ "$CURRENT_COMMIT" != "$TARGET_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ] && [ "$CURRENT_COMMIT" != "local" ]; }; then
    log "Update available! Downloading..."

    # Download the installer into a root-only directory. /tmp is world-writable,
    # so staging there let any local user swap the file between download and
    # execution - and the web user had a sudo grant to run exactly that path.
    mkdir -p "$STAGE_DIR"
    chmod 700 "$STAGE_DIR"
    SCRIPT_PATH="$STAGE_DIR/irongate-install.sh"
    rm -f "$SCRIPT_PATH"

    # Fetch the pinned commit, never the moving main ref.
    SRC_URL="$REPO_RAW_BASE/$TARGET_SHA/irongate-install.sh"
    log "Downloading $SRC_URL"
    curl -sf --max-time 60 -H "User-Agent: Irongate-Updater" "$SRC_URL" -o "$SCRIPT_PATH"

    if [ ! -s "$SCRIPT_PATH" ]; then
        log "ERROR: downloaded installer is missing or empty - aborting"
        exit 1
    fi

    # Authenticity gate: the bytes must be exactly the bytes that were reviewed
    # and pinned. Checked before the file is made executable or run.
    ACTUAL_SHA256=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)
    if [ "$ACTUAL_SHA256" != "$PINNED_INSTALLER_SHA256" ]; then
        log "ERROR: installer sha256 ${ACTUAL_SHA256:-unavailable} does not match pin $PINNED_INSTALLER_SHA256 - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi

    # Sanity gate: reject a truncated download or an unparseable script.
    SCRIPT_SIZE=$(stat -c%s "$SCRIPT_PATH" 2>/dev/null || echo 0)
    if [ "$SCRIPT_SIZE" -lt "$MIN_INSTALLER_BYTES" ]; then
        log "ERROR: installer is only ${SCRIPT_SIZE} bytes, expected >= ${MIN_INSTALLER_BYTES} - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi
    if ! bash -n "$SCRIPT_PATH" 2>/dev/null; then
        log "ERROR: installer failed syntax check - aborting"
        rm -f "$SCRIPT_PATH"
        exit 1
    fi
    log "Integrity checks passed (${SCRIPT_SIZE} bytes, sha256 matches pin, syntax valid, commit ${TARGET_COMMIT})"

    # installed_commit is stamped only AFTER the installer has exited 0 (below). Stamping it first made a
    # failed installer look installed: the next scheduled run said "Already up to date" and never retried.
    chmod 700 "$SCRIPT_PATH"

    # The installer rewrites the configuration directory (the pin file's directory). Before it runs, that directory is
    # snapshotted, owners and modes included, to a root-only tarball next to the staged installer (0600, root:root);
    # if the installer fails, the directory is put back from it (it holds what the dashboard saved, the login and the
    # access list).
    CONF_DIR="${PIN_FILE%/*}"
    SNAPSHOT="$STAGE_DIR/conf-snapshot.tar"
    rm -f "$SNAPSHOT"
    if ! ( umask 077; tar -C "$CONF_DIR" --numeric-owner -cpf "$SNAPSHOT" . ) 2>/dev/null; then
        log "ERROR: cannot snapshot $CONF_DIR - not running the installer"
        rm -f "$SNAPSHOT"
        exit 1
    fi
    chown root:root "$SNAPSHOT" && chmod 600 "$SNAPSHOT"
    log "Snapshot of $CONF_DIR taken (root:root 0600)"

    log "Running installer..."
    bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1 9>&-
    INSTALL_RC=$?
    if [ "$INSTALL_RC" -ne 0 ]; then
        if tar -C "$CONF_DIR" --same-owner -p --numeric-owner -xf "$SNAPSHOT" 2>/dev/null; then
            RESTORE_MSG="$CONF_DIR restored from the snapshot taken before the installer ran (extracted over the directory; entries the failed run created are left in place)"
            rm -f "$SNAPSHOT"
        else
            RESTORE_MSG="ERROR: restoring $CONF_DIR from $SNAPSHOT failed - the snapshot is kept"
        fi
        log "ERROR: installer exited with status $INSTALL_RC"
        log "$RESTORE_MSG"
        exit 1
    fi
    rm -f "$SNAPSHOT"
    log "Installer succeeded - snapshot removed"
    # The installer stamps installed_commit with the moving main HEAD; restore
    # the pinned commit so the next scheduled run does not reinstall. A stamp
    # that does not land leaves installed != pin, so every "Update now" press
    # would reinstall: it is an error here, never a quiet success.
    if ! [[ "$TARGET_COMMIT" =~ ^[0-9a-f]{7}$ ]]; then
        log "ERROR: refusing to record installed_commit '$TARGET_COMMIT' - not a 7-hex commit id"
        exit 1
    fi
    ig_sqlite3_write "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$TARGET_COMMIT');"
    DB_RC=$?
    if [ "$DB_RC" -ne 0 ]; then
        log "ERROR: could not record installed_commit $TARGET_COMMIT in $DB_PATH (sqlite3 status $DB_RC) - the next run will reinstall"
        exit 1
    fi
    STAMPED_COMMIT=$(ig_sqlite3_read "SELECT value FROM settings WHERE key='installed_commit';")
    DB_RC=$?
    if [ "$DB_RC" -ne 0 ] || [ "$STAMPED_COMMIT" != "$TARGET_COMMIT" ]; then
        log "ERROR: installed_commit read-back failed (sqlite3 status $DB_RC, read '${STAMPED_COMMIT:-}') - expected $TARGET_COMMIT"
        exit 1
    fi
    log "Update complete!"
    log "Update check finished"
    # The installer rewrites this very file; bash reads scripts incrementally, so
    # stop here instead of reading whatever now sits at the old offset.
    exit 0
else
    log "Already up to date"
fi

log "Update check finished"
