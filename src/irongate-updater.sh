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

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

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

# Update last check time
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));" 2>/dev/null

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
    curl -sf -H "User-Agent: Irongate-Updater" "$SRC_URL" -o "$SCRIPT_PATH"

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

    # Store the target commit BEFORE running update (in case script fails to set it)
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$TARGET_COMMIT');" 2>/dev/null
    log "Set target commit to $TARGET_COMMIT"

    chmod 700 "$SCRIPT_PATH"
    log "Running installer..."
    bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1
    INSTALL_RC=$?
    if [ "$INSTALL_RC" -ne 0 ]; then
        log "ERROR: installer exited with status $INSTALL_RC"
        exit 1
    fi
    # The installer stamps installed_commit with the moving main HEAD; restore
    # the pinned commit so the next scheduled run does not reinstall.
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$TARGET_COMMIT');" 2>/dev/null
    log "Update complete!"
    log "Update check finished"
    # The installer rewrites this very file; bash reads scripts incrementally, so
    # stop here instead of reading whatever now sits at the old offset.
    exit 0
else
    log "Already up to date"
fi

log "Update check finished"
