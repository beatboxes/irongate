#!/bin/bash
# Irongate Auto-Updater (commit hash based)
#
# Runs as root. The web interface may TRIGGER an update (--force) but never
# supplies the code: this script fetches and verifies the installer itself.

GITHUB_API="https://api.github.com/repos/beatboxes/irongate/commits/main"
REPO_RAW_BASE="https://raw.githubusercontent.com/beatboxes/irongate"
STAGE_DIR="/opt/irongate/.update"
MIN_INSTALLER_BYTES=100000
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
DB_PATH="/var/www/irongate/dhcp.db"
LOG_FILE="/var/log/irongate-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Check if auto-update is enabled
AUTO_UPDATE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE" != "true" ] && [ "$FORCE" -ne 1 ]; then
    log "Auto-update is disabled, skipping"
    exit 0
fi

log "Starting update check..."

# Get current commit from database
CURRENT_COMMIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null || echo "unknown")

# Get latest commit from GitHub API
REMOTE_SHA=$(curl -sf -H "User-Agent: Irongate-Updater" "$GITHUB_API" 2>/dev/null | grep -m1 '"sha"' | cut -d'"' -f4)
REMOTE_COMMIT=$(printf '%s' "$REMOTE_SHA" | cut -c1-7)

if [ -z "$REMOTE_COMMIT" ]; then
    log "ERROR: Could not fetch remote commit from GitHub API"
    exit 1
fi

log "Current: $CURRENT_COMMIT, Remote: $REMOTE_COMMIT"

# Update last check time
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));" 2>/dev/null

# Compare commits
if [ "$FORCE" -eq 1 ] || { [ "$CURRENT_COMMIT" != "$REMOTE_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ] && [ "$CURRENT_COMMIT" != "local" ]; }; then
    log "Update available! Downloading..."
    
    # Store the target commit BEFORE running update (in case script fails to set it)
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$REMOTE_COMMIT');" 2>/dev/null
    log "Set target commit to $REMOTE_COMMIT"
    
    # Download the installer into a root-only directory. /tmp is world-writable,
    # so staging there let any local user swap the file between download and
    # execution - and the web user had a sudo grant to run exactly that path.
    mkdir -p "$STAGE_DIR"
    chmod 700 "$STAGE_DIR"
    SCRIPT_PATH="$STAGE_DIR/irongate-install.sh"
    rm -f "$SCRIPT_PATH"

    # Pin to the resolved commit rather than the moving main ref, so the bytes
    # executed are the bytes that were checked.
    if [ -n "$REMOTE_SHA" ]; then
        SRC_URL="$REPO_RAW_BASE/$REMOTE_SHA/irongate-install.sh"
    else
        SRC_URL="$REPO_RAW_BASE/main/irongate-install.sh"
    fi
    log "Downloading $SRC_URL"
    curl -sf -H "User-Agent: Irongate-Updater" "$SRC_URL" -o "$SCRIPT_PATH"

    # Integrity gate. None of this is a substitute for a signature, but it does
    # reject the realistic failures: a truncated download, an HTML error page
    # served instead of the script, or a corrupted file.
    if [ ! -s "$SCRIPT_PATH" ]; then
        log "ERROR: downloaded installer is missing or empty - aborting"
        exit 1
    fi
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
    log "Integrity checks passed (${SCRIPT_SIZE} bytes, syntax valid, commit ${REMOTE_COMMIT})"

    chmod 700 "$SCRIPT_PATH"
    log "Running installer..."
    bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1
    log "Update complete!"
else
    log "Already up to date"
fi

log "Update check finished"
