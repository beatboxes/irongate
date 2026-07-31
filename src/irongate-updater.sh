#!/bin/bash
# Irongate Auto-Updater (commit hash based)

GITHUB_API="https://api.github.com/repos/beatboxes/irongate/commits/main"
REPO_RAW="https://raw.githubusercontent.com/beatboxes/irongate/main"
DB_PATH="/var/www/irongate/dhcp.db"
LOG_FILE="/var/log/irongate-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Check if auto-update is enabled
AUTO_UPDATE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='auto_update_enabled';" 2>/dev/null)
if [ "$AUTO_UPDATE" != "true" ]; then
    log "Auto-update is disabled, skipping"
    exit 0
fi

log "Starting update check..."

# Get current commit from database
CURRENT_COMMIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='installed_commit';" 2>/dev/null || echo "unknown")

# Get latest commit from GitHub API
REMOTE_COMMIT=$(curl -sf -H "User-Agent: Irongate-Updater" "$GITHUB_API" 2>/dev/null | grep -m1 '"sha"' | cut -d'"' -f4 | cut -c1-7)

if [ -z "$REMOTE_COMMIT" ]; then
    log "ERROR: Could not fetch remote commit from GitHub API"
    exit 1
fi

log "Current: $CURRENT_COMMIT, Remote: $REMOTE_COMMIT"

# Update last check time
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update_check', datetime('now'));" 2>/dev/null

# Compare commits
if [ "$CURRENT_COMMIT" != "$REMOTE_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ] && [ "$CURRENT_COMMIT" != "local" ]; then
    log "Update available! Downloading..."
    
    # Store the target commit BEFORE running update (in case script fails to set it)
    sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO settings (key, value) VALUES ('installed_commit', '$REMOTE_COMMIT');" 2>/dev/null
    log "Set target commit to $REMOTE_COMMIT"
    
    # Download and run installer
    SCRIPT_PATH="/tmp/irongate-update.sh"
    curl -sf -H "User-Agent: Irongate-Updater" "$REPO_RAW/irongate-install.sh" -o "$SCRIPT_PATH"
    
    if [ -f "$SCRIPT_PATH" ]; then
        chmod +x "$SCRIPT_PATH"
        log "Running installer..."
        bash "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1
        log "Update complete!"
    else
        log "ERROR: Failed to download update script"
        exit 1
    fi
else
    log "Already up to date"
fi

log "Update check finished"
