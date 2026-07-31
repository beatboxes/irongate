#!/bin/bash
# IronGate DHCP Notification Script
# Called by dnsmasq when lease events occur
# Arguments: $1=action (add|del|old), $2=MAC, $3=IP, $4=hostname

ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="$4"
GRACE_FILE="/var/run/irongate/dhcp_grace.list"
GRACE_SECONDS=30

mkdir -p /var/run/irongate

case "$ACTION" in
    add|old)
        # New or renewed lease - add to grace period list
        EXPIRY=$(($(date +%s) + GRACE_SECONDS))
        
        # Remove any existing entry for this MAC
        if [ -f "$GRACE_FILE" ]; then
            grep -v "^${MAC}," "$GRACE_FILE" > "${GRACE_FILE}.tmp" 2>/dev/null || true
            mv "${GRACE_FILE}.tmp" "$GRACE_FILE" 2>/dev/null || true
        fi
        
        # Add new grace period entry
        echo "${MAC},${IP},${EXPIRY}" >> "$GRACE_FILE"
        
        logger -t irongate "DHCP grace period: $MAC ($IP) - ${GRACE_SECONDS}s"
        ;;
    del)
        # Lease released - remove from grace period
        if [ -f "$GRACE_FILE" ]; then
            grep -v "^${MAC}," "$GRACE_FILE" > "${GRACE_FILE}.tmp" 2>/dev/null || true
            mv "${GRACE_FILE}.tmp" "$GRACE_FILE" 2>/dev/null || true
        fi
        logger -t irongate "DHCP lease released: $MAC ($IP)"
        ;;
esac

exit 0
