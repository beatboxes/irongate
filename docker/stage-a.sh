#!/bin/bash
# Stage A (engine container). Runs on the isolated --internal network.
#
# run-e2e.sh has already proven the network has no path to any real network
# before this script is reached; that is why starting a DHCP server here is safe.
set -o pipefail

echo "=== container network ==="
ip -4 addr show eth0 | sed 's/^/  /'
ip route | sed 's/^/  /'

echo
echo "=== starting dnsmasq on the isolated network ==="
dnsmasq --interface=eth0 --bind-interfaces \
        --dhcp-range=10.99.0.100,10.99.0.200,12h \
        --dhcp-authoritative \
        --log-facility=/var/log/dnsmasq-e2e.log --log-dhcp

sleep 2
if ss -ulnp 2>/dev/null | grep -q ':67 '; then
    echo "  dnsmasq listening on UDP/67"
else
    echo "  dnsmasq FAILED to bind UDP/67"
    exit 1
fi

echo
echo "=== waiting for the client container's DHCP exchange (bounded, 40s) ==="
DHCP_SEEN=no
for i in $(seq 1 40); do
    if grep -qE 'DHCPACK' /var/log/dnsmasq-e2e.log 2>/dev/null; then
        DHCP_SEEN=yes
        echo "  DHCPACK observed after ${i}s"
        break
    fi
    sleep 1
done
[ "$DHCP_SEEN" = no ] && echo "  no DHCPACK within 40s (dnsmasq bind is still verified below)"

echo
echo "=== unit suite (24 tests; live-indexer tests skip on an isolated network) ==="
/opt/irongate/venv/bin/python3 /opt/irongate/tests/test_blockchain.py 2>&1 | tail -25
UNIT=${PIPESTATUS[0]}

echo
bash /opt/irongate/tests/e2e-checks.sh
E2E=$?

echo
echo "--- dnsmasq DHCP log ---"
grep -iE 'DHCP(DISCOVER|OFFER|REQUEST|ACK)' /var/log/dnsmasq-e2e.log 2>/dev/null | tail -12 \
    || echo "  (no DHCP exchange recorded)"

echo
echo "unit_exit=$UNIT e2e_failures=$E2E"
exit $(( UNIT + E2E ))
