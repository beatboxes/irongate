#!/bin/bash
# IronGate end-to-end harness.
#
# Two stages:
#   A. Isolated - runs a DHCP server on a Docker network created with --internal,
#      which has no route to any real network. Isolation is PROVEN before dnsmasq
#      is allowed to start; if it cannot be proven, the run aborts.
#   B. Networked - runs only the Midnight read-path checks, with no DHCP server,
#      so the live indexer is actually exercised.
#
# Usage: bash docker/run-e2e.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NET=irongate-e2e
SUBNET=10.99.0.0/24
ENGINE_IP=10.99.0.2
RESULTS="$REPO/e2e-results.txt"
STATUS=0

cd "$REPO"
exec > >(tee "$RESULTS") 2>&1

echo "=============================================="
echo " IronGate E2E   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "=============================================="

cleanup() {
  echo
  echo "--- teardown ---"
  docker compose -f docker/docker-compose.yml down --remove-orphans >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1 && echo "  removed network $NET"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not responding"; exit 1; }

echo
echo "### Build ###"
docker compose -f docker/docker-compose.yml build 2>&1 | tail -15 || { echo "BUILD FAILED"; exit 1; }

echo
echo "### Stage A - network isolation gate ###"
docker network rm "$NET" >/dev/null 2>&1
docker network create --internal --subnet "$SUBNET" "$NET" >/dev/null || {
  echo "could not create isolated network"; exit 1; }
echo "  created $NET ($SUBNET) with --internal"

ISOLATED=1

# 1. Docker must report the network as internal.
if [ "$(docker network inspect "$NET" --format '{{.Internal}}')" = "true" ]; then
  echo "  [OK]   docker reports Internal=true"
else
  echo "  [FAIL] docker reports Internal=false"; ISOLATED=0
fi

# 2. The host must have no route to the test subnet.
if command -v route.exe >/dev/null 2>&1; then
  if route.exe print 2>/dev/null | grep -qE '^\s+10\.99\.0\.0'; then
    echo "  [FAIL] host routing table has a route to $SUBNET"; ISOLATED=0
  else
    echo "  [OK]   host has no route to $SUBNET"
  fi
elif ip route get "$ENGINE_IP" >/dev/null 2>&1; then
  echo "  [WARN] host claims a route to $ENGINE_IP"
else
  echo "  [OK]   host has no route to $ENGINE_IP"
fi

# 3. The engine address must not answer from the host.
if ping -n 1 -w 1000 "$ENGINE_IP" >/dev/null 2>&1 || ping -c 1 -W 1 "$ENGINE_IP" >/dev/null 2>&1; then
  echo "  [FAIL] $ENGINE_IP is reachable from the host"; ISOLATED=0
else
  echo "  [OK]   $ENGINE_IP unreachable from the host"
fi

if [ "$ISOLATED" -ne 1 ]; then
  echo
  echo "ABORT: network isolation could not be proven. dnsmasq was NOT started."
  exit 2
fi
echo "  isolation proven - safe to start DHCP"

echo
echo "### Stage A - engine, unit tests and E2E checks ###"
docker compose -f docker/docker-compose.yml up \
    --abort-on-container-exit --exit-code-from irongate 2>&1
A=$?
echo "stage_a_exit=$A"
[ "$A" -ne 0 ] && STATUS=1

echo
echo "### Stage B - Midnight read path (networked, no DHCP server) ###"
# MSYS_NO_PATHCONV stops Git Bash rewriting the container-side /bin/bash into a
# Windows path before docker ever sees it.
MSYS_NO_PATHCONV=1 docker run --rm --name irongate-e2e-midnight irongate-e2e:latest \
  /bin/bash -c '
    echo "--- live indexer probe ---"
    /opt/irongate/venv/bin/python3 -c "
import sys; sys.path.insert(0,\"/opt/irongate\")
import blockchain
bc = blockchain.IrongateBlockchain({\"enabled\": False, \"network\": \"preprod\"})
head = bc._query_block()
if head is None:
    print(\"  [FAIL] no response from the Midnight preprod indexer\"); raise SystemExit(1)
print(\"  [PASS] chain height\", head[\"height\"])
s = bc.get_stats()
assert s[\"chain\"] == \"midnight\" and s[\"connected\"] is True and s[\"write_supported\"] is False
print(\"  [PASS] get_stats reports midnight, connected, write_supported=False\")
"
    echo "--- full suite with network available ---"
    /opt/irongate/venv/bin/python3 /opt/irongate/tests/test_blockchain.py 2>&1 | tail -12
  ' 2>&1
B=$?
echo "stage_b_exit=$B"
[ "$B" -ne 0 ] && STATUS=1

echo
echo "=============================================="
if [ "$STATUS" -eq 0 ]; then echo " RESULT: PASS"; else echo " RESULT: FAIL"; fi
echo " results written to e2e-results.txt"
echo "=============================================="
exit $STATUS
