#!/bin/bash
# IronGate end-to-end checks. Runs INSIDE the test container.
#
# Verifies that the extracted source tree actually works at the paths a real
# install uses. Network-dependent Midnight checks are NOT here - they run in the
# separate networked stage, because this stage runs on an isolated network.
#
# Exit code = number of failed checks.

PY=/opt/irongate/venv/bin/python3
PASS=0
FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
run()  { if eval "$2" >/tmp/out 2>&1; then ok "$1"; else bad "$1"; sed 's/^/         /' /tmp/out | tail -6; fi }

echo "=== IronGate E2E checks ==="
echo "--- module and tooling ---"

run "blockchain.py imports and exports MIDNIGHT_AVAILABLE" \
    "$PY -c \"import sys; sys.path.insert(0,'/opt/irongate'); import blockchain; assert blockchain.MIDNIGHT_AVAILABLE is True; assert hasattr(blockchain,'IrongateBlockchain'); assert hasattr(blockchain,'VerificationResult')\""

run "engine irongate.py imports" \
    "$PY -c \"import sys; sys.path.insert(0,'/opt/irongate'); import irongate\""

run "irongate-blockchain CLI responds to --help" \
    "$PY /opt/irongate/irongate-blockchain --help"

run "no Algorand SDK import remains in blockchain.py" \
    "! grep -qE '^\\s*(import|from)\\s+algosdk' /opt/irongate/blockchain.py"

echo "--- security contracts ---"

run "chain outage yields undecided, never a pass (fail-open regression)" \
    "$PY -c \"
import sys; sys.path.insert(0,'/opt/irongate'); import blockchain
bc = blockchain.IrongateBlockchain({'enabled': False, 'fallback_allow': True})
bc.enabled = True; bc.contract_address = '0x00'; bc._get_contract_state = lambda: None
r = bc.verify_device('aa:bb:cc:dd:ee:ff','10.0.0.5')
assert r['verified'] is None, 'expected undecided, got %r' % r['verified']
\""

run "write path raises instead of faking success" \
    "$PY -c \"
import sys; sys.path.insert(0,'/opt/irongate'); import blockchain
bc = blockchain.IrongateBlockchain({'enabled': False})
try:
    bc.register_device('aa:bb:cc:dd:ee:ff','10.0.0.5','isolated','h')
except NotImplementedError:
    raise SystemExit(0)
raise SystemExit('register_device did not raise')
\""

run "unimplemented layers do not claim ACTIVE" \
    "! grep -qE 'Layer: (IPv6 RA Guard|Bypass Detection) - ACTIVE' /opt/irongate/irongate.py"

echo "--- config handling ---"

cat > /etc/irongate/config.yaml <<'YAML'
network:
  interface: "eth0"
  local_ip: "10.99.0.2"
  gateway_ip: "10.99.0.1"
mode: "single"
layers:
  arp_defense: true
  ipv6_ra: true
  gateway_takeover: true
  bypass_detection: true
  firewall: true
blockchain:
  enabled: false
  network: "preprod"
  contract_address: null
  indexer_url: null
  cache_ttl: 60
  fallback_allow: true
  audit_logging: false
  allow_rogue_devices: false
custom_groups: []
devices:
  - mac: "aa:bb:cc:dd:ee:01"
    ip: "10.99.0.50"
    zone: "isolated"
  - mac: "aa:bb:cc:dd:ee:02"
    ip: "10.99.0.51"
    zone: "trusted"
YAML

run "generated config.yaml parses as YAML" \
    "$PY -c \"import yaml; c=yaml.safe_load(open('/etc/irongate/config.yaml')); assert len(c['devices'])==2; assert c['blockchain']['network']=='preprod'\""

# The constructor only records the path; load_config() is what reads the file.
run "engine loads that config without error" \
    "$PY -c \"
import sys; sys.path.insert(0,'/opt/irongate'); import irongate
g = irongate.Irongate('/etc/irongate/config.yaml')
g.load_config()
assert g.config['mode'] == 'single', g.config.get('mode')
assert len(g.config['devices']) == 2
assert g.layer_firewall is True and g.layer_arp_defense is True
assert g.blockchain_enabled is False, 'Layer 8 must stay off by default'
\""

echo "--- web tier ---"

run "api.php present and syntactically valid" "php -l /var/www/irongate/api.php"
run "index.html present"                      "test -s /var/www/irongate/index.html"

run "SQLite device database is creatable and writable" \
    "$PY -c \"
import sqlite3
c = sqlite3.connect('/var/www/irongate/dhcp.db')
c.execute('CREATE TABLE IF NOT EXISTS irongate_devices (mac TEXT PRIMARY KEY, ip TEXT, zone TEXT)')
c.execute(\\\"INSERT OR REPLACE INTO irongate_devices VALUES ('aa:bb:cc:dd:ee:01','10.99.0.50','isolated')\\\")
c.commit()
assert c.execute('SELECT COUNT(*) FROM irongate_devices').fetchone()[0] == 1
c.close()
\""

echo "--- DHCP ---"

run "dnsmasq configuration validates" \
    "dnsmasq --test --interface=eth0 --dhcp-range=10.99.0.100,10.99.0.200,24h --dhcp-script=/opt/irongate/dhcp-notify.sh"

run "dhcp-notify.sh is executable and parses" \
    "bash -n /opt/irongate/dhcp-notify.sh && test -x /opt/irongate/dhcp-notify.sh"

echo "=========================================="
echo "E2E: $PASS passed, $FAIL failed"
echo "=========================================="
exit $FAIL
