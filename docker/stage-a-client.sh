#!/bin/bash
# Stage A (client container). Proves a real DHCP exchange with the test server.
#
# dhclient is deliberately not used to reconfigure the interface: Docker's IPAM has
# already given eth0 a static address outside the server's pool, and removing it
# would break container networking. Instead scapy sends a genuine DHCPDISCOVER and
# sniffs for the server's DHCPOFFER, exercising the same server code path.
echo "=== DHCP client ==="
sleep 6
echo "  eth0: $(ip -4 -o addr show eth0 | awk '{print $4}')"

/opt/irongate/venv/bin/python3 - <<'PY'
import sys
from scapy.all import (Ether, IP, UDP, BOOTP, DHCP, get_if_hwaddr,
                       AsyncSniffer, sendp, conf)

conf.checkIPaddr = False
iface = "eth0"
mac = get_if_hwaddr(iface)
raw = bytes.fromhex(mac.replace(":", ""))

# Sniff first: the offer is broadcast, so srp1's answer-matching does not reliably
# pair it with the request. Capture on udp/68 instead.
sniffer = AsyncSniffer(iface=iface, filter="udp and dst port 68", count=1, timeout=20)
sniffer.start()

discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP(chaddr=raw, xid=0xC0FFEE, flags=0x8000)
    / DHCP(options=[("message-type", "discover"), "end"])
)
print("  sending DHCPDISCOVER from %s" % mac)
sendp(discover, iface=iface, verbose=0)

pkts = sniffer.join() or sniffer.results
if not pkts:
    print("DHCP_EXCHANGE=NO_OFFER")
    sys.exit(1)

reply = pkts[0]
offered = reply[BOOTP].yiaddr
opts = {o[0]: o[1] for o in reply[DHCP].options if isinstance(o, tuple)}
kind = opts.get("message-type")
print("  reply message-type=%s offered=%s server=%s" % (kind, offered, opts.get("server_id")))

if kind == 2 and offered and offered != "0.0.0.0":
    print("DHCP_EXCHANGE=OFFER_RECEIVED ip=%s" % offered)
    sys.exit(0)
print("DHCP_EXCHANGE=UNEXPECTED_REPLY")
sys.exit(1)
PY
echo "  scapy probe exit=$?"

# Stay alive. compose runs with --exit-code-from irongate, which aborts the whole
# run as soon as ANY container exits; if this one exits first it kills the engine
# mid-test. The engine's completion ends the run.
sleep 600
