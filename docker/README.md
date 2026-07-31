# End-to-end test harness

```bash
bash docker/run-e2e.sh
```

Output is written to `e2e-results.txt` at the repository root.

## Why this is not a plain `docker compose up`

The harness starts a **DHCP server**. A stray DHCP server on a real network hands out addresses and
a default gateway to anything that asks, which can take a network down. So isolation is not assumed
here — it is proven before dnsmasq is allowed to start, and the run aborts if it cannot be.

`run-e2e.sh` creates the network itself with `--internal`, then checks three independent things:

1. `docker network inspect` reports `Internal: true` — Docker blocks all external connectivity on
   such a network.
2. The host's routing table has no route to `10.99.0.0/24`.
3. `10.99.0.2` does not answer a ping from the host.

Only if all three hold does it bring the containers up. `docker-compose.yml` declares the network as
`external` precisely so that it cannot be created implicitly by `docker compose up`, which would
start dnsmasq before anything had been verified.

## Two stages

**Stage A — isolated.** dnsmasq runs on the internal network. Covers: engine and Midnight module
import, the 24-test unit suite, the CLI, config generation and load, `api.php` syntax, SQLite
writability, dnsmasq config validation and UDP/67 bind, and two security contracts that previously
regressed — that a chain outage yields *undecided* rather than a pass, and that the write path
raises instead of faking success. A second container runs `dhclient` against the server to attempt a
real lease.

Because the network is internal, the Midnight live-indexer tests **skip** in this stage. That is by
design; they are covered in stage B.

### Known limitation: the DHCP lease exchange is not proven here

The client sends a real `DHCPDISCOVER` with scapy, but no `DHCPOFFER` comes back and dnsmasq logs no
exchange at all — meaning the broadcast is not reaching the server across the Docker bridge. This
looks like a property of the container network rather than a fault in IronGate or dnsmasq, but it
has not been root-caused and should not be reported as if DHCP were verified.

What this stage *does* prove about DHCP: dnsmasq accepts the configuration IronGate generates
(`dnsmasq --test` with the real range and `--dhcp-script`), starts, and binds UDP/67. What it does
not prove is a client obtaining a lease. Verifying that needs a network where L2 broadcast between
two hosts is reliable — a bridged VM pair, or a physical test segment.

**Stage B — networked.** A container on a normal network with **no DHCP server**, which queries the
public Midnight preprod indexer and asserts a real chain height comes back. This is what proves the
read path actually works rather than merely being importable.

## Notes

- The image installs the same apt packages the installer does and lays the source out at the real
  runtime paths (`/opt/irongate`, `/var/www/irongate`), so the extracted tree is exercised where it
  actually runs.
- `NET_ADMIN` and `NET_RAW` are granted because scapy and dnsmasq need them. The containers are not
  privileged and have no host network access.
- The image is a test artifact. Do not deploy it.
