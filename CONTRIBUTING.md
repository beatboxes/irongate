# Contributing to IronGate

## The one rule that will trip you up

`irongate-install.sh` is a self-contained installer that carries the entire codebase inside
heredocs. The same code is also committed as ordinary files under `src/`, `web/`, `config/` and
`templates/`.

**The installer is the source of truth.** Editing `src/irongate.py` alone changes nothing about a
real installation — the installer will overwrite it on the next deploy.

```bash
# 1. Edit the heredoc inside irongate-install.sh
# 2. Regenerate the extracted tree
python3 tools/heredoc_sync.py --extract
# 3. Confirm both copies agree
bash tools/check-sync.sh
```

`tools/check-sync.sh` exits non-zero if the two disagree. Run it before opening a pull request; a PR
that fails it will not be merged.

Useful while working:

```bash
python3 tools/heredoc_sync.py --list     # heredoc inventory and where each file lands
python3 tools/heredoc_sync.py --check    # same as check-sync.sh
```

Do not rename `irongate-install.sh`. `src/irongate-updater.sh` and the web UI's update action fetch
it from the repository by that exact name; renaming it silently breaks automatic updates on every
deployed instance.

## Development environment

You do not need a Raspberry Pi to work on most of this. The Docker harness gives you a Debian
container with the dependencies installed:

```bash
bash docker/run-e2e.sh
```

For the Python modules alone:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
IRONGATE_DIR=src ./venv/bin/python tests/test_blockchain.py
```

The Midnight module (`src/blockchain.py`) has no dependencies at all — it uses only the standard
library — so it can be imported and tested anywhere.

## Tests

The suite is standard-library `unittest`. There is no pytest dependency; `python tests/test_blockchain.py`
runs everything.

Network-dependent tests skip rather than fail when there is no route to the Midnight indexer, so the
deterministic suite stays meaningful offline.

The input-validation suite (`tests/test_validation.py`, `tests/test_validation.php`,
`tests/test_updater.sh`, `tests/test_installer_pin.sh`, `tests/test_installer_links.sh`) needs no internet and no root on the device. Run it in
disposable containers:

```bash
python3 -m pytest tests/test_validation.py            # or: python3 -m unittest tests/test_validation.py
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w php:8.3-cli php tests/test_validation.php web
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w python:3.12-slim bash tests/test_updater.sh src/irongate-updater.sh
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w python:3.12-slim bash tests/test_installer_pin.sh irongate-install.sh
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w python:3.12-slim bash tests/test_installer_links.sh irongate-install.sh
```

The dnsmasq root helper (`src/dnsmasq-apply`, irongate-audit O4) and the installer's commit stamp have three more suites
(`tests/test_dnsmasq_phpside.php`, `tests/test_dnsmasq_apply.py`, `tests/test_installer_o4.py`). The PHP one writes the
characterization data (what the web API stages and what the old generator of 18e5177 produced for the same database)
that the Python one reads; the Python one needs a real `dnsmasq` and `visudo` mounted into the container (the commands
below mount the workstation's through their own loader). The helper embeds `dnsmasq`'s option table (`OPTION_VALUES`:
every name a configuration file may use, with its option value, so that aliases of forbidden options are forbidden too)
and `tests/test_dnsmasq_apply.py` reads the table out of the mounted binary and requires the two to be equal: with another
`dnsmasq` version the test names the differences, and the table is regenerated from that binary, never edited by hand
(`python3 tests/test_dnsmasq_apply.py --print-option-table /usr/sbin/dnsmasq` prints the block to paste):

```bash
mkdir -p /tmp/ig-chars
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IG_OUT=/out -v "$PWD":/w:ro -v /tmp/ig-chars:/out -w /w php:8.3-cli php tests/test_dnsmasq_phpside.php web
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IRONGATE_DIR=/w/src -e IG_CHAR_DIR=/chars -v "$PWD":/w:ro -v /tmp/ig-chars:/chars:ro \
    -v /usr/sbin/dnsmasq:/host-dnsmasq:ro -v /lib/x86_64-linux-gnu:/hostlib:ro -w /w python:3.12-slim python -m unittest tests/test_dnsmasq_apply.py
docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IG_INSTALLER=/w/irongate-install.sh -e IG_SRC=/w/src -v "$PWD":/w:ro \
    -v /usr/sbin/visudo:/host-visudo:ro -v /usr/sbin/dnsmasq:/host-dnsmasq:ro -v /lib/x86_64-linux-gnu:/hostlib:ro -v /usr/libexec/sudo:/usr/libexec/sudo:ro -w /w python:3.12-slim python -m unittest tests/test_installer_o4.py
```

The PHP and shell tests overwrite `/var/www/irongate` or `/etc/irongate`, bind local ports or create
root-owned files, so they refuse to run unless `IRONGATE_TEST_SANDBOX=1` is set; never run them on a real
device. `tests/test_blockchain.py` must keep passing both offline and on a host that can reach the real
indexers (a rejected `indexer_url` makes no request, so it never depends on the network).

If you fix a bug, add a test that fails before your fix and passes after it. Please say so in the PR
so a reviewer can verify the same way.

## Things that need care

This is network security software running as root on a device that sits in the middle of somebody's
traffic. A few areas deserve extra scrutiny:

- **The ARP callback runs per packet.** Anything added there must be bounded. No unbounded network
  calls, no unbounded memory.
- **Fail-open is a bug.** If a check cannot be completed, the answer is "undecided, defer to the
  other layers" — never "allow". An unreachable dependency is not evidence that a device is
  trustworthy.
- **Do not report a capability that is not implemented.** Two layers currently log
  `ENABLED IN CONFIG, NOT IMPLEMENTED` for exactly this reason. If you implement them, change the
  log and the README together.
- **The web API has no authentication.** Assume every input reaching `web/api.php` is hostile.
  Values from DHCP — hostnames and MAC addresses — are attacker-controlled. Use `escapeshellarg()`
  for anything reaching a shell, prepared statements for SQL, and the `yamlScalar()` helper for
  anything written into the generated config.
- **Never commit a real device database.** `*.db` is gitignored; keep it that way.

## Code style

Match the file you are editing. The Python is standard-library-first with explicit error handling;
the PHP follows the existing procedural style. Keep diffs minimal — the smallest change that fixes
the root cause, not a drive-by reformat.

## Pull requests

Explain what breaks without the change. Include the evidence you gathered — a failing test, log
output, a reproduction. For anything touching enforcement or the web API, say what you did to
convince yourself it is safe.

## License

Contributions are accepted under the Apache License 2.0.
