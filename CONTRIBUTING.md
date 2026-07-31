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
