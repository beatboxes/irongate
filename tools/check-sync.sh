#!/bin/bash
# Verify that the extracted source tree still matches irongate-install.sh.
#
# The installer carries the whole codebase in heredocs and is the source of truth;
# src/, web/, config/ and templates/ are extracted copies committed for review.
# This check fails if the two disagree.
#
# Usage: bash tools/check-sync.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 tools/heredoc_sync.py --check
