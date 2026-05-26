#!/usr/bin/env bash
# vesl-nockup comprehensive preflight — the slow gate for substantial
# commits.
#
# Runs the quick gate (scripts/preflight.sh) first, then adds
# `cargo test --workspace` — which sweeps the integration suite under
# tools/graft-inject/tests/. That suite includes lifecycle tests that
# boot a real nockchain stack via Hoon compilation
# (checkpoint_lifecycle, batch_lifecycle, etc.); expect 30–45 min.
#
# Manual ceremony, NOT on the pre-push hook. Run when commits could
# move the integration surface — graft codegen edits, manifest /
# family changes, vesl-core sync, pin bumps, kernel state-machinery
# edits, new integration tests. See CLAUDE.md §9 for the scenario
# table.
#
# To bail mid-sweep: Ctrl-C.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

step() { printf '\n=== %s ===\n' "$1"; }

step "quick preflight (scripts/preflight.sh)"
"$SCRIPT_DIR/preflight.sh"

step "cargo test --workspace (full sweep, includes the integration suite)"
cargo test --workspace

echo
echo "preflight-full: all clear (comprehensive)."
