#!/usr/bin/env bash
# vesl-nockup quick preflight — the fast local gate for routine pushes.
#
# Runs the unit-level gates ci.yml depends on: clean tree, branch
# dev/main, pin agreement, bundled-crate sync, lint, and the workspace
# *unit* test suite. Skips the slow integration sweep under
# tools/graft-inject/tests/ that boots real nockchain stacks; for that,
# use scripts/preflight-full.sh (see CLAUDE.md §9 for scenarios).
#
# Manual run:
#   ./scripts/preflight.sh
#
# Pre-push hook:
#   scripts/hooks/pre-push invokes this for pushes targeting
#   refs/heads/{dev,main}. Opt in per-clone with:
#     git config core.hooksPath scripts/hooks
#
# Override (edge cases — known-flaky test, hotfix bypass, etc.):
#   git push --no-verify
#
# Speed: ~30–90s on a warm cargo cache.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

step() { printf '\n--- %s ---\n' "$1"; }

step "working tree"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "preflight: uncommitted changes — commit or stash first" >&2
    git status --short >&2
    exit 1
fi
echo "clean."

step "branch"
branch=$(git rev-parse --abbrev-ref HEAD)
case "$branch" in
    dev|main) echo "$branch (ok)" ;;
    *)
        echo "preflight: on branch '$branch'; push gates run on dev/main only" >&2
        echo "  override: git push --no-verify" >&2
        exit 1
        ;;
esac

step "scripts/check-pins.sh"
./scripts/check-pins.sh

step "./sync.sh --verify (canonical pins)"
./sync.sh --verify

step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo test --workspace --lib (unit tests only — integration suite is the full preflight's job)"
cargo test --workspace --lib

echo
echo "preflight: all clear (quick)."
