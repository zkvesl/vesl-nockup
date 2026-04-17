#!/usr/bin/env bash
# sync.sh — copy Hoon libs and templates from ../vesl into this repo.
#
# Phase 6.5b: the Rust crate stack (vesl-core, nock-noun-rs,
# nockchain-tip5-rs, nockchain-client-rs) is no longer mirrored here.
# Consumers (test/vesl-test) depend on vesl-core via path/git dep
# directly; nothing for sync.sh to do on the Rust side.
#
# Run from the vesl-nockup repo root. Leaves changes staged for review;
# does not commit.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
vesl="${1:-$HOME/projects/nockchain/vesl}"

if [[ ! -d "$vesl" ]]; then
    echo "vesl source not found at $vesl" >&2
    echo "usage: sync.sh [path-to-vesl-repo]" >&2
    exit 1
fi

echo "syncing from $vesl"

# --- Hoon files ---
echo "  hoon libs"
cp "$vesl/protocol/lib/vesl-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-graft.toml"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/mint-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/mint-graft.toml"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-merkle.hoon" "$here/hoon/lib/"

echo "  hoon common"
cp "$vesl/templates/graft-scaffold/hoon/common/zeke.hoon"    "$here/hoon/common/"
cp "$vesl/templates/graft-scaffold/hoon/common/wrapper.hoon" "$here/hoon/common/"
mkdir -p "$here/hoon/common/ztd"
cp "$vesl/templates/graft-scaffold/hoon/common/ztd/"*.hoon   "$here/hoon/common/ztd/"

echo
echo "sync complete. review with:"
echo "  git status"
echo "  git diff"
echo
echo "nothing has been committed."
