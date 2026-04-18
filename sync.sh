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
cp "$vesl/protocol/lib/settle-graft.hoon" "$here/hoon/lib/"
cp "$vesl/protocol/lib/settle-graft.toml" "$here/hoon/lib/"
cp "$vesl/protocol/lib/mint-graft.hoon"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/mint-graft.toml"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/guard-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/guard-graft.toml"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/forge-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/forge-graft.toml"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-merkle.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-prover.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-lower.hoon"   "$here/hoon/lib/"

# Phase 9b: forge-graft pulls in the STARK prover, which depends on
# /common/v2/table/prover/{compute,memory}, /common/stark/prover,
# /common/nock-common, zose/zoon, and friends. The graft-scaffold
# template's hoon/common/ subset (wrapper + zeke + ztd only) is too
# thin to compile a forge-composed kernel.
#
# vesl/hoon/common is itself a symlink into nockchain/hoon/common,
# and that tree carries nested symlinks (e.g. common/hoon.hoon →
# ../../crates/hoonc/hoon/hoon-138.hoon). `cp -L` dereferences them
# so vesl-nockup ends up with real file content — required for any
# consumer that doesn't have the nockchain repo next to them, which
# is the whole point of vesl-nockup as a distribution.
echo "  hoon common (full tree, incl. STARK deps for forge-graft)"
rm -rf "$here/hoon/common"
cp -rL "$vesl/hoon/common" "$here/hoon/common"

# /#  softed-constraints inside vesl-prover.hoon resolves to
# hoon/dat/softed-constraints.hoon (hoonc's "/#" rune looks in dat/).
# Tiny tree (3 files, 16K); copy wholesale.
echo "  hoon dat (softed-constraints for STARK)"
rm -rf "$here/hoon/dat"
cp -rL "$vesl/hoon/dat" "$here/hoon/dat"

# softed-constraints.hoon in turn loads pre-jammed constraint tables
# from /jams/constraints-0-1.jam and /jams/constraints-2.jam. These
# are large (~16MB total) but unavoidable: the STARK prover uses
# them at compile time as pre-computed Polynomial constraints.
# Without this tree forge-graft compositions fail with
# "missing dependency /jams/constraints-0-1.jam".
echo "  hoon jams (pre-jammed STARK constraint tables, ~16MB)"
rm -rf "$here/hoon/jams"
cp -rL "$vesl/hoon/jams" "$here/hoon/jams"

echo
echo "sync complete. review with:"
echo "  git status"
echo "  git diff"
echo
echo "nothing has been committed."
