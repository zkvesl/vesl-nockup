#!/usr/bin/env bash
# sync.sh — copy Hoon libs, the vesl-core crate stack, the vesl-identity
# bundle (vesl-signing now; vesl-wallet-spec at W5, vesl-wallet at W8),
# and templates from sibling repos into this repo so vesl-nockup is
# self-contained post-sync.
#
# vesl-core is canonical, optimized for local dev (path-deps to sibling
# nockchain). vesl-identity is the github.com/zkvesl/vesl-identity
# workspace bundle introduced in Phase 0 W1-3
# (per vesl-labs/docs/plans/shared-infrastructure/10-PHASE-0-NOW.md).
# vesl-nockup bundles both crate stacks under crates/ and rewrites
# template nockchain path-deps to git-deps on copy, so shipped templates
# compile standalone when end-users pull them via `nockup package add`
# or copy-and-build elsewhere.
#
# Run from the vesl-nockup repo root. Leaves changes staged for review;
# does not commit.

set -euo pipefail

# Pin baked into shipped templates' nockchain git-deps. Bump when the
# synced vesl-core crate stack moves to a new nockchain rev — typically
# whatever sibling ../nockchain/ HEAD was when the crates were last built.
# Overridable via env: NOCK_PIN=<sha> ./sync.sh
NOCK_PIN="${NOCK_PIN:-c51f8040457de1c7d799de6024c4b22275371cf4}"

here="$(cd "$(dirname "$0")" && pwd)"
vesl="${1:-$HOME/projects/nockchain/vesl-core}"
vesl_identity="${2:-$HOME/projects/nockchain/vesl-identity}"

if [[ ! -d "$vesl" ]]; then
    echo "vesl-core source not found at $vesl" >&2
    echo "usage: sync.sh [path-to-vesl-core-repo] [path-to-vesl-identity-repo]" >&2
    exit 1
fi

if [[ ! -d "$vesl_identity" ]]; then
    echo "vesl-identity source not found at $vesl_identity" >&2
    echo "usage: sync.sh [path-to-vesl-core-repo] [path-to-vesl-identity-repo]" >&2
    exit 1
fi

# AUDIT 2026-04-19 M-21: refuse to run when source and destination
# resolve to the same real path. `rm -rf $here/hoon/common` followed
# by `cp -rL` would otherwise self-nuke the repo. Cheap check; the
# resolved paths are stable across the script's lifetime. Apply the
# same check to the vesl-identity arg added in Phase 7.
if [[ "$(realpath "$here" 2>/dev/null)" == "$(realpath "$vesl" 2>/dev/null)" ]]; then
    echo "sync.sh refuses to run: source and destination resolve to the same path" >&2
    echo "  here: $here" >&2
    echo "  vesl: $vesl" >&2
    exit 1
fi
if [[ "$(realpath "$here" 2>/dev/null)" == "$(realpath "$vesl_identity" 2>/dev/null)" ]]; then
    echo "sync.sh refuses to run: source and destination resolve to the same path" >&2
    echo "  here: $here" >&2
    echo "  vesl_identity: $vesl_identity" >&2
    exit 1
fi

# AUDIT 2026-04-19 M-21: `cp -rL` dereferences symlinks by design —
# vesl/hoon/common is a symlink into nockchain/hoon/common, and that
# tree has nested symlinks into the hoonc crate source. Flattening is
# the whole point of this script. It also means a compromised upstream
# vesl checkout could plant a symlink to secrets (e.g. ~/.ssh/id_rsa)
# and have them committed into vesl-nockup. The trust boundary is the
# vesl checkout; operators should review incoming changes the way they
# would any other supply-chain input before running sync.sh.

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
cp "$vesl/protocol/lib/intent-graft.hoon" "$here/hoon/lib/"
cp "$vesl/protocol/lib/intent-graft.toml" "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-merkle.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-prover.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-lower.hoon"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-gates.hoon"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/kv-graft.hoon"     "$here/hoon/lib/"
cp "$vesl/protocol/lib/kv-graft.toml"     "$here/hoon/lib/"
cp "$vesl/protocol/lib/counter-graft.hoon" "$here/hoon/lib/"
cp "$vesl/protocol/lib/counter-graft.toml" "$here/hoon/lib/"
cp "$vesl/protocol/lib/queue-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/queue-graft.toml"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/rbac-graft.hoon"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/rbac-graft.toml"   "$here/hoon/lib/"
cp "$vesl/protocol/lib/registry-graft.hoon" "$here/hoon/lib/"
cp "$vesl/protocol/lib/registry-graft.toml" "$here/hoon/lib/"
# Phase 03 — behavior grafts. clock-graft and log-graft are the
# additive pilots (Phase 03a); validate-graft is the first
# consumer of the prelude marker landed in 03b (Phase 03c).
# index/batch wait on follow-on sub-phases. fsm-graft deferred
# until codegen lands.
cp "$vesl/protocol/lib/log-graft.hoon"      "$here/hoon/lib/"
cp "$vesl/protocol/lib/log-graft.toml"      "$here/hoon/lib/"
cp "$vesl/protocol/lib/clock-graft.hoon"    "$here/hoon/lib/"
cp "$vesl/protocol/lib/clock-graft.toml"    "$here/hoon/lib/"
cp "$vesl/protocol/lib/validate-graft.hoon" "$here/hoon/lib/"
cp "$vesl/protocol/lib/validate-graft.toml" "$here/hoon/lib/"
cp "$vesl/protocol/lib/batch-graft.hoon"    "$here/hoon/lib/"
cp "$vesl/protocol/lib/batch-graft.toml"    "$here/hoon/lib/"

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

# --- Docs ---
# Manifest schema lives in vesl/docs/graft-manifest.md (canonical).
# Mirror it into vesl-nockup so the README's Reference link resolves
# without the consumer needing access to the private vesl repo.
echo "  docs (manifest schema)"
mkdir -p "$here/docs"
cp "$vesl/docs/graft-manifest.md" "$here/docs/"

# --- Intentionally NOT synced: vesl-core/scripts/ ---
# vesl-core ships dev-only scripts (fakenet-harness.sh, check-jam.sh, etc.)
# that drive a chain or compile kernels. vesl-nockup is a distribution
# target — its consumers don't run a fakenet from this repo, and shipping
# a harness here would be misleading. Do not add a `cp -rL "$vesl/scripts"`
# step. If a script is genuinely useful for vesl-nockup users, port the
# minimum surface area into vesl-nockup explicitly (separate file, not a
# mirror).

# --- Rust crate stack ---
# Bundle vesl-core's extracted crate stack into vesl-nockup/crates/ so the
# workspace (tools/, test/) and shipped templates resolve vesl-core path-deps
# within vesl-nockup itself. `cp -rL` dereferences any symlinks for the same
# reasons as the hoon tree copy above. nockchain stays external — the one
# legitimate sibling dep.
echo "  rust crates (vesl-core crate stack)"
mkdir -p "$here/crates"
for c in nock-noun-rs nockchain-tip5-rs nockchain-client-rs vesl-core; do
    rm -rf "$here/crates/$c"
    cp -rL "$vesl/crates/$c" "$here/crates/$c"
done

# --- vesl-identity bundle (Phase 0 W1-3, OD#10) ---
# Mirror the vesl-identity workspace's crate stack into vesl-nockup/crates/
# alongside the vesl-core stack. Currently only `vesl-signing` exists
# (W1-3 lift target); `vesl-wallet-spec` lands at W5 and `vesl-wallet` at
# W8 — the loop here is future-proofed for both. Crates that don't yet
# exist in the source are silently skipped so this script doesn't break
# when run against a partial bundle.
echo "  rust crates (vesl-identity bundle)"
for c in vesl-signing vesl-wallet-spec vesl-wallet; do
    src="$vesl_identity/crates/$c"
    if [[ -d "$src" ]]; then
        rm -rf "$here/crates/$c"
        cp -rL "$src" "$here/crates/$c"
    fi
done

# --- Templates ---
# Mirror vesl/templates/ into vesl-nockup/templates/ so zkvesl-docs
# Path 1 ("copy graft-scaffold") and anyone following the README's
# template flow can reach them without access to the vesl repo.
# app.hoon stays vesl-nockup canonical (marker reference, not synced).
#
# 2026-04-23: graft-intent → graft-hash-gate rename. The old
# graft-intent name is now reserved for the family-5 intent placeholder;
# the pre-rename hash-gate demo moved to graft-hash-gate. Clean the stale
# pre-rename directory if a previous sync left it behind so the loop can
# recreate it from the (now-MOVED.md) canonical copy without drift.
rm -rf "$here/templates/graft-intent"

echo "  templates (graft-scaffold + domain templates + hash-gate demo)"
for t in graft-scaffold graft-hash-gate graft-intent graft-mint graft-settle \
         data-registry settle-report counter; do
    if [[ -d "$vesl/templates/$t" ]]; then
        rm -rf "$here/templates/$t"
        cp -rL "$vesl/templates/$t" "$here/templates/$t"
        # Rewrite nockchain path-deps → git-deps at NOCK_PIN so shipped
        # templates compile without a sibling nockchain/ clone. vesl-core
        # path-deps (../../crates/…) stay — they resolve against the
        # bundled crates/ when built in-place in vesl-nockup; end-users
        # who copy templates out adjust per the graft-scaffold convention.
        # graft-scaffold's own ../../nockchain/… paths are 2 levels up
        # (not 3) and intentionally unrewritten — that template ships
        # with "adjust paths to your clone" comments.
        toml="$here/templates/$t/Cargo.toml"
        if [[ -f "$toml" ]]; then
            sed -i -E \
                's|path = "\.\./\.\./\.\./nockchain/crates/[^"]*"|git = "https://github.com/nockchain/nockchain.git", rev = "'"$NOCK_PIN"'"|g' \
                "$toml"
        fi
    fi
done

echo
echo "sync complete. review with:"
echo "  git status"
echo "  git diff"
echo
echo "nothing has been committed."
