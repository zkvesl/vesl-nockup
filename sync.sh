#!/usr/bin/env bash
# sync.sh — copy Hoon libs, the vesl-core crate stack, the vesl-wallet
# workspace (vesl-signing + vesl-wallet-spec + vesl-wallet), and
# templates from sibling repos into this repo so vesl-nockup is
# self-contained post-sync.
#
# vesl-core is canonical, optimized for local dev (path-deps to sibling
# nockchain). The vesl-wallet workspace is the github.com/zkvesl/vesl-wallet
# bundle (formerly named vesl-identity).
# vesl-nockup bundles both crate stacks under crates/ and rewrites
# template nockchain path-deps to git-deps on copy, so shipped templates
# compile standalone when end-users pull them via `nockup package add`
# or copy-and-build elsewhere.
#
# Run from the vesl-nockup repo root. Leaves changes staged for review;
# does not commit.
#
# --verify: copy + rewrite into a temp dir and diff against the
# committed bundle. Nonzero exit on drift. Used by CI to catch
# hand-edits to bundled crates / templates and sync.sh logic changes
# that weren't re-run.

set -euo pipefail

# --- arg parsing ---
SYNC_VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
    SYNC_VERIFY=1
    shift
fi

# --- pins ---
# nockchain rev baked into shipped templates' git-deps. Bump when the
# synced vesl-core crate stack moves to a new nockchain rev — typically
# whatever sibling ../nockchain/ HEAD was when the crates were last built.
# Overridable via env: NOCK_PIN=<sha> ./sync.sh
NOCK_PIN="${NOCK_PIN:-1a23ccdabf3f8909bf7c7966c48edc36cbf91a66}"

# vesl-core rev that the bundled crate stack + templates were last
# synced from. sync.sh aborts when the sibling vesl-core's HEAD does
# not match this — bump the pin deliberately (edit this line) before
# re-running. Overridable via env: VESL_CORE_PIN=<sha> ./sync.sh
VESL_CORE_PIN="${VESL_CORE_PIN:-6090499c5a2ff8267bfb4b122497b9256acb34b8}"

here="$(cd "$(dirname "$0")" && pwd)"
vesl="${1:-$HOME/projects/nockchain/vesl-core}"
vesl_wallet_repo="${2:-$HOME/projects/nockchain/vesl-wallet}"

if [[ ! -d "$vesl" ]]; then
    echo "vesl-core source not found at $vesl" >&2
    echo "usage: sync.sh [--verify] [path-to-vesl-core-repo] [path-to-vesl-wallet-repo]" >&2
    exit 1
fi

if [[ ! -d "$vesl_wallet_repo" ]]; then
    echo "vesl-wallet source not found at $vesl_wallet_repo" >&2
    echo "usage: sync.sh [--verify] [path-to-vesl-core-repo] [path-to-vesl-wallet-repo]" >&2
    exit 1
fi

# --- pin check ---
# Block sync when the sibling vesl-core HEAD has drifted from the
# committed VESL_CORE_PIN. The operator bumps the pin by editing the
# default above; CI uses VESL_CORE_PIN=<sha> override.
if command -v git >/dev/null 2>&1; then
    vesl_head=$(git -C "$vesl" rev-parse HEAD 2>/dev/null || echo "")
    if [[ -n "$vesl_head" && "$vesl_head" != "$VESL_CORE_PIN" ]]; then
        echo "vesl-core pin mismatch:" >&2
        echo "  expected (VESL_CORE_PIN in sync.sh):  $VESL_CORE_PIN" >&2
        echo "  actual  ($vesl HEAD):                 $vesl_head" >&2
        echo >&2
        echo "To bump: edit VESL_CORE_PIN at the top of sync.sh to the new SHA," >&2
        echo "then re-run. CI overrides with VESL_CORE_PIN=<sha> ./sync.sh --verify." >&2
        exit 1
    fi
    # Soft-warn on dirty working tree — pin only guarantees committed
    # state matches; uncommitted changes leak into the bundle. Includes
    # untracked files since `cp -rL` copies them too.
    if ! git -C "$vesl" diff --quiet 2>/dev/null || \
       ! git -C "$vesl" diff --cached --quiet 2>/dev/null || \
       [[ -n "$(git -C "$vesl" ls-files --others --exclude-standard 2>/dev/null)" ]]; then
        echo "warning: $vesl has uncommitted or untracked changes; sync copies working tree, not HEAD" >&2
    fi
fi

# Refuse same-path runs — later `rm -rf $here/...` + `cp -rL` would
# otherwise self-nuke the repo. Cheap check; resolved paths are
# stable across the script's lifetime.
if [[ "$(realpath "$here" 2>/dev/null)" == "$(realpath "$vesl" 2>/dev/null)" ]]; then
    echo "sync.sh refuses to run: source and destination resolve to the same path" >&2
    echo "  here: $here" >&2
    echo "  vesl: $vesl" >&2
    exit 1
fi
if [[ "$(realpath "$here" 2>/dev/null)" == "$(realpath "$vesl_wallet_repo" 2>/dev/null)" ]]; then
    echo "sync.sh refuses to run: source and destination resolve to the same path" >&2
    echo "  here: $here" >&2
    echo "  vesl_wallet_repo: $vesl_wallet_repo" >&2
    exit 1
fi

# Trust boundary: `cp -rL` dereferences symlinks (vesl/hoon/common is
# itself a symlink into nockchain/hoon/common with nested symlinks into
# hoonc crate source — flattening is intentional so consumers get real
# file content). A compromised upstream vesl checkout could plant a
# symlink to secrets (e.g. ~/.ssh/id_rsa) that ends up committed here.
# Review incoming vesl changes like any supply-chain input.

# --- destination ---
# In verify mode, redirect all writes to a fresh empty temp dir. After
# sync, diff temp vs $here for the known sync-target subtrees only.
# Don't seed the temp with $here — vesl-nockup carries multi-GB
# target/ build artifacts and `cp -rL` would copy all of them.
real_here="$here"
if [[ $SYNC_VERIFY -eq 1 ]]; then
    here=$(mktemp -d -t vesl-nockup-sync-verify.XXXXXX)
    trap 'rm -rf "$here"' EXIT
    # Pre-create dirs sync writes into without mkdir -p of its own.
    mkdir -p "$here/hoon/lib" "$here/templates"
    echo "verify mode: syncing to $here, will diff against $real_here"
else
    echo "syncing from $vesl"
fi

# --- Hoon files ---
#
# Intentionally NOT synced — kernel-private internals:
#   forge-kernel.hoon, guard-kernel.hoon, mint-kernel.hoon,
#   settle-kernel.hoon, vesl-kernel.hoon       (the kernels)
#   kernel-arms.hoon                            (shared dispatch arms)
#   vesl-stark.hoon, vesl-stark-verifier.hoon   (STARK glue)
#   vesl-verifier.hoon, vesl-mint.hoon          (kernel-private math)
#   vesl-entrypoint.hoon                        (STAGED ABI placeholder)
#   rag-logic.hoon                              (lives per-template)
#   vesl-test.hoon                              (compile-time test arms)
#
# These are consumed only by the kernel libraries, which vesl-nockup
# users never recompile from source. Kernels ship as committed JAM
# artifacts in vesl-core/assets/ and are loaded via include_bytes! from
# the kernels/{guard,mint,settle} Rust crates that vesl-nockup doesn't
# mirror; vesl-nockup composes domain apps via graft-inject instead.
# If you spot a missing file in this list and reach for "obviously add
# it" — that's why it's missing.
#
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
cp "$vesl/protocol/lib/domain-patterns.hoon" "$here/hoon/lib/"
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

# forge-graft pulls in the STARK prover, which depends on the full
# /common/v2/table/prover/{compute,memory}, /common/stark/prover,
# /common/nock-common, zose/zoon tree. The graft-scaffold template's
# hoon/common/ subset (wrapper + zeke + ztd only) is too thin to
# compile a forge-composed kernel. cp -rL flattens nested symlinks
# (see trust-boundary note above).
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

# templates/README.md walks consumers through the template catalog;
# templates/GRAFTING.md explains how to graft a tentacle onto an existing
# nockapp (covers both `nockup graft inject` and Docker integrators).
# Keep the canonical copies in vesl-core; mirror so end users pulling a
# template via nockup still see the orientation docs alongside it.
echo "  docs (template README + GRAFTING walkthrough)"
mkdir -p "$here/templates"
cp "$vesl/templates/README.md"    "$here/templates/README.md"
cp "$vesl/templates/GRAFTING.md"  "$here/templates/GRAFTING.md"

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
for c in nock-noun-rs nockchain-tip5-rs nockchain-client-rs vesl-core vesl-checkpoint; do
    rm -rf "$here/crates/$c"
    cp -rL "$vesl/crates/$c" "$here/crates/$c"
done

# --- vesl-wallet workspace (formerly vesl-identity, OD#10) ---
# Mirror the vesl-wallet workspace's three crates (vesl-signing,
# vesl-wallet-spec, vesl-wallet) into vesl-nockup/crates/ alongside the
# vesl-core stack. Crates that don't yet exist in the source are
# silently skipped so this script doesn't break when run against a
# partial bundle.
echo "  rust crates (vesl-wallet workspace)"
for c in vesl-signing vesl-wallet-spec vesl-wallet; do
    src="$vesl_wallet_repo/crates/$c"
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

echo "  templates (graft-scaffold + domain templates + hash-gate demo + vesl)"
for t in graft-scaffold graft-hash-gate graft-intent graft-mint graft-settle \
         data-registry settle-report counter vesl; do
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
        # vesl-nockup ships the codegen binary as `nockup-graft` (the
        # sidecar that `nockup graft <subcmd>` dispatches to). vesl-core
        # canonical names it `graft-inject`. Rewrite build.rs strings so
        # shipped templates invoke the nockup-named binary at scaffold
        # time. Editorial CLI mentions in .hoon comments are backported
        # to vesl-core canonical instead (single source of truth there).
        buildrs="$here/templates/$t/build.rs"
        if [[ -f "$buildrs" ]]; then
            sed -i 's/graft-inject/nockup-graft/g' "$buildrs"
        fi
        # Strip cargo build artifacts that local `cargo build` left in
        # vesl-core/templates/<t>/. Shipped templates are source-only;
        # target/ is multi-GB pollution and pollutes the verify diff.
        rm -rf "$here/templates/$t/target"
    fi
done

# --- .sync-pins.toml ---
# Records the pins this bundle was synced from. CI's sync-verify job
# regenerates this and diffs; hand-bumping a pin here without re-running
# sync.sh produces drift and fails CI.
cat > "$here/.sync-pins.toml" <<EOF
# Auto-generated by sync.sh. Bumping a pin here is meaningless without
# re-running sync. See VESL_CORE_PIN / NOCK_PIN at the top of sync.sh.

[vesl-core]
repo = "https://github.com/zkvesl/vesl-core"
pin  = "$VESL_CORE_PIN"

[nockchain]
repo = "https://github.com/nockchain/nockchain"
pin  = "$NOCK_PIN"
EOF

# --- verify diff ---
if [[ $SYNC_VERIFY -eq 1 ]]; then
    # Preserve files that live under synced dirs but sync.sh deliberately
    # doesn't touch (kept-canonical files). Without this they'd register
    # as drift (missing in the empty temp). Extend this list if other kept
    # files emerge.
    #
    #   templates/app.hoon — the canonical scaffold marker reference.
    #   hoon/lib/lib.hoon — placeholder `/+  lib` import target for the
    #     BARE_SCAFFOLD test fixture; not a sync-derived graft.
    #   templates/WALLET_CONFIG.md — vesl-nockup-local TOML-toggle doc
    #     for the per-role wallet config pattern.
    [[ -f "$real_here/templates/app.hoon" ]] && \
        cp "$real_here/templates/app.hoon" "$here/templates/app.hoon"
    [[ -f "$real_here/hoon/lib/lib.hoon" ]] && \
        cp "$real_here/hoon/lib/lib.hoon" "$here/hoon/lib/lib.hoon"
    [[ -f "$real_here/templates/WALLET_CONFIG.md" ]] && \
        cp "$real_here/templates/WALLET_CONFIG.md" "$here/templates/WALLET_CONFIG.md"
    echo
    echo "verifying sync output against committed bundle"
    # Restrict diff to paths sync.sh actually writes. A full $here vs
    # $real_here diff would flag every untouched file in $real_here as
    # "missing" because temp seeded with $real_here/. and sync only
    # overwrites specific subtrees — anything else is identical.
    drift=0
    for path in hoon/lib hoon/common hoon/dat hoon/jams docs/graft-manifest.md \
                crates templates .sync-pins.toml; do
        # Exclude target/ — cargo build artifacts pollute both sides
        # and aren't part of shipped templates. Exclude Cargo.lock for
        # the same reason; per-template lockfiles drift with every
        # transitive dep release and aren't what sync produces.
        if ! diff -ruN --exclude=target --exclude=Cargo.lock \
                "$real_here/$path" "$here/$path" > /tmp/sync-verify-diff.$$ 2>&1; then
            echo "DRIFT: $path"
            cat /tmp/sync-verify-diff.$$
            drift=1
        fi
        rm -f /tmp/sync-verify-diff.$$
    done
    if [[ $drift -eq 0 ]]; then
        echo "OK — sync output matches committed bundle"
        exit 0
    else
        exit 1
    fi
fi

echo
echo "sync complete. review with:"
echo "  git status"
echo "  git diff"
echo
echo "nothing has been committed."
