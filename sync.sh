#!/usr/bin/env bash
# sync.sh — copy crates and Hoon from ../vesl into this repo, rewriting
# the Cargo.toml deps from monorepo relative paths to git deps.
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

# --- crates ---
for crate in vesl-core nock-noun-rs nockchain-tip5-rs nockchain-client-rs; do
    src="$vesl/crates/$crate"
    dst="$here/crates/$crate"
    echo "  crate: $crate"
    rm -rf "$dst/src" "$dst/tests" 2>/dev/null || true
    mkdir -p "$dst"
    cp "$src/Cargo.toml" "$dst/"
    [[ -f "$src/rust-toolchain.toml" ]] && cp "$src/rust-toolchain.toml" "$dst/"
    cp -r "$src/src" "$dst/"
    [[ -d "$src/tests" ]] && cp -r "$src/tests" "$dst/"
done

# --- Cargo.toml rewrites ---
# Convert monorepo relative paths to git deps. Sibling vesl-crate paths
# (../nockchain-tip5-rs etc.) stay as-is. ibig uses the nockchain fork.
echo "  rewriting Cargo.toml deps"
for toml in "$here"/crates/*/Cargo.toml; do
    sed -i -E \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/nockvm/rust/ibig" ?\}|{ git = "https://github.com/nockchain/nockchain.git", package = "ibig" }|g' \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/nockapp-grpc" ?\}|{ git = "https://github.com/nockchain/nockchain.git" }|g' \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/nockapp", default-features = false ?\}|{ git = "https://github.com/nockchain/nockchain.git", default-features = false }|g' \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/nockvm/rust/nockvm" ?\}|{ git = "https://github.com/nockchain/nockchain.git" }|g' \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/nockvm/rust/nockvm_macros" ?\}|{ git = "https://github.com/nockchain/nockchain.git" }|g' \
        -e 's|\{ ?path = "\.\./\.\./\.\./nockchain/crates/([a-z0-9-]+)" ?\}|{ git = "https://github.com/nockchain/nockchain.git" }|g' \
        "$toml"
done

# --- Hoon files ---
echo "  hoon libs"
cp "$vesl/protocol/lib/vesl-graft.hoon"  "$here/hoon/lib/"
cp "$vesl/protocol/lib/vesl-graft.toml"  "$here/hoon/lib/"
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
