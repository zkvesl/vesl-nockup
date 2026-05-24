#!/usr/bin/env bash
# Verified Hoon compile.
#
# hoonc can exit 0 while producing no kernel: a structural error in the
# Hoon surfaces as a "no panic!" line and an empty or missing `out.jam`,
# not a non-zero exit. Its exit code alone is not trustworthy. This wrapper
# runs hoonc, then checks the `out.jam` artifact and fails loud when hoonc
# lied — so a following `cargo run` never boots a stale or empty kernel.
#
# On success, refreshes .out-jam-source-fingerprint so the next
# `vesl-test verify-jam` reflects this compile rather than the previous
# one — keeping `edit -> ./compile.sh -> vesl-test verify-jam` a clean
# fresh-result loop.
#
# Usage: ./compile.sh [hoon/app/app.hoon]
set -euo pipefail

kernel="${1:-hoon/app/app.hoon}"

hoonc "$kernel" hoon/

if [ ! -s out.jam ]; then
  echo "" >&2
  echo "compile.sh: hoonc exited 0 but out.jam is missing or empty." >&2
  echo "  hoonc silently failed on a structural error in ${kernel}." >&2
  echo "  Re-read hoonc's output above for the [DIAG] / mote line." >&2
  exit 1
fi

# Refresh the verify-jam source fingerprint. Mirror exactly the file set
# vesl-test/src/bin/vesl_test.rs prints in its "missing fingerprint" hint
# (kernel + hoon/lib/*.hoon + hoon/lib/*.toml) — if the sets drift, the
# hint becomes a lie. Atomic write so a SIGINT between sha256sum and
# overwrite cannot leave a partial sidecar.
fingerprint=".out-jam-source-fingerprint"
tmp="$(mktemp "${fingerprint}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
sha256sum "$kernel" hoon/lib/*.hoon hoon/lib/*.toml > "$tmp"
mv "$tmp" "$fingerprint"
trap - EXIT

echo "compile.sh: ${kernel} -> out.jam ($(wc -c < out.jam) bytes), fingerprint refreshed"
