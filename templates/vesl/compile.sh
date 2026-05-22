#!/usr/bin/env bash
# Verified Hoon compile.
#
# hoonc can exit 0 while producing no kernel: a structural error in the
# Hoon surfaces as a "no panic!" line and an empty or missing `out.jam`,
# not a non-zero exit. Its exit code alone is not trustworthy. This wrapper
# runs hoonc, then checks the `out.jam` artifact and fails loud when hoonc
# lied — so a following `cargo run` never boots a stale or empty kernel.
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

echo "compile.sh: ${kernel} -> out.jam ($(wc -c < out.jam) bytes)"
