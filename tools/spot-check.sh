#!/usr/bin/env bash
#
# spot-check.sh — skip-profile path-independence verifier.
#
# Confirms graft-inject's per-graft codegen produces identical sha256
# markers when reached directly (single graft-inject invocation against
# a fresh kernel) vs. cumulatively (the meta-mode A→B→…→<PROFILE>
# sweep that incrementally renames domain causes between transitions).
#
# A path-independence FAIL would mean the cumulative sweep introduced
# structural drift in the graft layer that doesn't match a clean
# direct compose — i.e., meta-mode is masking a graft-side regression.
#
# Per `vesl-core/.dev/DOGFOOD_META.md` §"Skip-profile reachability
# spot-check" + RM5 F_to_G.md TOOL-SUGGEST.
#
# Usage:
#   tools/spot-check.sh <profile-letter>   # A through J
#
# Prerequisites:
#   - graft-inject installed (`make graft-inject`)
#   - hoonc available on PATH
#   - The primary meta sandbox already exists at $META_DIR with the
#     cumulative-domain sweep through at least <profile-letter>:
#     `~/projects/nockchain/vesl-dogfood-meta/meta-evolving-app/hoon/app/app.hoon`

set -euo pipefail

PROFILE="${1:-G}"
SKIP_DIR="${SKIP_DIR:-${HOME}/projects/nockchain/vesl-dogfood-meta-skip}"
META_DIR="${META_DIR:-${HOME}/projects/nockchain/vesl-dogfood-meta}"
NOCKUP_DIR="${NOCKUP_DIR:-${HOME}/projects/nockchain/vesl-nockup}"

# Cumulative graft sets per profile letter, matching DOGFOOD.md
# §"Exercise Profiles" + meta-mode cumulative-domain semantics:
# each profile's set is the union of all preceding profiles' grafts.
# RM5 F→G validated the G profile (12 grafts) directly.
case "$PROFILE" in
  A) GRAFTS="settle-graft,mint-graft,guard-graft" ;;
  B) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft" ;;
  C) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft" ;;
  D) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft,counter-graft,clock-graft,batch-graft" ;;
  E) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft,counter-graft,clock-graft,batch-graft" ;;
  F) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft,counter-graft,clock-graft,batch-graft,queue-graft" ;;
  G) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft,counter-graft,clock-graft,batch-graft,queue-graft,kv-graft" ;;
  H|I|J) GRAFTS="settle-graft,mint-graft,guard-graft,registry-graft,rbac-graft,log-graft,validate-graft,counter-graft,clock-graft,batch-graft,queue-graft,kv-graft" ;;
  *) echo "spot-check.sh: profile '$PROFILE' not in catalog (A-J)" >&2; exit 2 ;;
esac

PRIMARY_HOON="$META_DIR/meta-evolving-app/hoon/app/app.hoon"
if [[ ! -f "$PRIMARY_HOON" ]]; then
  echo "spot-check.sh: primary sandbox app.hoon not found at $PRIMARY_HOON" >&2
  echo "spot-check.sh: run a normal A→${PROFILE} cumulative sweep first per DOGFOOD_META.md" >&2
  exit 1
fi

echo "spot-check.sh: verifying profile $PROFILE — direct vs. cumulative composition"
echo "  primary (cumulative):  $PRIMARY_HOON"
echo "  skip (direct):          $SKIP_DIR/skip-direct-$PROFILE"
echo "  grafts:                 $GRAFTS"

# Wipe + re-stage the skip sandbox.
rm -rf "$SKIP_DIR"
mkdir -p "$SKIP_DIR"
cp -r "$NOCKUP_DIR/templates/graft-scaffold" "$SKIP_DIR/skip-direct-$PROFILE"
cp -r "$NOCKUP_DIR/hoon" "$SKIP_DIR/skip-direct-$PROFILE/"
# Always overlay the canonical 10-marker app.hoon so the spot-check
# is independent of whether RM5 §2.1 (scaffold app.hoon = canonical)
# has been merged on the current branch. templates/app.hoon is
# vesl-nockup-canonical and not synced (sync.sh:194 carve-out).
cp "$NOCKUP_DIR/templates/app.hoon" "$SKIP_DIR/skip-direct-$PROFILE/hoon/app/app.hoon"

cd "$SKIP_DIR/skip-direct-$PROFILE"
graft-inject inject \
  --grafts "$GRAFTS" \
  --accept-untrusted-libs \
  --apply hoon/app/app.hoon \
  > /tmp/spot-check-direct-grafts.txt 2>&1
hoonc --ephemeral hoon/app/app.hoon hoon/ > /tmp/hoonc-spot-$PROFILE.log 2>&1 || true

if [[ ! -s out.jam ]]; then
  echo "spot-check.sh: hoonc produced empty out.jam (direct-compose failure)" >&2
  echo "spot-check.sh: hoonc log follows ----------------------------" >&2
  cat /tmp/hoonc-spot-$PROFILE.log >&2
  echo "spot-check.sh: --------------------------------------------- end" >&2
  exit 1
fi

# Compare per-graft sha256 markers between cumulative and direct paths.
# graft-inject embeds these as `::  graft-inject:<graft>:<block>:begin sha256:<12hex>`
# at every populated marker site.
PRIMARY_SHAS=$(grep -oE "graft-inject:[a-z-]+graft:[a-z-]+:begin sha256:[a-f0-9]+" "$PRIMARY_HOON" | sort -u)
DIRECT_SHAS=$(grep -oE "graft-inject:[a-z-]+graft:[a-z-]+:begin sha256:[a-f0-9]+" "$SKIP_DIR/skip-direct-$PROFILE/hoon/app/app.hoon" | sort -u)

# Filter to only the grafts in this profile (the primary sandbox may
# have grafts beyond <profile> if it's been swept further).
PROFILE_FILTER=$(echo "$GRAFTS" | tr ',' '|')
PRIMARY_FILTERED=$(echo "$PRIMARY_SHAS" | grep -E "graft-inject:($PROFILE_FILTER):" || true)
DIRECT_FILTERED=$(echo "$DIRECT_SHAS"  | grep -E "graft-inject:($PROFILE_FILTER):" || true)

DIFF=$(diff <(echo "$PRIMARY_FILTERED") <(echo "$DIRECT_FILTERED") || true)

if [[ -n "$DIFF" ]]; then
  echo "spot-check.sh: PROFILE $PROFILE — path-independence FAIL"
  echo "Per-graft sha256 marker mismatch:"
  echo "$DIFF"
  exit 1
fi

echo "spot-check.sh: PROFILE $PROFILE — path-independence PASS (per-graft sha256s match)"
