#!/usr/bin/env bash
# Atomically bump an upstream PIN across every site in vesl-nockup.
#
# Usage:
#   scripts/bump-pin.sh <type> <40-char-sha> [--sync] [--no-sync]
#
# Type:
#   nock          NOCK_PIN
#   vesl-core     VESL_CORE_PIN
#   vesl-wallet   VESL_WALLET_PIN
#
# Sites:
#   sync.sh                            (canonical default)
#   .github/workflows/ci.yml           (CI env)
#   templates/*/Cargo.toml             (NOCK_PIN only — every
#                                       nockchain/nockchain git-dep)
#
# After all-three-pin bumps, the bundled crates may also need re-syncing
# (because vesl-nockup ships byte-mirrors of vesl-core + vesl-wallet
# crates). Pass --sync to auto-run ./sync.sh; default behavior is to
# print a reminder. --no-sync explicitly silences the reminder.
#
# Pre-flight: SHA must be 40-char lowercase hex AND exist upstream.
# Refuses ghost SHAs — the C-09 root cause this gate exists to prevent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

usage() {
    echo "usage: $0 <type> <sha> [--sync | --no-sync]" >&2
    echo "  type: nock | vesl-core | vesl-wallet" >&2
    echo "  sha:  40-char lowercase hex" >&2
    echo "  --sync:    auto-run ./sync.sh after pin bump" >&2
    echo "  --no-sync: silence the post-bump 'remember to sync' reminder" >&2
    exit 2
}

if [[ $# -lt 2 ]]; then usage; fi

TYPE="$1"
SHA="$2"
RUN_SYNC=
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sync)    RUN_SYNC=1; shift ;;
        --no-sync) RUN_SYNC=0; shift ;;
        *) echo "error: unknown flag: $1" >&2; usage ;;
    esac
done

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: '$SHA' is not a 40-char lowercase hex SHA" >&2
    exit 2
fi

case "$TYPE" in
    nock)
        KEY="NOCK_PIN"
        REPO_PATH="../nockchain"
        REPO_URL="https://github.com/nockchain/nockchain"
        URL_FRAG="nockchain/nockchain"
        ;;
    vesl-core)
        KEY="VESL_CORE_PIN"
        REPO_PATH="../vesl-core"
        REPO_URL="https://github.com/zkvesl/vesl-core"
        URL_FRAG=""  # vesl-core not git-dep'd by templates
        ;;
    vesl-wallet)
        KEY="VESL_WALLET_PIN"
        REPO_PATH="../vesl-wallet"
        REPO_URL="https://github.com/zkvesl/vesl-wallet"
        URL_FRAG=""
        ;;
    *)
        echo "error: unknown pin type: $TYPE" >&2; usage ;;
esac

# Existence check.
found=0
if [[ -d "$REPO_PATH/.git" ]] && \
   git -C "$REPO_PATH" cat-file -t "$SHA" >/dev/null 2>&1; then
    echo "ok — SHA $SHA found in sibling $REPO_PATH"; found=1
fi
if [[ $found -eq 0 ]] && \
   git ls-remote --exit-code "$REPO_URL" "$SHA" >/dev/null 2>&1; then
    echo "ok — SHA $SHA reachable via ls-remote $REPO_URL"; found=1
fi
if [[ $found -eq 0 ]]; then
    echo "error: SHA $SHA not found in $REPO_PATH and not reachable at $REPO_URL" >&2
    echo "       refusing to bump pin to a ghost SHA" >&2
    exit 1
fi

# --- Edits ---
sites_changed=0

# sync.sh canonical default: NAME="${NAME:-<sha>}"
sed -i -E "s/(${KEY}=\"\\\$\\{${KEY}:-)[0-9a-f]{40}/\\1$SHA/" sync.sh
sites_changed=$((sites_changed + 1))
echo "updated sync.sh"

# ci.yml env: NAME: <sha>
sed -i -E "s/(${KEY}:[[:space:]]+)[0-9a-f]{40}/\\1$SHA/" .github/workflows/ci.yml
sites_changed=$((sites_changed + 1))
echo "updated .github/workflows/ci.yml"

# Templates (nockchain only — vesl-core/vesl-wallet aren't git-dep'd by templates).
if [[ "$TYPE" == "nock" && -n "$URL_FRAG" ]]; then
    for tpl in templates/*/Cargo.toml; do
        [[ -f "$tpl" ]] || continue
        if grep -q "$URL_FRAG" "$tpl"; then
            sed -i -E "/$URL_FRAG/ s/(rev[[:space:]]*=[[:space:]]*\")[0-9a-f]{40}/\\1$SHA/g" "$tpl"
            sites_changed=$((sites_changed + 1))
            echo "updated $tpl"
        fi
    done
fi

echo ""
echo "Bumped $KEY to $SHA in $sites_changed site(s)."

# --- Optional sync.sh re-run ---
case "$RUN_SYNC" in
    1)
        if [[ ! -d "$REPO_PATH/.git" ]]; then
            warn_sync_skip="sibling $REPO_PATH not present; cannot run ./sync.sh"
        elif [[ "$(git -C "$REPO_PATH" rev-parse HEAD 2>/dev/null)" != "$SHA" ]]; then
            warn_sync_skip="sibling $REPO_PATH HEAD does not match $SHA; bring it to $SHA before running ./sync.sh"
        fi
        if [[ -n "${warn_sync_skip:-}" ]]; then
            echo "" >&2
            echo "skipping ./sync.sh: $warn_sync_skip" >&2
        else
            echo ""
            echo "Re-syncing bundle (./sync.sh)"
            ./sync.sh
        fi
        ;;
    0)
        : ;;  # quiet
    *)
        echo ""
        echo "Reminder: bundle may need ./sync.sh re-run to mirror the new pin's content."
        echo "  Run scripts/check-pins.sh first to confirm pin agreement."
        echo "  Then ./sync.sh to refresh bundled crates (or pass --sync to bump-pin.sh)."
        ;;
esac

echo ""
echo "Verify with scripts/check-pins.sh."
