#!/usr/bin/env bash
# release.sh — preflight + version bump + release-notes draft for a vesl-nockup tag.
#
# Usage: scripts/release.sh <version>
#   <version> — semver string, optionally with -beta.N / -rc.N prerelease. Leading 'v' stripped.
#
# Behavior:
#   1. Preflight: clean tree, on dev/local-dev, sync equivalence with vesl-core,
#      tests + clippy, cargo check across every template.
#   2. Bump tools/* and test/* crate versions only (mirrored crates/* belong to
#      sync.sh and must NOT be bumped here).
#   3. Render release notes to /tmp/vesl-nockup-release-notes-<version>.md.
#   4. Commit the bump.
#
# Does NOT push. Does NOT tag. Tagging happens on origin/main after squash-push.

set -euo pipefail

VERSION=${1:?usage: scripts/release.sh <version>}
VERSION=${VERSION#v}

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# --- Preflight ---
git diff --quiet || { echo "release.sh: uncommitted changes in working tree"; exit 1; }
git diff --cached --quiet || { echo "release.sh: staged but uncommitted changes"; exit 1; }

branch=$(git rev-parse --abbrev-ref HEAD)
[[ $branch == "dev" || $branch == "local-dev" ]] \
  || { echo "release.sh: must be on dev (or local-dev); current: $branch"; exit 1; }

# Sync equivalence: mirrored crates must match vesl-core verbatim.
# Drift means sync.sh hasn't run since the last vesl-core edit — releasing
# now would ship stale mirror.
echo "release.sh: checking sync equivalence with ../vesl-core"
if ! diff -rq --exclude=target ../vesl-core/crates ./crates >/dev/null 2>&1; then
  echo "release.sh: sync drift detected between ../vesl-core/crates and ./crates"
  echo "  run ./sync.sh in this repo first, review the diff, then re-run release.sh"
  exit 1
fi

echo "release.sh: running cargo test --workspace"
cargo test --workspace

echo "release.sh: running cargo clippy --workspace -- -D warnings"
cargo clippy --workspace -- -D warnings

echo "release.sh: cargo check across templates/*"
for t in templates/*/; do
  if [[ -f "${t}Cargo.toml" ]]; then
    echo "  checking $t"
    (cd "$t" && cargo check --quiet)
  fi
done

# --- Bump ---
echo "release.sh: bumping tools/* and test/* crate versions to $VERSION"
for f in tools/*/Cargo.toml test/*/Cargo.toml; do
  [[ -f "$f" ]] || continue
  if grep -q '^version = "0.0.0-placeholder"' "$f"; then
    echo "  skip (placeholder): $f"
    continue
  fi
  sed -i "0,/^version = \".*\"/{s//version = \"$VERSION\"/}" "$f"
  echo "  bumped: $f"
done

# --- Compute substitutions ---
VESL_CORE_REV=$(cd ../vesl-core && git rev-parse HEAD)
VESL_CORE_TAG=$(cd ../vesl-core && git describe --tags --abbrev=0 2>/dev/null || echo "untagged")
NOCK_PIN=$(awk -F': ' '/^  NOCK_PIN:/{gsub(/[ \t]/, "", $2); print $2; exit}' .github/workflows/ci.yml)

table_for() {
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    name=$(awk -F'"' '/^name *=/{print $2; exit}' "$f")
    ver=$(awk -F'"' '/^version *=/{print $2; exit}' "$f")
    printf "| %-22s | %s |\n" "$name" "$ver"
  done
}

MIRRORED_TABLE=$(table_for crates/*/Cargo.toml)
TOOLING_TABLE=$(table_for tools/*/Cargo.toml test/*/Cargo.toml)
TEMPLATE_LIST=$(ls -1 templates/ 2>/dev/null | awk '{print "- " $0}')

# --- Render notes ---
NOTES=/tmp/vesl-nockup-release-notes-${VERSION}.md
awk -v tag="$VERSION" \
    -v vesl_core_rev="$VESL_CORE_REV" \
    -v vesl_core_tag="$VESL_CORE_TAG" \
    -v nock_pin="$NOCK_PIN" \
    -v mirrored_table="$MIRRORED_TABLE" \
    -v tooling_table="$TOOLING_TABLE" \
    -v template_list="$TEMPLATE_LIST" \
    '{
       gsub(/<TAG>/, tag);
       gsub(/<VESL_CORE_REV>/, vesl_core_rev);
       gsub(/<VESL_CORE_TAG>/, vesl_core_tag);
       gsub(/<NOCK_PIN>/, nock_pin);
       if ($0 ~ /<MIRRORED_TABLE>/) { print mirrored_table; next }
       if ($0 ~ /<TOOLING_TABLE>/)  { print tooling_table;  next }
       if ($0 ~ /<TEMPLATE_LIST>/)  { print template_list;  next }
       print
     }' scripts/release-notes.template.md > "$NOTES"

# --- Commit ---
# Only stage paths the script may have touched (tools/*, test/*).
shopt -s nullglob
to_stage=()
for f in tools/*/Cargo.toml test/*/Cargo.toml; do
  to_stage+=("$f")
done
shopt -u nullglob
if (( ${#to_stage[@]} > 0 )); then
  git add "${to_stage[@]}"
fi

if git diff --cached --quiet; then
  echo "release.sh: no version changes to commit (tools/test already at $VERSION?)"
else
  git commit -m "release: vesl-nockup $VERSION"
fi

echo
echo "release.sh: done."
echo "  notes:  $NOTES"
echo "  next:"
echo "    1. review $NOTES (fill in highlights / breaking / bug-fix sections)"
echo "    2. git push origin $branch"
echo "    3. squash-merge $branch into main on GitHub (or locally), then:"
echo "         git fetch origin main"
echo "         git tag -a v$VERSION -F $NOTES origin/main"
echo "         git push origin v$VERSION"
echo "    4. release.yml fires on the v$VERSION push and creates the GitHub Release"
echo "       using the tag annotation as the body."
