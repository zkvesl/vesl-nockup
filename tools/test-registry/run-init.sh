#!/usr/bin/env bash
#
# End-to-end simulation of `nockup project init` against vesl-nockup as
# both the template source (template_git) and the package source
# (zkvesl/vesl-graft via NOCKUP_REGISTRY_URL).
#
# Verifies that Phase 1's three extension hooks compose correctly:
#   - template_git fetches from file:// URL
#   - NOCKUP_REGISTRY_URL points at a local fixture
#   - the vesl template scaffolds with no manual fixups
#
# Usage:
#   tools/test-registry/run-init.sh [--keep-tempdir]
#
# Env vars:
#   NOCKUP_BIN     — path to a nockup built from the extension-hooks branch
#                    (default: `which nockup`)
#   VESL_NOCKUP    — vesl-nockup checkout path
#                    (default: the dir containing this script's parent)

set -euo pipefail

: "${NOCKUP_BIN:=$(command -v nockup || true)}"
if [[ -z "${NOCKUP_BIN}" ]]; then
  echo "error: nockup binary not found on PATH (set NOCKUP_BIN=)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${VESL_NOCKUP:=$(cd "${SCRIPT_DIR}/../.." && pwd)}"

if [[ ! -f "${VESL_NOCKUP}/templates/vesl/Cargo.toml" ]]; then
  echo "error: VESL_NOCKUP=${VESL_NOCKUP} does not look like a vesl-nockup checkout" >&2
  exit 1
fi

TEMPLATE="${SCRIPT_DIR}/local-registry.toml.tmpl"
if [[ ! -f "${TEMPLATE}" ]]; then
  echo "error: registry template missing at ${TEMPLATE}" >&2
  exit 1
fi

KEEP_TEMP=0
if [[ "${1:-}" == "--keep-tempdir" ]]; then
  KEEP_TEMP=1
fi

TEMPDIR="$(mktemp -d)"
trap 'if [[ ${KEEP_TEMP} -eq 0 ]]; then rm -rf "${TEMPDIR}"; else echo "kept tempdir: ${TEMPDIR}" >&2; fi' EXIT

echo ">> tempdir: ${TEMPDIR}"
echo ">> nockup:  ${NOCKUP_BIN}"
echo ">> vesl-nockup: ${VESL_NOCKUP}"

# Render the registry fixture into the tempdir.
sed "s|__VESL_NOCKUP_PATH__|${VESL_NOCKUP}|g" "${TEMPLATE}" > "${TEMPDIR}/registry.toml"

# Pin the template commit to whatever HEAD is in the local checkout. The
# fetcher's default is `main`, which on a feature branch may not contain
# the template under test. Pinning makes the test deterministic.
TEMPLATE_COMMIT="$(cd "${VESL_NOCKUP}" && git rev-parse HEAD)"

# Write a nockapp.toml that pulls the vesl template from the local
# vesl-nockup checkout via template_git (file:// URL).
cat > "${TEMPDIR}/nockapp.toml" <<TOML
[package]
name = "smoke-app"
version = "0.1.0"
description = "simulation-harness scaffold"
template = "vesl"
template_git = "file://${VESL_NOCKUP}"
template_path = "templates"
template_commit = "${TEMPLATE_COMMIT}"

[dependencies]
TOML

cd "${TEMPDIR}"
NOCKUP_REGISTRY_URL="file://${TEMPDIR}/registry.toml" \
  HOME="${TEMPDIR}/fake-home" \
  "${NOCKUP_BIN}" project init

PROJECT="${TEMPDIR}/smoke-app"
echo ">> asserting on scaffolded project at ${PROJECT}"

# 1. Files exist
for f in Cargo.toml build.rs src/main.rs hoon/app/app.hoon hoon/lib/lib.hoon README.md; do
  if [[ ! -f "${PROJECT}/${f}" ]]; then
    echo "FAIL: ${f} missing from scaffold" >&2
    exit 2
  fi
  echo "   ok: ${f}"
done

# 2. Cargo.toml has both [patch] blocks
if ! grep -qF '[patch."https://github.com/nockchain/nockchain.git"]' "${PROJECT}/Cargo.toml"; then
  echo "FAIL: Cargo.toml missing nockchain [patch] block" >&2
  exit 2
fi
if ! grep -qF '[patch.crates-io]' "${PROJECT}/Cargo.toml"; then
  echo "FAIL: Cargo.toml missing crates-io [patch] block" >&2
  exit 2
fi
echo "   ok: Cargo.toml has both [patch] blocks"

# 3. Cargo.toml renders project_name correctly (handlebars worked)
if ! grep -qF 'name = "smoke-app"' "${PROJECT}/Cargo.toml"; then
  echo "FAIL: Cargo.toml did not render project_name" >&2
  exit 2
fi
echo "   ok: project_name rendered in Cargo.toml"

# 4. build.rs is the no-op shape
if ! grep -qF 'rerun-if-changed=out.jam' "${PROJECT}/build.rs"; then
  echo "FAIL: build.rs is not the no-op shape" >&2
  exit 2
fi
if grep -qF 'Command::new("hoonc")' "${PROJECT}/build.rs"; then
  echo "FAIL: build.rs still invokes hoonc — should be a no-op" >&2
  exit 2
fi
echo "   ok: build.rs is a no-op"

# 5. app.hoon has the nockup markers
markers_required=(
  'nockup:imports'
  'nockup:state'
  'nockup:domain-effect'
  'nockup:effect-union'
  'nockup:cause'
  'nockup:load-defaults'
  'nockup:peek'
  'nockup:poke-prelude'
  'nockup:poke'
  'nockup:poke-postlude'
)
for m in "${markers_required[@]}"; do
  if ! grep -qF "${m}" "${PROJECT}/hoon/app/app.hoon"; then
    echo "FAIL: app.hoon missing marker ${m}" >&2
    exit 2
  fi
done
echo "   ok: app.hoon has all nockup:* markers"

echo ">> all assertions passed"
