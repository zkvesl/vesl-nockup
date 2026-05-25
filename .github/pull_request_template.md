<!--
Thanks for opening a PR! Quick checklist before you submit:

- [ ] PR targets the `dev` branch (not `main`).
- [ ] My change does NOT touch any paths listed as "synced from
      vesl-core" or "synced from vesl-wallet" in CONTRIBUTING.md's
      canonical-path table.
- [ ] `cargo test --workspace` passes locally.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean.

If your change DOES touch a synced path, land the fix upstream first:

- vesl-core changes  → https://github.com/zkvesl/vesl-core
- vesl-wallet changes → https://github.com/zkvesl/vesl-wallet

After upstream merge, a maintainer bumps the corresponding pin
(VESL_CORE_PIN / VESL_WALLET_PIN) in sync.sh and re-runs ./sync.sh
to propagate. The pr-synced-path-warning CI job will comment if any
synced paths are touched here.

The sync-verify CI job is the hard gate; this comment is a heads-up.

First-time contributor? See CONTRIBUTING.md's "Good first PRs"
table — adding a lint, HTTP handler, or codegen target is now a
template-shaped change.
-->

## Summary

<!-- One or two sentences on what changed and why. -->

## Test plan

<!-- How did you verify the change? cargo test? dogfood scaffold?
     curl smoke? Reference the relevant command + expected output. -->
