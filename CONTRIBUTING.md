# Contributing to vesl-nockup

vesl-nockup is the user-facing toolchain for building NockApps:
`graft-inject` composer, `vesl-test` lifecycle harness, `vesl-hull`
HTTP API, plus a stack of templates. We welcome external PRs.
This doc names what's safe to edit, how to run the suite, and where
to look first if you want a small win on your way in.

PRs land against the `dev` branch — `main` is squash-merged from
`dev` on release days. Branch off `origin/dev`, push to your fork,
open the PR against `zkvesl/vesl-nockup:dev`.

## Good first PRs

Several subsystems are laid out as template-shaped contribution
surfaces — adding a new entry follows the pattern of an existing
sibling, so you don't need to read the whole subsystem first.

| Add a... | Open this directory | Pattern |
|---|---|---|
| **Lint pass** | `tools/graft-inject/src/lint/` | Copy `bare_tilde.rs` (~200 lines, self-contained), wire it into `mod.rs`, and add a `default_severity_table` entry. The 6 existing lints sit side by side as templates. |
| **HTTP handler** | `crates/vesl-hull/src/api/handlers/` | Copy `health.rs` (10 lines) or `status.rs` (~25 lines), expose with `pub(in crate::api)`, add a route line in `api/mod.rs`'s `stock_routes()`. Auth + body-limit + rate-limit + RBAC are inherited from the layer stack. |
| **Codegen target** | `tools/graft-inject/src/codegen/` | Copy `kernel_cause_tags.rs` as a template; new entry point goes in `codegen/mod.rs`'s re-exports. |
| **Template** | `templates/` | Add a sibling dir to `templates/vesl/`. CI's `templates-check` job runs `cargo check` on every template; opt out via `# ci: skip-template-check` in `Cargo.toml` if your template needs Jinja substitution. |
| **vesl-test inspector mode** | `test/vesl-test/src/` | The `inspect` and `watch` subcommands are clap dispatches over `peek` + effect-stream filters. Add a sibling subcommand by extending the clap enum and wiring a driver fn. |

Open a draft PR early if you want a sanity check on the approach
before writing it out — we'd rather you not waste time on a wrong
shape.

## Running tests

```bash
# Full workspace test suite — incremental ~5s warm; cold (first build
# after fresh clone) takes 8-12 minutes because the nockchain sibling
# crates compile in.
cargo test --workspace

# Lint-policy gates that CI enforces. Run this before pushing; it's
# the same invocation CI's `clippy` job runs.
cargo clippy --workspace --all-targets -- -D warnings

# Verify the synced bundle still matches what sync.sh would produce.
# CI's `sync-verify` job runs the same check; running it locally
# catches the failure before you push.
./sync.sh --verify

# Spot-check a single template profile end-to-end (graft-inject
# compose + cargo check). CI runs all five profiles (A B F G J);
# locally you can run one at a time.
./tools/spot-check.sh A
```

If you're only touching `tools/graft-inject/`, the per-crate test
loop is much faster than the full workspace:

```bash
cargo test -p graft-inject --lib    # 123 unit tests, <1s warm
cargo test -p vesl-hull --lib       # 37 unit tests, <1s warm
```

## CI and getting reviewed

PRs run six jobs (visible at the bottom of the PR conversation):

- **check-pins** — confirms `NOCK_PIN` / `VESL_CORE_PIN` /
  `VESL_WALLET_PIN` agree across `sync.sh`, `ci.yml`, and that the
  SHAs exist upstream. Sub-second; fails on ghost SHAs.
- **sync-verify** — runs `./sync.sh --verify` against the pinned
  upstreams. Fails on any hand-edit to synced paths.
- **test** — `cargo test --workspace` against the pinned nockchain
  sibling.
- **clippy** — `cargo clippy --workspace --all-targets -- -D warnings`.
- **templates-check** — `cargo check` per template directory.
- **graft-inject-check** + **spot-check-path-independence** — install
  the binary from your branch and run the spot-check matrix.
- **e2e-init-simulation** — `nockup project init` against a file://
  registry fixture, verifies the three extension hooks compose.

A clean run shows green checks across every job in <15 min. A red
job's "Details" link goes straight to the failing step's logs.
Re-run a flaky job from the PR page if needed; persistent failures
get triaged.

**Reviewer routing.** Tag `@zkvesl` on the PR or in your description
if it sits open more than a day; we triage from there.

For PRs touching `tools/graft-inject/` internals (the composer, lint
engine, codegen), expect a closer review — these surfaces ship in
the binary every user runs.

## Before you edit

vesl-nockup bundles synced code from two upstreams alongside its own
canonical surfaces. Some paths here are owned by **vesl-core** or
**vesl-wallet** — they get refreshed by `./sync.sh` and any local
edits are reverted on the next sync. Other paths are vesl-nockup's
own canonical surface and can be edited in place.

Check the table below before opening a PR. If your fix lives in a
synced path, land it upstream first.

CI's `sync-verify` job will block any PR with hand-edits to synced
paths, but learning that after CI runs wastes your turnaround.

## Where does each path live canonically?

| Path | Canonical repo | Edit here? | Notes |
|---|---|---|---|
| `crates/vesl-core/` | vesl-core | no | Rust SDK (Mint/Guard/Settle/Forge facades, poke builders) |
| `crates/vesl-checkpoint/` | vesl-core | no | Checkpoint trait surface |
| `crates/nock-noun-rs/` | vesl-core | no | Rust → Nock noun helpers |
| `crates/nockchain-tip5-rs/` | vesl-core | no | tip5 Merkle math |
| `crates/nockchain-client-rs/` | vesl-core | no | Chain RPC client |
| `crates/vesl-hull/` | **vesl-nockup** | **yes** | HTTP API hull (factored from vesl-core) |
| `crates/vesl-signing/` | vesl-wallet | no | Schnorr/Tip5/SIWN primitives |
| `crates/vesl-wallet/` | vesl-wallet | no | HD wallet API |
| `crates/vesl-wallet-spec/` | vesl-wallet | no | BIP-44 layout |
| `hoon/` | vesl-core | no | Kernels, grafts, math, common libs |
| `templates/vesl/` | **vesl-nockup** | **yes** | Demo+Serve scaffold |
| `templates/app.hoon` | **vesl-nockup** | **yes** | Canonical scaffold marker reference |
| `templates/<other>/` | vesl-core | no | 8 sibling templates (counter, data-registry, graft-*, settle-report) |
| `templates/{GRAFTING,README,WALLET_CONFIG}.md` | vesl-core | no | Template docs |
| `tools/graft-inject/` | **vesl-nockup** | **yes** | Graft composer (no upstream) |
| `tools/spot-check.sh`, `tools/test-registry/` | **vesl-nockup** | **yes** | Scaffolder smoke tooling |
| `test/vesl-test/` | **vesl-nockup** | **yes** | Lifecycle harness |
| `docs/graft-manifest.md` | vesl-core | no | Synced doc |
| Repo infrastructure (`README.md`, `Cargo.toml`, `Makefile`, `sync.sh`, `.github/`, `.gitignore`) | **vesl-nockup** | **yes** | — |
| `.sync-pins.toml` | (generated) | no | Regenerated by `sync.sh` on every run |
| `.dev/` | (local-only) | n/a | Gitignored personal workspace |

## Edit discipline

**Editing a canonical-here path.** Open a PR against `vesl-nockup`.
Standard review.

**Editing a synced path.** Open the PR against the upstream first:

- vesl-core changes → [`zkvesl/vesl-core`](https://github.com/zkvesl/vesl-core)
- vesl-wallet changes → [`zkvesl/vesl-wallet`](https://github.com/zkvesl/vesl-wallet)

Once merged upstream, a vesl-nockup maintainer bumps the
corresponding `VESL_CORE_PIN` or `VESL_WALLET_PIN` at the top of
`sync.sh` and re-runs `./sync.sh`. The bundled copy here moves
forward in a single follow-up commit.

**If your PR touches a synced path, CI will fail.** The
`sync-verify` job recomputes what `sync.sh` would produce against
the pinned upstream revs and diffs against your branch. Hand-edits
register as drift and the job exits non-zero. The
`pr-synced-path-warning` job posts an early comment when this
happens so you don't have to wait for the full CI run.

**If you need to override sync behavior** (e.g., a vesl-nockup-only
patch on a file that lives in a synced subtree), that's a `sync.sh`
change, not a hand-edit. Either:

- Add the file to the kept-canonical carve-out near the end of
  `sync.sh` (search for "kept-canonical files"), or
- Add a post-sync rewrite step (see the `graft-inject` →
  `nockup-graft` `sed` for the existing pattern).

## Useful commands

```bash
# Refresh the bundle from sibling checkouts. Defaults to
# ~/projects/nockchain/{vesl-core,vesl-wallet}; pass paths to override.
./sync.sh
./sync.sh /path/to/vesl-core /path/to/vesl-wallet

# Dry-run; exits non-zero on drift between the committed bundle and
# what sync.sh would produce. CI's sync-verify job runs this.
./sync.sh --verify

# Override the pin tripwire for a one-off sync against a non-pinned rev.
VESL_CORE_PIN=<sha>   ./sync.sh
VESL_WALLET_PIN=<sha> ./sync.sh
```

## Three-repo overview

- **vesl-core** ([`github.com/zkvesl/vesl-core`](https://github.com/zkvesl/vesl-core)) —
  Hoon kernels, pre-built JAMs, Rust SDK, fakenet harness.
  Source-of-truth for the protocol.
- **vesl-wallet** ([`github.com/zkvesl/vesl-wallet`](https://github.com/zkvesl/vesl-wallet)) —
  signing primitives (`vesl-signing`), HD wallet (`vesl-wallet`),
  BIP-44 spec (`vesl-wallet-spec`). Independent release cycle;
  crates are `cargo add`-able by external consumers.
- **vesl-nockup** ([`github.com/zkvesl/vesl-nockup`](https://github.com/zkvesl/vesl-nockup)) —
  user-facing scaffolder: `graft-inject` composer, `vesl-test`
  lifecycle harness, `vesl-hull` HTTP API, the `vesl` template,
  dogfood tooling. Where users land.

The relationship is uniformly downstream-pull: vesl-nockup ←
vesl-core, vesl-nockup ← vesl-wallet. Pin discipline (`sync.sh` +
`.sync-pins.toml` + CI env vars) keeps the bundle deterministic.
