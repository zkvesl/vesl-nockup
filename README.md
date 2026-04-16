# vesl-nockup

Vesl packaged for the nockup ecosystem. If you're building a NockApp with `nockup` and want to graft Vesl's verification primitives onto your kernel — without cloning the whole Vesl monorepo — this is the repo.

## Why this exists

The main [vesl](https://github.com/zkVesl/vesl) repo uses relative paths to a sibling `nockchain` clone (`../../../nockchain/crates/...`). That layout works for Docker and in-repo dev but breaks the moment you try to consume the crates from a standalone nockup project. Along the way, Dogfood Round 2 also found that the bare nockup scaffold has broken defaults (empty git revs, wrong `build.rs` syntax, stale `boot::setup` signature) and that grafting Vesl onto a scaffold requires roughly 80 lines of mechanical Hoon wiring.

This repo fixes all of that:

- **Crates** with git deps on `github.com/nockchain/nockchain` instead of relative paths. `cargo build` works from a clean clone — no sibling repos required.
- **Hoon libraries** bundled so `hoonc` doesn't need `$NOCK_HOME`.
- **`graft-inject`** — a CLI that reads your `app.hoon`, finds marker comments, and injects all vesl wiring (imports, state, cause, poke delegations, peek fallthrough).
- **`vesl-test`** — a Rust harness that boots your grafted kernel and runs a standard lifecycle suite (register, verify, settle, replay, root mismatch, unregistered hull).

Docker users: you probably want the main [vesl](https://github.com/zkVesl/vesl) repo. This one is for nockup.

## Quick start

```bash
# scaffold a new NockApp
mkdir my-app && cd my-app
cat > my-app.toml <<'TOML'
[package]
name = "my-app"
version = "0.1.0"
description = "grafted NockApp"
template = "basic"
TOML
nockup project init

# pull in vesl graft libraries (Hoon)
nockup package add zkvesl/vesl-graft

# copy the marker-annotated app.hoon from templates/ and auto-wire:
cp /path/to/vesl-nockup/templates/app.hoon hoon/app/app.hoon
graft-inject hoon/app/app.hoon

# add Rust crates to Cargo.toml manually (nockup doesn't manage Rust deps):
#   vesl-core          = { git = "https://github.com/zkVesl/vesl-nockup" }
#   nock-noun-rs       = { git = "https://github.com/zkVesl/vesl-nockup" }
#   nockchain-tip5-rs  = { git = "https://github.com/zkVesl/vesl-nockup" }

hoonc --new hoon/app/app.hoon hoon/
cargo +nightly build
```

## What `graft-inject` does

Given an `app.hoon` with marker comments:

```hoon
/+  lib
::  nockup:imports
/=  *  /common/wrapper
```

It finds each `::  nockup:<name>` marker, inserts the corresponding Hoon block, and writes the file back. Markers used:

| Marker | What gets inserted |
|--------|--------------------|
| `::  nockup:imports` | `/+  *vesl-graft` and `/+  *vesl-merkle` |
| `::  nockup:state` | `vesl=vesl-state` (grafted into `$:` state fragment) |
| `::  nockup:cause` | `vesl-cause` (unioned into `$%` cause) |
| `::  nockup:poke` | Three `?-` arms — `%vesl-register`, `%vesl-verify`, `%vesl-settle` — each with a default hash-comparison gate |
| `::  nockup:peek` | `(vesl-peek vesl.state path)` replacing a bare `~` fallthrough |

The tool is **idempotent**. If the wiring is already present, it logs `skipped` and leaves the file alone. Safe to run in a CI loop, safe to run after editing.

If a marker is missing, it warns and continues. If all five are missing, it errors — you probably pointed it at the wrong file.

`templates/app.hoon` is a pre-annotated scaffold you can drop into `hoon/app/app.hoon` in a fresh `nockup project init`. It's the bare nockup basic template with the five markers added at the right places.

## What `vesl-test` does

```rust
use vesl_test::GraftTestHarness;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut h = GraftTestHarness::boot("out.jam").await?;
    let report = h.run_standard_suite().await;
    println!("{}", report.summary());
    if !report.is_success() {
        for (name, reason) in &report.failed {
            eprintln!("  FAIL {name}: {reason}");
        }
        std::process::exit(1);
    }
    Ok(())
}
```

The standard suite exercises:

1. `%vesl-register` returns `%vesl-registered`
2. Duplicate register (same hull) returns `%vesl-error`
3. `%vesl-verify` returns `%vesl-verified`
4. `%vesl-settle` returns `%vesl-settled`
5. Replay settle (same note-id) returns `%vesl-error`
6. Unregistered hull returns `%vesl-error`
7. Root mismatch returns `%vesl-error`

Also exposes `build_register_poke`, `build_payload_poke`, `jam_graft_payload` so you can build pokes without booting the harness.

## Repository layout

```
crates/
  vesl-core/              Mint / Guard / Settle / Forge SDK
  nock-noun-rs/           Ergonomic noun construction for Rust drivers
  nockchain-tip5-rs/      Standalone tip5 Merkle tree
  nockchain-client-rs/    gRPC chain/wallet client
hoon/
  lib/vesl-graft.hoon     state + poke dispatcher
  lib/vesl-merkle.hoon    Merkle primitives (tip5)
  lib/lib.hoon            stub — nockup's basic template imports this
  common/zeke.hoon        tip5 entry
  common/wrapper.hoon     kernel lifecycle wrapper
  common/ztd/             tip5 math tables (8 files)
templates/
  app.hoon                marker-annotated scaffold — start here
tools/
  graft-inject/           Rust binary — kernel auto-wiring
test/
  vesl-test/              Rust harness — standard lifecycle suite
hoon.toml                 nockup package manifest (Hoon only)
Cargo.toml                Rust workspace
sync.sh                   copy+rewrite from zkVesl/vesl
```

## CI sync

`sync.sh` is a one-way copy from `zkVesl/vesl` (monorepo) to `zkVesl/vesl-nockup`. It handles Cargo.toml path → git dep rewriting via `sed`. Run it manually on release day:

```bash
./sync.sh ~/projects/nockchain/vesl
git diff
git add -A && git commit -m "sync from vesl"
```

No scheduler. No GitHub Action. Humans run it when there's a release.

## The nockup manifest caveats

nockup's `HoonPackage` format (see `nockchain/crates/nockup/src/manifest.rs`) installs Hoon files only — no Rust crate injection, no post-install hooks. That's fine; those steps are the developer's job anyway. The README sequence above reflects reality:

1. `nockup package add` → Hoon files land in your project's `hoon/lib/`
2. You add Rust crates to `Cargo.toml` yourself (or a future helper)
3. You run `graft-inject hoon/app/app.hoon` to wire the kernel

If nockup adds post-install hook support later, step 3 can become automatic.

~
