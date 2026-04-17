# vesl-nockup

Add vesl to a nockup project in 15 minutes.

## Prerequisites

You need `hoonc`, `nockchain`, `nockup`, and Rust nightly on your PATH. All four ship from the [nockchain monorepo](https://github.com/nockchain/nockchain) — follow that repo's install instructions, then:

```bash
hoonc --version && nockchain --version && nockup --help >/dev/null && cargo +nightly --version
```

If those all resolve, you're ready.

## Step 1 — scaffold a project

From whatever directory you want your project to live under, write a `nockapp.toml` describing the package, then let nockup create the project subdir:

```bash
cat > nockapp.toml <<'TOML'
[package]
name = "my-app"
version = "0.1.0"
description = "grafted NockApp"
template = "basic"
TOML

nockup project init
cd my-app
```

`nockup project init` reads `nockapp.toml` from the current directory and creates `my-app/` containing `hoon/app/app.hoon`, `src/main.rs`, `Cargo.toml`, and `build.rs` — the empty nockup scaffold. The filename must be exactly `nockapp.toml`; nockup won't pick it up under any other name.

The nockup `basic` template is generic and needs three one-time fixups before vesl deps will compile. Apply these inside `my-app/`:

1. **`Cargo.toml`** — the scaffolded nockchain deps carry empty git revisions (`rev = ""`). Replace them with path deps (or pinned revs). For a local dev checkout of the nockchain monorepo, replace the whole `[dependencies]` section and add a `[patch]` block so vesl-core's transitive git deps resolve to the same checkout:

   ```toml
   [dependencies]
   nockapp       = { path = "../../nockchain/crates/nockapp", default-features = false }
   nockvm        = { path = "../../nockchain/crates/nockvm/rust/nockvm" }
   nockvm_macros = { path = "../../nockchain/crates/nockvm/rust/nockvm_macros" }

   vesl-core         = { path = "../../vesl-nockup/crates/vesl-core" }
   nock-noun-rs      = { path = "../../vesl-nockup/crates/nock-noun-rs" }
   nockchain-tip5-rs = { path = "../../vesl-nockup/crates/nockchain-tip5-rs" }

   tokio = { version = "1", features = ["rt-multi-thread", "macros"] }

   [patch."https://github.com/nockchain/nockchain.git"]
   nockapp         = { path = "../../nockchain/crates/nockapp" }
   nockvm          = { path = "../../nockchain/crates/nockvm/rust/nockvm" }
   nockvm_macros   = { path = "../../nockchain/crates/nockvm/rust/nockvm_macros" }
   nockchain-math  = { path = "../../nockchain/crates/nockchain-math" }
   nockchain-types = { path = "../../nockchain/crates/nockchain-types" }
   noun-serde      = { path = "../../nockchain/crates/noun-serde" }
   ibig            = { path = "../../nockchain/crates/nockvm/rust/ibig" }
   ```

   Adjust `../../` to wherever your `nockchain` and `vesl-nockup` checkouts live relative to the project. If `nockup package add` resolves `zkvesl/vesl-graft` for you (Step 2 below), the three `vesl-core`/`nock-noun-rs`/`nockchain-tip5-rs` lines will be written for you — leave them out of this block. Everything else stays.

2. **`build.rs`** — the scaffold invokes a `hoonc --output <path>` flag that doesn't exist. Vesl compiles `out.jam` via `hoonc` in Step 4 directly, so collapse `build.rs` to a no-op:

   ```rust
   fn main() {
       println!("cargo:rerun-if-changed=out.jam");
   }
   ```

3. **`src/main.rs`** — the scaffold wraps the CLI in `Some(cli)` and imports a handful of unused symbols. Step 6 below replaces this file wholesale, so you can leave it alone for now — just know that the driver template here is the one that compiles.

## Step 2 — install the vesl graft package

```bash
nockup package add zkvesl/vesl-graft -v latest
```

(`-v latest` is required; nockup refuses a bare `add` without a version spec.)

When the package resolves, `nockup package add` records the dep in `nockapp.toml` and installs on the next `nockup project init` / `nockup package install` — run from the **parent** of the project dir, not from inside (`nockup package install` walks `./<package-name>/` and will error `Project directory '<package-name>' not found. Run nockup project init first.` if you run it from within the project). A successful install drops the Hoon libraries into `hoon/lib/` (`vesl-graft.hoon`, `vesl-merkle.hoon`) and the tip5 hash tree into `hoon/common/` (`zeke.hoon`, `ztd/*.hoon`). It does not touch your Rust `src/` or `hoon/app/app.hoon`. Confirm with `ls hoon/lib/vesl-graft.hoon` — nockup silently skips dependencies it can't resolve, so the absence of a warning does not mean it succeeded.

Then copy the marker template over the scaffolded (and markerless) `app.hoon`:

```bash
cp <path-to-vesl-nockup>/templates/app.hoon hoon/app/app.hoon
```

The nockup `basic` template's `app.hoon` does not contain the five `::  nockup:*` markers that `graft-inject` wires against. `templates/app.hoon` is the same minimal kernel with the markers pre-placed at the correct structural points.

### If the registry hasn't resolved `zkvesl/vesl-graft` yet

Until the package lands in nockup's resolver, mirror what `package add` would have done by copying directly out of your local `vesl-nockup` checkout. (Skip `nockup package add` / `package install` entirely — they won't resolve, and `install` will error from inside the project dir anyway.)

```bash
cp <vesl-nockup>/hoon/lib/vesl-graft.hoon   hoon/lib/
cp <vesl-nockup>/hoon/lib/vesl-merkle.hoon  hoon/lib/
cp <vesl-nockup>/hoon/common/zeke.hoon      hoon/common/
mkdir -p hoon/common/ztd
cp <vesl-nockup>/hoon/common/ztd/*.hoon     hoon/common/ztd/
```

The three `vesl-core` / `nock-noun-rs` / `nockchain-tip5-rs` Rust deps are already in your `Cargo.toml` from Step 1's fixup — nothing to add here. Proceed to the marker copy above.

## Step 3 — wire the kernel

```bash
graft-inject hoon/app/app.hoon
```

The `app.hoon` you copied in Step 2 has five `::  nockup:*` marker comments at fixed structural points. `graft-inject` reads each marker and inserts the Hoon needed to compose vesl into your kernel — imports, a `vesl-state` field, a `vesl-cause` union branch, three `?-` poke arms (`%vesl-register`, `%vesl-verify`, `%vesl-settle`), and a `vesl-peek` fallthrough in your peek handler. About 80 lines of mechanical boilerplate, written for you. The tool is idempotent — run it twice and it skips anything already wired.

Expected output:

```
graft-inject: hoon/app/app.hoon
  injected: imports, state, cause, poke, peek (5/5)
```

The arms `graft-inject` installs use a default hash-comparison gate: the kernel tip5-hashes the raw payload and checks it against the registered root. That's enough to verify single-leaf commitments. For anything richer — Merkle manifests, signatures, ZK proofs — see *Customizing* below.

## Step 4 — compile the kernel

```bash
hoonc hoon/app/app.hoon hoon/
```

Produces `out.jam`, the compiled kernel your Rust driver will boot. (If you're iterating and want to bypass hoonc's cache, add `--new`.)

## Step 5 — build and run

With `Cargo.toml` set up from Step 1 and the vesl crates from Step 2, build the driver:

```bash
cargo +nightly build
```

First build compiles the full nockchain stack — expect 2–5 minutes with path deps (faster on subsequent builds) or longer if the nockchain git deps resolve over the network.

## Step 6 — exercise the full lifecycle

Replace `src/main.rs` with a driver that registers a Merkle root and settles a note against it. The poke construction lives in `vesl-core` — you only write the orchestration:

```rust
use std::error::Error;
use std::fs;

use nockapp::NockApp;
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use vesl_core::{
    Mint, Tip5Hash,
    build_vesl_register_poke, build_vesl_settle_poke,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = boot::default_boot_cli(false);
    boot::init_default_tracing(&cli);
    let kernel = fs::read("out.jam")?;
    let mut app: NockApp = boot::setup(&kernel, cli, &[], "my-app", None).await?;

    // 1. Commit data to a Merkle tree.
    //    Default hash-gate verifies single-leaf commits only; see Customizing
    //    below for multi-leaf / signed / STARK gates.
    let items: [&[u8]; 1] = [b"first"];
    let mut mint = Mint::new();
    let root: Tip5Hash = mint.commit(&items);

    // 2. Register the root under hull_id = 1
    poke(&mut app, build_vesl_register_poke(1, &root)).await?;

    // 3. Settle a note committing to `first` (note_id = 1, hull = 1)
    poke(&mut app, build_vesl_settle_poke(1, 1, &root, items[0])).await?;

    Ok(())
}

async fn poke(app: &mut NockApp, slab: NounSlab) -> Result<(), Box<dyn Error>> {
    let effects = app.poke(SystemWire.to_wire(), slab).await?;
    for e in &effects {
        let n = unsafe { e.root() };
        if let Ok(cell) = n.as_cell() {
            if let Ok(tag) = cell.head().as_atom() {
                let s = std::str::from_utf8(tag.as_ne_bytes())
                    .unwrap_or("?").trim_end_matches('\0');
                println!("  effect: %{s}");
            }
        }
    }
    Ok(())
}
```

```bash
cargo +nightly run
```

Expected output:

```
  effect: %vesl-registered
  effect: %vesl-settled
```

You now have a grafted NockApp with on-kernel Merkle verification and replay-protected settlement.

`vesl-core` also exports `build_vesl_verify_poke(note_id, hull, root, data)` for pure verification (no state transition). All three builders take the same shape: primitives in, ready-to-poke `NounSlab` out.

**Why a single-leaf commit?** The default verification gate that `graft-inject` installs tip5-hashes the raw payload bytes and compares the digest against the registered root. That equality holds only when the committed tree has one leaf (root ≡ `hash-leaf(data)`). The moment you commit two or more leaves, the registered root becomes the Merkle hash of the subtree and the default gate returns `%.n` on settle — which triggers a deterministic crash (see Troubleshooting). For multi-leaf commitments, replace the gate per *Customizing → Replace the default verification gate*.

## Adding vesl to an existing nockup project

If you already have a working nockapp, skip Step 1. The rest applies, with one extra step: you have an `app.hoon` already — you need to *annotate* it with markers rather than copy the template over it.

1. `nockup package add zkvesl/vesl-graft -v latest && nockup package install` — same as Step 2 above.
2. **Annotate your existing `app.hoon` with the five `::  nockup:*` markers.** `graft-inject` looks for exact marker comments at specific structural points:
   - `::  nockup:imports` — at the top of the file, near your other `/+` imports
   - `::  nockup:state` — inside your `versioned-state` `$:` block, above the closing `==`
   - `::  nockup:cause` — inside your `cause` `$%` union, above the closing `==`
   - `::  nockup:poke` — inside your `?-` poke switch, as the last item before `==`
   - `::  nockup:peek` — inside your peek handler's `?+` default arm (or on the line above a bare `~` fallthrough)

   See `templates/app.hoon` for a reference placement. Two-space law applies — `::` followed by exactly two spaces, then `nockup:<name>`.
3. `graft-inject hoon/app/app.hoon` — same as Step 3 above. Safe to run against a populated kernel; it only edits marker lines.
4. Recompile (`hoonc hoon/app/app.hoon hoon/`) and rebuild (`cargo +nightly build`).
5. Call `vesl_core::build_vesl_register_poke`, `build_vesl_settle_poke`, `build_vesl_verify_poke` from your existing `main.rs` alongside your domain pokes. No rewrite needed.

If `graft-inject` reports `warning — markers not found: ...`, you missed a marker or a two-space law violation. The tool is pure text — it does what the regex says.

## Customizing

The grafted kernel is opinionated: default hash gate, single hull namespace, hardcoded state layout. Every app needs to override at least one of these.

### Add your own state fields

Your app almost certainly has state beyond vesl's commitment tracking — counters, maps, user records, pending jobs. Add them after `vesl=vesl-state` in `versioned-state`:

```hoon
+$  versioned-state
  $:  %v1
      vesl=vesl-state
      counter=@ud
      items=(map @ @t)
  ==
```

Any new field needs handling in `++load` (migration from older state versions) and `++poke` (the arms that read or write it).

### Add your own domain pokes

Vesl handles `%vesl-register`, `%vesl-verify`, and `%vesl-settle`. Your app handles everything else — order placement, message sending, whatever your domain is. The minimum per domain command is three blocks of Hoon: one state field (if the command needs state), one cause variant, and one `?-` arm.

Worked example — a **badge issuer** that increments a per-subject counter and emits `%badge-issued`:

```hoon
::  in versioned-state, after `vesl=vesl-state`:
badges=(map @ud @ud)
```

```hoon
::  in the cause $% union, alongside vesl-cause:
[%issue-badge subject=@ud]
```

```hoon
::  inside ?-, alongside the vesl arms:
  %issue-badge
=/  n=@ud  +((~(gut by badges.state) subject.u.act 0))
:_  state(badges (~(put by badges.state) subject.u.act n))
^-  (list effect)
~[[%badge-issued subject.u.act n]]
```

Seven lines of custom Hoon total. Two of those (the state field and the cause variant) are pure type declarations; five are the arm itself. The arm's `:_ state(...)` / `^- (list effect)` / `~[[...]]` shape is NockApp's required `[effects state]` return — the same in any nockapp, graft or no graft.

The vesl arms stay put. You're adding arms, not replacing them.

Future direction: `graft-inject` is being rearchitected (see `.dev/PARAMETIZATION.md`) so that user-defined domains can ship as their own grafts with a TOML manifest — which will mechanize the state-field and cause-variant declarations. The arm body is the part that stays yours.

### Replace the default verification gate

`graft-inject` installs a gate that tip5-hashes the raw payload bytes and checks equality against the registered root. That works for single-leaf commitments (one piece of data → one root). It breaks the moment you have anything richer:

- **Merkle manifests** (like verifiable RAG): payload is a structured manifest with multiple leaves + proofs; the gate walks each proof against the root.
- **Signatures**: payload carries a signature; the gate verifies it against a public key committed in the root.
- **STARK proofs**: payload is a proof; the gate runs the verifier.

Inside each `%vesl-*` arm, replace the gate body:

```hoon
=/  hash-gate=verify-gate
  |=  [data=* expected-root=@]
  ^-  ?
  (my-custom-verify data expected-root)
```

`verify-gate` is `$-([data=* expected-root=@] ?)`. `data` is whatever your Rust side jammed into the `payload` atom; your gate casts it (`;;(manifest data)`, `;;(my-intent data)`, etc.) and returns a loobean. The caller decides what the data shape is — the graft doesn't care.

## Testing with `vesl-test`

Add to `[dev-dependencies]`:

```toml
vesl-test = { git = "https://github.com/zkVesl/vesl-nockup" }
```

Write a lifecycle test:

```rust
use vesl_test::GraftTestHarness;

#[tokio::test]
async fn graft_lifecycle() -> anyhow::Result<()> {
    let mut h = GraftTestHarness::boot("out.jam").await?;
    let report = h.run_standard_suite().await;
    assert!(report.is_success(), "{:?}", report.failed);
    Ok(())
}
```

The standard suite covers register, duplicate-register, verify, settle, replay, unregistered-hull, and root-mismatch. Raw pokes through `h.poke_slab(slab)` if you need them.

## Troubleshooting

**`graft-inject` reports `warning — markers not found: imports, state, ...`**
You edited `app.hoon` without the marker comments, or your spacing is off. Two-space law: `::` followed by exactly two spaces, then `nockup:<name>`.

**`hoonc` exits 0 but no `out.jam`**
Type error in the kernel. Most common cause: your `effect` type is narrower than the union the grafted arms produce. Use `+$  effect  *` unless you've explicitly constrained it.

**`cargo build` fails on `ibig` with "expected `UBig`, found `ibig::ubig::UBig`"**
You pulled `ibig` from crates.io instead of the nockchain fork. Vesl-core pins the nockchain fork — if you've added your own `ibig` dep, remove it.

**`Number is greater than DIRECT_MAX` panic**
A `u64` you're feeding into `D()` has its top bit set. Use `nock_noun_rs::atom_from_u64(alloc, value)` instead of `D(value)` for hashed IDs.

**`%vesl-settle` returns no effects, stderr shows `DETERMINISTIC error mote=Exit`**
The verify-gate returned `%.n`. The `?>` at `lib/vesl-graft.hoon:132` crashes on gate failure by design — a rejected payload must remain an unprovable STARK state rather than an emitted error. From the Rust side, `app.poke(...).await` resolves `Ok(effects)` with `effects.len() == 0`; treat that as a gate rejection and inspect stderr for the trace. The most common cause is committing multiple leaves with the default single-leaf hash-gate (see Step 6's *Why a single-leaf commit?* note).

## Reference

- Marker source-of-truth: `tools/graft-inject/src/main.rs`
- Hoon graft state + dispatcher: `hoon/lib/vesl-graft.hoon`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- Rust SDK: `crates/vesl-core/src/`
- Tip5 tree: `crates/nockchain-tip5-rs/src/`
- Test harness: `test/vesl-test/src/lib.rs`
