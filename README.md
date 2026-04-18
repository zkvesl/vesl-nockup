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

1. **`Cargo.toml`** — the scaffolded nockchain deps carry empty git revisions (`rev = ""`). Replace them with path deps (or pinned revs). As of Phase 6.5b the `vesl-core` / `nock-noun-rs` crates live in the main `vesl` repo, not `vesl-nockup`; point the project at them there. For a local dev checkout of the nockchain monorepo, replace the whole `[dependencies]` section and add a `[patch]` block so vesl-core's transitive git deps resolve to the same checkout:

   ```toml
   [dependencies]
   nockapp       = { path = "../../nockchain/crates/nockapp", default-features = false }
   nockvm        = { path = "../../nockchain/crates/nockvm/rust/nockvm" }
   nockvm_macros = { path = "../../nockchain/crates/nockvm/rust/nockvm_macros" }

   vesl-core    = { path = "../../vesl/crates/vesl-core" }
   nock-noun-rs = { path = "../../vesl/crates/nock-noun-rs" }

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

   Adjust `../../` to wherever your `nockchain` and `vesl` checkouts live relative to the project. If `nockup package add` resolves `zkvesl/vesl-graft` for you (Step 2 below), the two `vesl-core` / `nock-noun-rs` lines will be written for you — leave them out of this block. Everything else stays.

2. **`build.rs`** — the scaffold invokes a `hoonc --output <path>` flag that doesn't exist. Vesl compiles `out.jam` via `hoonc` in Step 4 directly, so collapse `build.rs` to a no-op:

   ```rust
   fn main() {
       println!("cargo:rerun-if-changed=out.jam");
   }
   ```

3. **`src/main.rs`** — the scaffold wraps the CLI in `Some(cli)` and imports a handful of unused symbols. Step 6 below replaces this file wholesale, so you can leave it alone for now — just know that the driver template here is the one that compiles.

## Step 2 — install the vesl graft packages

```bash
nockup package add zkvesl/vesl-graft -v latest
```

(`-v latest` is required; nockup refuses a bare `add` without a version spec.)

The `zkvesl/vesl-graft` package ships four composable primitives:

| Graft | Priority | What it does |
|---|---|---|
| `vesl-graft`  | 10 | Register/verify/settle notes against a Merkle root, with replay protection and epoch rotation. |
| `mint-graft`  | 20 | Commit a Merkle root to a `hull=@` trellis cell. Append-only. |
| `guard-graft` | 30 | Register a root per hull, check leaves against it. Soft verify (ok=%.y/%.n). |
| `forge-graft` | 40 | STARK-prove a Nock computation over jammed data, bound to a hull + note-id. |

Each graft ships its own `<name>-graft.hoon` library and a sibling `<name>-graft.toml` manifest that `graft-inject` consumes in Step 3. Install gives you all four by default; Step 3 picks which ones compose into your kernel.

When the package resolves, `nockup package add` records the dep in `nockapp.toml` and installs on the next `nockup project init` / `nockup package install` — run from the **parent** of the project dir, not from inside (`nockup package install` walks `./<package-name>/` and will error `Project directory '<package-name>' not found. Run nockup project init first.` if you run it from within the project). A successful install drops eight Hoon files into `hoon/lib/` (the four `<name>-graft.hoon` libraries and their `.toml` manifests), plus `vesl-merkle.hoon` and — for forge — `vesl-prover.hoon` / `vesl-lower.hoon`. The tip5 hash tree lands in `hoon/common/` (`zeke.hoon`, `ztd/*.hoon`); forge additionally pulls in the STARK prover tree (`common/v2/`, `common/stark/`, `common/nock-common/`, `dat/softed-constraints.hoon`, and the pre-jammed constraint tables in `jams/`). Nothing touches your Rust `src/` or `hoon/app/app.hoon`. Confirm with `ls hoon/lib/vesl-graft.hoon hoon/lib/mint-graft.toml` — nockup silently skips dependencies it can't resolve, so the absence of a warning does not mean it succeeded.

Then copy the marker template over the scaffolded (and markerless) `app.hoon`:

```bash
cp <path-to-vesl-nockup>/templates/app.hoon hoon/app/app.hoon
```

The nockup `basic` template's `app.hoon` does not contain the five `::  nockup:*` markers that `graft-inject` wires against. `templates/app.hoon` is the same minimal kernel with the markers pre-placed at the correct structural points.

### If the registry hasn't resolved `zkvesl/vesl-graft` yet

Until the package lands in nockup's resolver, mirror what `package add` would have done by copying directly out of your local `vesl-nockup` checkout. (Skip `nockup package add` / `package install` entirely — they won't resolve, and `install` will error from inside the project dir anyway.)

```bash
# Always-required libs + the vesl graft.
cp <vesl-nockup>/hoon/lib/vesl-graft.hoon   hoon/lib/
cp <vesl-nockup>/hoon/lib/vesl-graft.toml   hoon/lib/
cp <vesl-nockup>/hoon/lib/vesl-merkle.hoon  hoon/lib/
cp <vesl-nockup>/hoon/common/zeke.hoon      hoon/common/
mkdir -p hoon/common/ztd
cp <vesl-nockup>/hoon/common/ztd/*.hoon     hoon/common/ztd/

# Optional: pick any subset of the other three primitives.
cp <vesl-nockup>/hoon/lib/mint-graft.{hoon,toml}   hoon/lib/
cp <vesl-nockup>/hoon/lib/guard-graft.{hoon,toml}  hoon/lib/

# Forge requires the STARK prover tree — copy the lot or skip it.
cp <vesl-nockup>/hoon/lib/forge-graft.{hoon,toml}  hoon/lib/
cp <vesl-nockup>/hoon/lib/vesl-prover.hoon         hoon/lib/
cp <vesl-nockup>/hoon/lib/vesl-lower.hoon          hoon/lib/
cp -r <vesl-nockup>/hoon/common/v2                 hoon/common/
cp -r <vesl-nockup>/hoon/common/stark              hoon/common/
cp -r <vesl-nockup>/hoon/common/nock-common.hoon   hoon/common/
cp -r <vesl-nockup>/hoon/dat                       hoon/
cp -r <vesl-nockup>/hoon/jams                      hoon/
```

The two `vesl-core` / `nock-noun-rs` Rust deps are already in your `Cargo.toml` from Step 1's fixup — nothing to add here. Proceed to the marker copy above.

## Step 3 — wire the kernel

```bash
graft-inject hoon/app/app.hoon
```

The `app.hoon` you copied in Step 2 has five `::  nockup:*` marker comments at fixed structural points. `graft-inject` discovers every `<name>-graft.toml` under `hoon/lib/`, composes their per-marker blocks, and writes them into your kernel — imports, state fields, cause-union branches, `?-` poke arms, and a chained peek dispatcher. About 80 lines per graft, written for you. The tool is idempotent — run it twice and it skips anything already wired.

Bare invocation auto-discovers every installed graft. Selective composition:

```bash
graft-inject --list                                          # see what's available
graft-inject --grafts vesl-graft,mint-graft hoon/app/app.hoon  # explicit subset
graft-inject --exclude forge-graft hoon/app/app.hoon           # everything but forge
graft-inject --dry-run hoon/app/app.hoon                     # preview; don't write
```

Expected output for an all-four compose:

```
graft-inject: hoon/app/app.hoon
  vesl-graft:  injected 5/5 (imports, state, cause, poke, peek)
  mint-graft:  injected 5/5 (imports, state, cause, poke, peek)
  guard-graft: injected 5/5 (imports, state, cause, poke, peek)
  forge-graft: injected 3/3 (imports, cause, poke)
  markers present: 5 (imports, state, cause, poke, peek)
```

`forge-graft` ships three blocks (no state, no peek — forge is stateless). The denominator is per-graft: each graft reports against the blocks *it* declares, not a fixed 5.

The arms `graft-inject` installs for the vesl graft use a default hash-comparison gate: the kernel tip5-hashes the raw payload and checks it against the registered root. That's enough to verify single-leaf commitments. For anything richer — Merkle manifests, signatures, ZK proofs — see *Customizing* below.

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

### mint / guard / forge: the other three primitives

If your `graft-inject` call composed more than just `vesl-graft`, `vesl-core` also exports builders for the other primitives. All take the same shape — primitives in, `NounSlab` out:

```rust
use vesl_core::{
    build_mint_commit_poke,       // mint-graft
    build_guard_register_poke,    // guard-graft
    build_guard_check_poke,       //   "
    build_forge_prove_poke,       // forge-graft
};

// Commit a Merkle root under hull=7 on the mint trellis.
poke(&mut app, build_mint_commit_poke(7, &root)).await?;

// Register the same hull/root on guard, then check a leaf.
poke(&mut app, build_guard_register_poke(7, &root)).await?;
poke(&mut app, build_guard_check_poke(7, b"leaf data")).await?;
// → %guard-checked ok=%.y if leaf hashes to the registered root,
//   ok=%.n if it doesn't, %guard-error if hull 7 isn't registered.
```

Mint is **append-only** — a second `build_mint_commit_poke(7, ...)` on the same hull emits `%mint-error`. Guard's check is **soft** on the hash (emits `%guard-checked` either way) but **hard** on registration (unregistered hull → `%guard-error`). The unified `hull=@` key means the same integer addresses the same logical cell across settle/mint/guard — you pick when to propagate (nothing auto-bridges).

### Forge: proving a Nock computation

Forge is the one primitive that produces a STARK, and the one with the heaviest compile (the prover tree adds ~16MB of pre-jammed constraint tables to your kernel). Whether to include it is a deployment decision — skip it via `graft-inject --exclude forge-graft` if you don't need proofs.

```rust
use vesl_core::build_forge_prove_poke;

// Prove a 64-increment Nock computation over `data`, bound to
// hull=7 and note-id=101 via the Fiat-Shamir transcript.
let slab = build_forge_prove_poke(7, 101, b"data to prove");
poke(&mut app, slab).await?;
// → %forge-proved (proof=@) on success,
//   %forge-error (msg=@t) if the prover crashed.
```

Cost: 5–40 s per proof on a modern CPU, dominated by FRI commitments. The kernel's `%forge-prove` arm wraps `prove-computation` in a `mule` so a prover crash won't kill the host kernel — it surfaces as `%forge-error`. Pair forge with mint/guard if you want the proof *and* a commitment trellis; forge itself is stateless (no state block, no peek surface).

The STARK verifier lives on the Rust side; see `vesl-core`'s forge module for the `verify` entry point. Cross-VM prove→verify is the real test — run it once per deployment, then let the kernel handle the per-request proving.

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

**`graft-inject` errors with `unknown graft: <name>`**
`--grafts <csv>` names a graft whose `.toml` isn't in `--lib-dir`. Check `graft-inject --list` to see what's installed. Auto-discovery (bare invocation) won't produce this error — it just picks what's there.

**`hoonc` exits 0 but no `out.jam`**
Type error in the kernel. Most common cause: your `effect` type is narrower than the union the grafted arms produce. Use `+$  effect  *` unless you've explicitly constrained it.

**`hoonc` fails with `mint-lost` / `-lost %<tag>` on a multi-graft compose**
The composed `?-` over `-.u.act` isn't exhaustive. Usually this means one of the graft manifests is stale — re-install the vesl graft package (or re-run `sync.sh` in a dev checkout) to pick up the latest arm set. H-01 added `%vesl-rotate-epoch` and pre-H-01 manifests will trip this.

**`hoonc` fails with `missing dependency /jams/constraints-0-1.jam`**
Forge-graft pulls in the STARK prover tree, which depends on pre-jammed constraint tables. Copy `hoon/dat/` and `hoon/jams/` from `vesl-nockup/` into your project, or skip forge via `graft-inject --exclude forge-graft`.

**`cargo build` fails on `ibig` with "expected `UBig`, found `ibig::ubig::UBig`"**
You pulled `ibig` from crates.io instead of the nockchain fork. Vesl-core pins the nockchain fork — if you've added your own `ibig` dep, remove it.

**`Number is greater than DIRECT_MAX` panic**
A `u64` you're feeding into `D()` has its top bit set. Use `nock_noun_rs::atom_from_u64(alloc, value)` instead of `D(value)` for hashed IDs. All vesl-core pokes already route hull-ids through `atom_from_u64` internally.

**`%vesl-settle` returns no effects, stderr shows `DETERMINISTIC error mote=Exit`**
The verify-gate returned `%.n`. The `?>` at `lib/vesl-graft.hoon:132` crashes on gate failure by design — a rejected payload must remain an unprovable STARK state rather than an emitted error. From the Rust side, `app.poke(...).await` resolves `Ok(effects)` with `effects.len() == 0`; treat that as a gate rejection and inspect stderr for the trace. The most common cause is committing multiple leaves with the default single-leaf hash-gate (see Step 6's *Why a single-leaf commit?* note).

**Peek returns `~` on what looks like a valid path**
Vesl-graft's peek paths are **namespaced**: `[%vesl-registered hull ~]`, `[%vesl-settled note-id ~]`, `[%vesl-root hull ~]`, `[%vesl-epoch ~]`, `[%settle-count ~]`. The unprefixed `%registered` / `%settled` / `%root` / `%epoch` forms (pre-Phase-10) are retired. Rust callers going through `vesl-core` are unaffected — the builders don't construct peek paths, they construct pokes.

## Reference

- Marker source-of-truth: `tools/graft-inject/src/main.rs`
- Manifest schema: `<vesl>/docs/graft-manifest.md`
- Hoon grafts + manifests: `hoon/lib/{vesl,mint,guard,forge}-graft.{hoon,toml}`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- STARK prover / lower (forge deps): `hoon/lib/vesl-prover.hoon`, `hoon/lib/vesl-lower.hoon`
- Rust SDK (upstream, consumed as a dep): `<vesl>/crates/vesl-core/src/`
  - Poke builders: `graft_pokes/{settle,mint,guard,forge}.rs`
- Test harness: `test/vesl-test/src/lib.rs`
- Integration tests: `tools/graft-inject/tests/{mint_lifecycle,guard_lifecycle,forge_compile,integration}.rs`
- Test scaffolding: `tools/graft-inject/tests/fixtures/mod.rs`
