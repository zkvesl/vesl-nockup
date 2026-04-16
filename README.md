# vesl-nockup

Add vesl to a nockup project in 15 minutes.

## Prerequisites

You need `hoonc`, `nockchain`, `nockup`, and Rust nightly on your PATH. All four ship from the [nockchain monorepo](https://github.com/nockchain/nockchain) — follow that repo's install instructions, then:

```bash
hoonc --version && nockchain --version && nockup --help >/dev/null && cargo +nightly --version
```

If those all resolve, you're ready.

## Step 1 — scaffold a project

```bash
mkdir my-app && cd my-app

cat > my-app.toml <<'TOML'
[package]
name = "my-app"
version = "0.1.0"
description = "grafted NockApp"
template = "basic"
TOML

nockup project init
```

That gives you `hoon/app/app.hoon`, `src/main.rs`, `Cargo.toml`, and `build.rs` — the empty nockup scaffold.

## Step 2 — install the vesl graft package

```bash
nockup package add zkvesl/vesl-graft
```

This drops the Hoon libraries into `hoon/lib/` (`vesl-graft.hoon`, `vesl-merkle.hoon`) and the tip5 hash tree into `hoon/common/` (`zeke.hoon`, `ztd/*.hoon`). It does not touch your Rust code or `app.hoon`.

## Step 3 — wire the kernel

```bash
graft-inject hoon/app/app.hoon
```

Your `app.hoon` starts with five `::  nockup:*` marker comments at fixed structural points. `graft-inject` reads each marker and inserts the Hoon needed to compose vesl into your kernel — imports, a `vesl-state` field, a `vesl-cause` union branch, three `?-` poke arms (`%vesl-register`, `%vesl-verify`, `%vesl-settle`), and a `vesl-peek` fallthrough in your peek handler. About 80 lines of mechanical boilerplate, written for you. The tool is idempotent — run it twice and it skips anything already wired.

Expected output:

```
graft-inject: hoon/app/app.hoon
  injected: imports, state, cause, poke, peek (5/5)
```

The arms `graft-inject` installs use a default hash-comparison gate: the kernel tip5-hashes the raw payload and checks it against the registered root. That's enough to verify single-leaf commitments. For anything richer — Merkle manifests, signatures, ZK proofs — see *Customizing* below.

## Step 4 — compile the kernel

```bash
hoonc --new hoon/app/app.hoon hoon/
```

Produces `out.jam`, the compiled kernel your Rust driver will boot.

## Step 5 — build and run

`nockup package add` updated your `Cargo.toml` with the vesl Rust deps and gave you a minimal `src/main.rs` that boots `out.jam`. Build:

```bash
cargo +nightly build
```

First build resolves `nockchain` as a git dep — expect 2–5 minutes.

## Step 6 — exercise the full lifecycle

Replace `src/main.rs` with a driver that registers a Merkle root and settles a note against it:

```rust
use std::error::Error;
use std::fs;

use nock_noun_rs::{jam_to_bytes, make_atom_in, make_tag_in, new_stack};
use nockapp::NockApp;
use nockapp::kernel::boot;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nockvm::noun::{D, T};
use vesl_core::{Mint, Tip5Hash, tip5_to_atom_le_bytes};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = boot::default_boot_cli(false);
    boot::init_default_tracing(&cli);
    let kernel = fs::read("out.jam")?;
    let mut app: NockApp = boot::setup(&kernel, cli, &[], "my-app", None).await?;

    // 1. Commit data to a Merkle tree
    let items = [b"first" as &[u8], b"second"];
    let mut mint = Mint::new();
    let root: Tip5Hash = mint.commit(&items);

    // 2. Register the root under hull_id = 1
    poke(&mut app, build_register(1, &root)).await?;

    // 3. Settle a note committing to `first`
    let payload = build_single_leaf_payload(1, 1, &root, items[0]);
    poke(&mut app, build_payload_poke("vesl-settle", &payload)).await?;

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

fn build_register(hull: u64, root: &Tip5Hash) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "vesl-register");
    let root_atom = make_atom_in(&mut slab, &tip5_to_atom_le_bytes(root));
    let poke = T(&mut slab, &[tag, D(hull), root_atom]);
    slab.set_root(poke);
    slab
}

fn build_payload_poke(verb: &str, payload: &[u8]) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, verb);
    let jammed = make_atom_in(&mut slab, payload);
    let poke = T(&mut slab, &[tag, jammed]);
    slab.set_root(poke);
    slab
}

fn build_single_leaf_payload(
    note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8],
) -> Vec<u8> {
    let mut slab: NounSlab = NounSlab::new();
    let rb = tip5_to_atom_le_bytes(root);
    let note_root = make_atom_in(&mut slab, &rb);
    let pending = make_tag_in(&mut slab, "pending");
    let state = T(&mut slab, &[pending, D(0)]);
    let note = T(&mut slab, &[D(note_id), D(hull), note_root, state]);
    let data_atom = make_atom_in(&mut slab, data);
    let exp_root = make_atom_in(&mut slab, &rb);
    let payload = T(&mut slab, &[note, data_atom, exp_root]);
    let mut stack = new_stack();
    jam_to_bytes(&mut stack, payload)
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

## Adding vesl to an existing nockup project

If you already have a working nockapp and want to bolt vesl onto it, Steps 1 and 5 don't apply. The rest do, with one extra step.

1. `nockup package add zkvesl/vesl-graft` — same as above. Adds Hoon libs and Rust deps without touching your `app.hoon`.
2. **Annotate your existing `app.hoon` with the five `::  nockup:*` markers.** `graft-inject` looks for exact marker comments at specific structural points:
   - `::  nockup:imports` — at the top of the file, near your other `/+` imports
   - `::  nockup:state` — inside your `versioned-state` `$:` block, above the closing `==`
   - `::  nockup:cause` — inside your `cause` `$%` union, above the closing `==`
   - `::  nockup:poke` — inside your `?-` poke switch, as the last item before `==`
   - `::  nockup:peek` — inside your peek handler's `?+` default arm (or on the line above a bare `~` fallthrough)

   See `templates/app.hoon` for a reference placement. Two-space law applies — `::` followed by exactly two spaces, then `nockup:<name>`.
3. `graft-inject hoon/app/app.hoon` — same as Step 3 above. Safe to run against a populated kernel; it only edits marker lines.
4. Recompile (`hoonc --new hoon/app/app.hoon hoon/`) and rebuild (`cargo +nightly build`).
5. Call the vesl pokes from your existing `main.rs` using the helpers from Step 6. You don't need to rewrite — just add `build_register`, `build_payload_poke`, and `build_single_leaf_payload` alongside your domain pokes.

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

Vesl handles `%vesl-register`, `%vesl-verify`, and `%vesl-settle`. Your app handles everything else — order placement, message sending, whatever your domain is. Add a cause variant:

```hoon
+$  cause
  $%  [%cause ~]
      [%my-action data=@t]
      vesl-cause
  ==
```

And an arm inside `?-`:

```hoon
  %my-action
~>  %slog.[0 data.u.act]
:_  state(counter +(counter.state))
~[[%my-actioned counter.state]]
```

The vesl arms stay put. You're adding arms, not replacing them.

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

## Reference

- Marker source-of-truth: `tools/graft-inject/src/main.rs`
- Hoon graft state + dispatcher: `hoon/lib/vesl-graft.hoon`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- Rust SDK: `crates/vesl-core/src/`
- Tip5 tree: `crates/nockchain-tip5-rs/src/`
- Test harness: `test/vesl-test/src/lib.rs`
