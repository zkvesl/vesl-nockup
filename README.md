# vesl-nockup

Walkthrough: add vesl verification to a nockup project in 10 minutes.

## Prerequisites

- `hoonc` on your PATH (`cd nockchain && make install-hoonc`)
- `nockchain` on your PATH (`cd nockchain && make install-nockchain`)
- Rust nightly (`rustup toolchain install nightly`)
- `nockup` on your PATH (`cargo install --path nockchain/crates/nockup`)

Check:

```bash
hoonc --version && nockchain --version && cargo +nightly --version && nockup --help >/dev/null
```

## Step 1 — scaffold a nockup project

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

You now have `hoon/app/app.hoon`, `src/main.rs`, `Cargo.toml`, `build.rs`.

## Step 2 — pull in vesl-nockup

Until the nockup package registry ships, clone it next to your project:

```bash
cd ..
git clone https://github.com/zkVesl/vesl-nockup.git
cd my-app
```

## Step 3 — install the Hoon libraries

```bash
cp -r ../vesl-nockup/hoon/lib/vesl-graft.hoon  hoon/lib/
cp -r ../vesl-nockup/hoon/lib/vesl-merkle.hoon hoon/lib/
cp -r ../vesl-nockup/hoon/common/zeke.hoon     hoon/common/
cp -r ../vesl-nockup/hoon/common/wrapper.hoon  hoon/common/    # overwrite nockup's — same file
mkdir -p hoon/common/ztd
cp ../vesl-nockup/hoon/common/ztd/*.hoon hoon/common/ztd/
```

## Step 4 — drop in the marker template and wire the graft

```bash
cp ../vesl-nockup/templates/app.hoon hoon/app/app.hoon
cargo +nightly run --manifest-path ../vesl-nockup/tools/graft-inject/Cargo.toml -- hoon/app/app.hoon
```

Expected:

```
graft-inject: hoon/app/app.hoon
  injected: imports, state, cause, poke, peek (5/5)
```

Running it a second time prints `skipped (already wired): ...` — the tool is idempotent.

What just got inserted:

| Marker | Inserted |
|--------|----------|
| `::  nockup:imports` | `/+  *vesl-graft`, `/+  *vesl-merkle` |
| `::  nockup:state`   | `vesl=vesl-state` inside `versioned-state` |
| `::  nockup:cause`   | `vesl-cause` unioned into your `cause` |
| `::  nockup:poke`    | `%vesl-register`, `%vesl-verify`, `%vesl-settle` arms with a default hash-comparison gate |
| `::  nockup:peek`    | `(vesl-peek vesl.state path)` in the fallthrough |

## Step 5 — compile the kernel

```bash
hoonc --new hoon/app/app.hoon hoon/
```

Produces `out.jam`. If it doesn't, the marker template is expecting `hoon/lib/lib.hoon` — Step 3 copied it, but double-check.

## Step 6 — wire the Rust side

Replace your generated `Cargo.toml` dependencies section:

```toml
[dependencies]
tokio             = { version = "1.32", features = ["rt-multi-thread", "macros"] }
anyhow            = "1.0"

nockapp        = { git = "https://github.com/nockchain/nockchain.git", default-features = false }
nockvm         = { git = "https://github.com/nockchain/nockchain.git" }
nockvm_macros  = { git = "https://github.com/nockchain/nockchain.git" }

vesl-core           = { path = "../vesl-nockup/crates/vesl-core" }
nock-noun-rs        = { path = "../vesl-nockup/crates/nock-noun-rs" }
nockchain-tip5-rs   = { path = "../vesl-nockup/crates/nockchain-tip5-rs" }
```

Replace `build.rs` with a no-op (hoonc ran in Step 5):

```rust
fn main() {}
```

Replace `src/main.rs` with a minimal driver:

```rust
use std::error::Error;
use std::fs;

use nockapp::NockApp;
use nockapp::kernel::boot;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = boot::default_boot_cli(false);
    boot::init_default_tracing(&cli);

    let kernel = fs::read("out.jam")?;
    let mut app: NockApp =
        boot::setup(&kernel, cli, &[], "my-app", None).await?;

    // your app logic here
    let _ = app;
    Ok(())
}
```

Build:

```bash
cargo +nightly build
```

First build resolves `nockchain` as a git dep — expect 2-5 minutes.

## Step 7 — exercise the full lifecycle

Replace `main` with register + settle:

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

    // 1. Commit some data to a Merkle tree
    let items = [b"first" as &[u8], b"second"];
    let mut mint = Mint::new();
    let root: Tip5Hash = mint.commit(&items);

    // 2. Register the root with the kernel under hull_id = 1
    poke(&mut app, build_register(1, &root)).await?;

    // 3. Settle a note that commits to `first`
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

That's it — a grafted NockApp with on-kernel Merkle verification and replay-protected settlement.

## Customizing

### Add your own state fields

In `hoon/app/app.hoon`, the state fragment looks like:

```hoon
+$  versioned-state
  $:  %v1
      ::  nockup:state
      vesl=vesl-state
  ==
```

Add fields after `vesl=vesl-state`:

```hoon
      vesl=vesl-state
      counter=@ud
      items=(map @ @t)
```

Update `++load` and `++poke` to handle the new fields.

### Add your own domain poke

Add the cause in the `$%` cause union:

```hoon
+$  cause
  $%  [%cause ~]
      [%my-action data=@t]
      vesl-cause
  ==
```

Add a `?-` arm in `++poke`:

```hoon
  %my-action
~>  %slog.[0 data.u.act]
[~ state]
```

### Replace the default hash gate

graft-inject installs a gate that tip5-hashes the raw data and compares it to the expected root. That works for single-leaf commitments. For RAG manifests, ZK proofs, or any other domain, replace the gate body inside each `%vesl-*` arm:

```hoon
=/  hash-gate=verify-gate
  |=  [data=* expected-root=@]
  ^-  ?
  (my-custom-verify data expected-root)
```

`verify-gate` is `$-([data=* expected-root=@] ?)`. `data` is whatever you jammed into the `payload` atom; your gate casts it (`;;(manifest data)`, etc.) and returns a loobean.

## Testing with `vesl-test`

Add to `[dev-dependencies]`:

```toml
vesl-test = { path = "../vesl-nockup/test/vesl-test" }
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

The standard suite covers register, duplicate-register, verify, settle, replay, unregistered-hull, and root-mismatch.

Raw pokes through `h.poke_slab(slab)` if you need them.

## Troubleshooting

**`graft-inject` reports `warning — markers not found: imports, state, ...`**
You edited `app.hoon` without the marker comments. Re-copy `templates/app.hoon` or paste the markers back.

**`hoonc` exits 0 but no `out.jam`**
Type error in the kernel. Most common cause: custom effect type narrower than the union grafted arms return. Use `+$  effect  *` (the template default) unless you've explicitly constrained it.

**`cargo build` fails on `ibig` with "expected `UBig`, found `ibig::ubig::UBig`"**
You pulled `ibig` from crates.io instead of the nockchain fork. Make sure vesl-core is on the version in this repo (uses `{ git = "https://github.com/nockchain/nockchain.git", package = "ibig" }`).

**`Number is greater than DIRECT_MAX` panic**
A `u64` you're feeding into `D()` has its top bit set. Use `nock_noun_rs::atom_from_u64(alloc, value)` instead of `D(value)` for hashed IDs.

## Reference

- Marker source-of-truth: `tools/graft-inject/src/main.rs`
- Hoon graft state + dispatcher: `hoon/lib/vesl-graft.hoon`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- Rust SDK: `crates/vesl-core/src/`
- Tip5 tree: `crates/nockchain-tip5-rs/src/`
- Test harness: `test/vesl-test/src/lib.rs`

~
