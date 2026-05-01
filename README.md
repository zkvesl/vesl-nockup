# vesl-nockup

Add vesl to a nockup project in 15 minutes.

## Prerequisites

You need `hoonc`, `nockchain`, `nockup`, and Rust nightly on your PATH. All four ship from the [nockchain monorepo](https://github.com/nockchain/nockchain) — follow that repo's install instructions, then install `graft-inject` from this repo:

```bash
cd tools/graft-inject && cargo install --path .
```

`cargo install --path .` drops the binary in `~/.cargo/bin/`, which is already on the Rust-nightly PATH. Verify the full toolchain:

```bash
hoonc --version && nockchain --version && nockup --help >/dev/null && cargo +nightly --version && graft-inject --version
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

   vesl-core    = { path = "../../vesl-core/crates/vesl-core" }
   nock-noun-rs = { path = "../../vesl-core/crates/nock-noun-rs" }

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

2. **`build.rs`** — Vesl compiles `out.jam` via an explicit `hoonc` call in Step 4, so `build.rs` doesn't need to invoke the compiler (and the scaffolded call wasn't producing a jam consumers could link against). Collapse it to a no-op that just declares the `out.jam` rebuild dependency:

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

The `zkvesl/vesl-graft` package ships the commitment family (family 1 in Vesl's 5-family graft catalog) — four composable primitives in priority band 10–40:

| Graft | Family | Priority | Status | What it does |
|---|---|---|---|---|
| `settle-graft`| 1 (commitment) | 10 | stable | Register/verify/settle notes against a Merkle root, with replay protection and epoch rotation. |
| `mint-graft`  | 1 (commitment) | 20 | stable | Commit a Merkle root to a `hull=@` trellis cell. Append-only. |
| `guard-graft` | 1 (commitment) | 30 | stable | Register a root per hull, check leaves against it. Soft verify (ok=%.y/%.n). |
| `forge-graft` | 1 (commitment) | 40 | stable | STARK-prove a Nock computation over jammed data, bound to a hull + note-id. |
| `intent-graft` | 5 (intent) | 200 | placeholder | Reserved slot for multi-party coordination (declare / match / cancel / expire). Crashes on invocation — swapped when canonical upstream lands. |

Each graft ships its own `<name>-graft.hoon` library and a sibling `<name>-graft.toml` manifest that `graft-inject` consumes in Step 3. Install gives you the shipped commitment family plus the intent-family placeholder; Step 3 picks which ones compose into your kernel. The full 5-family lattice — commitment, verification gates (library, not a graft), state (planned), behavior (planned), intent (placeholder) — lives in [`docs/graft-manifest.md`](docs/graft-manifest.md).

When the package resolves, `nockup package add` records the dep in `nockapp.toml` and installs on the next `nockup project init` / `nockup package install` — run from the **parent** of the project dir, not from inside (`nockup package install` walks `./<package-name>/` and will error `Project directory '<package-name>' not found. Run nockup project init first.` if you run it from within the project). A successful install drops eight Hoon files into `hoon/lib/` (the four `<name>-graft.hoon` libraries and their `.toml` manifests), plus `vesl-merkle.hoon` and — for forge — `vesl-prover.hoon` / `vesl-lower.hoon`. The tip5 hash tree lands in `hoon/common/` (`zeke.hoon`, `ztd/*.hoon`); forge additionally pulls in the STARK prover tree (`common/v0-v1/`, `common/v2/`, `common/stark/`, `dat/softed-constraints.hoon`, and the pre-jammed constraint tables in `jams/`). Nothing touches your Rust `src/` or `hoon/app/app.hoon`.

**Verify the install succeeded.** `nockup package install` silently skips dependencies it can't resolve, so a clean `✓ No dependencies to install` output does not mean vesl landed. Check that the expected graft files are on disk:

```bash
ls hoon/lib/settle-graft.hoon hoon/lib/settle-graft.toml hoon/lib/vesl-merkle.hoon
```

If any of those three paths are missing, the registry did not resolve `zkvesl/vesl-graft` — fall through to *If the registry hasn't resolved* below.

Then copy the marker template over the scaffolded (and markerless) `app.hoon`:

```bash
cp <path-to-vesl-nockup>/templates/app.hoon hoon/app/app.hoon
```

The nockup `basic` template's `app.hoon` does not contain the five `::  nockup:*` markers that `graft-inject` wires against. `templates/app.hoon` is the same minimal kernel with the markers pre-placed at the correct structural points.

### If the registry hasn't resolved `zkvesl/vesl-graft` yet

Until the package lands in nockup's resolver, mirror what `package add` would have done by copying directly out of your local `vesl-nockup` checkout. (Skip `nockup package add` / `package install` entirely — they won't resolve, and `install` will error from inside the project dir anyway.)

```bash
# Always-required libs + the settle graft.
cp <vesl-nockup>/hoon/lib/settle-graft.hoon hoon/lib/
cp <vesl-nockup>/hoon/lib/settle-graft.toml hoon/lib/
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
cp -r <vesl-nockup>/hoon/common/v0-v1              hoon/common/
cp -r <vesl-nockup>/hoon/common/v2                 hoon/common/
cp -r <vesl-nockup>/hoon/common/stark              hoon/common/
cp -r <vesl-nockup>/hoon/dat                       hoon/
cp -r <vesl-nockup>/hoon/jams                      hoon/
```

The two `vesl-core` / `nock-noun-rs` Rust deps are already in your `Cargo.toml` from Step 1's fixup — nothing to add here. Proceed to the marker copy above.

## Step 3 — wire the kernel

```bash
graft-inject hoon/app/app.hoon            # preview
graft-inject --apply hoon/app/app.hoon    # write
```

The `app.hoon` you copied in Step 2 has five `::  nockup:*` marker comments at fixed structural points. `graft-inject` discovers every `<name>-graft.toml` under `hoon/lib/`, composes their per-marker blocks, and prints the result — imports, state fields, cause-union branches, `?-` poke arms, and a chained peek dispatcher. About 80 lines per graft, written for you. The tool is idempotent — re-running after `--apply` skips anything already wired.

**Preview by default.** A bare invocation prints the composed kernel to stdout and a per-manifest sha256 summary to stderr. Nothing is written until you pass `--apply`. This keeps a compromised `hoon/lib/` — pulled by `sync.sh`, a bad `cp`, or a dependency bump — from silently composing hostile Hoon into your kernel source. See `docs/graft-manifest.md` for the trust model.

Selective composition:

```bash
graft-inject --list                                                    # see what's available
graft-inject --grafts settle-graft,mint-graft --apply hoon/app/app.hoon # explicit subset
graft-inject --exclude forge-graft --apply hoon/app/app.hoon            # everything but forge
```

Expected output for an all-four compose (with `--apply`):

```
graft-inject: hoon/app/app.hoon
  settle-graft     sha256:a9c72bbe7dc1 injected 5/5 (imports, state, cause, poke, peek)
  mint-graft       sha256:4b2e...       injected 5/5 (imports, state, cause, poke, peek)
  guard-graft      sha256:c310...       injected 5/5 (imports, state, cause, poke, peek)
  forge-graft      sha256:f721...       injected 3/3 (imports, cause, poke)
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
    build_settle_register_poke, build_settle_note_poke,
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
    poke(&mut app, build_settle_register_poke(1, &root)).await?;

    // 3. Settle a note committing to `first` (note_id = 1, hull = 1)
    poke(&mut app, build_settle_note_poke(1, 1, &root, items[0])).await?;

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
  effect: %settle-registered
  effect: %settle-noted
```

You now have a grafted NockApp with on-kernel Merkle verification and replay-protected settlement.

`vesl-core` also exports `build_settle_verify_poke(note_id, hull, root, data)` for pure verification (no state transition). All three builders take the same shape: primitives in, ready-to-poke `NounSlab` out.

**Why a single-leaf commit?** The default verification gate that `graft-inject` installs tip5-hashes the raw payload bytes and compares the digest against the registered root. That equality holds only when the committed tree has one leaf (root ≡ `hash-leaf(data)`). The moment you commit two or more leaves, the registered root becomes the Merkle hash of the subtree and the default gate returns `%.n` on settle — which triggers a deterministic crash (see Troubleshooting). For multi-leaf commitments, replace the gate per *Customizing → Replace the default verification gate*.

### mint / guard / forge: the other three primitives

If your `graft-inject` call composed more than just `settle-graft`, `vesl-core` also exports builders for the other primitives. All take the same shape — primitives in, `NounSlab` out:

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

### State grafts: app-state primitives without writing Hoon

Beyond the four commitment grafts, `graft-inject` ships off-the-shelf state grafts in the 50–99 priority band so apps don't need to write Hoon for generic app-state. Two grafts have landed so far.

**`kv-graft` (priority 50)** — a loose key-value store keyed on `@t` cords with opaque atom values:

```rust
use vesl_core::{build_kv_set_poke, build_kv_delete_poke};

poke(&mut app, build_kv_set_poke("greeting", b"hello")).await?;
// → %kv-stored key='greeting'

poke(&mut app, build_kv_set_poke("greeting", b"goodbye")).await?;
// Overwrite is allowed (loose semantics). → %kv-stored

poke(&mut app, build_kv_delete_poke("greeting")).await?;
// → %kv-deleted (idempotent — missing keys also emit %kv-deleted)
```

Compose by listing the graft alongside the others: `graft-inject --grafts settle,mint,kv hoon/app/app.hoon`. Peek path is `[%kv-value key=@t]` returning the stored atom or `~`. The store is capped at 10M entries (`%kv-error 'capacity'` on overflow). Overwrite of an existing key bypasses the cap.

`kv-graft` is the *loose* store: overwrite-on-set, noop on delete-missing. The strict counterpart (`registry-graft`) — error on overwrite, error on missing-update, structured `record=*` values — ships later in Phase 02. Pick by stance.

**`counter-graft` (priority 60)** — named `@ud` counters, init on first touch, saturating at `2^64-1`:

```rust
use vesl_core::{
    build_counter_increment_poke, build_counter_reset_poke, build_counter_set_poke,
};

// First increment of an unset name initializes to 1.
poke(&mut app, build_counter_increment_poke("requests")).await?;
// → %counter-incremented value=1

// Set to an arbitrary value.
poke(&mut app, build_counter_set_poke("requests", 1000)).await?;
// → %counter-set

// Reset to 0 (idempotent — also initializes unset names).
poke(&mut app, build_counter_reset_poke("requests")).await?;
// → %counter-reset
```

Peek path is `[%counter-value name=@t]`. Increments past `u64::MAX` return `%counter-error 'saturated'` and leave the counter unchanged so `u64` callers never encounter values they can't decode.

**`queue-graft` (priority 70)** — FIFO job queue with monotonic IDs. Bodies are opaque (`*` on the Hoon side); callers pre-jam whatever shape they want:

```rust
use vesl_core::{
    build_queue_clear_poke, build_queue_pop_poke, build_queue_push_poke,
};

let body_jammed: Vec<u8> = /* jam your domain payload here */;
poke(&mut app, build_queue_push_poke(&body_jammed)).await?;
// → %queue-pushed id=1

poke(&mut app, build_queue_pop_poke()).await?;
// → %queue-popped (job=~ on empty queue, [~ [id body]] otherwise)

poke(&mut app, build_queue_clear_poke()).await?;
// → %queue-cleared (next-id is preserved across clears)
```

Peek path is `[%queue-len ~]` — total pending jobs. `%queue-push` is the first state-graft poke that cue's caller-supplied bytes inside its body, so the kernel wraps the decode in `mule`: malformed jam surfaces as `%queue-error` rather than crashing the kernel (Safety Contract C1).

When the body originates as an in-process noun, `build_queue_push_poke_from_noun(slab)` jams internally and skips the manual jam dance. For pipelines that forward bytes pulled from a cue-emitting source (e.g., `%queue-popped` body) into another cue-consuming graft (`%batch-add`, `%log-append`, `%registry-put`), pair the byte-taking builder with `vesl_core::rejam_atom` — the popped bytes are atom representation, not jam, and feeding them straight in fails (or hangs `cue` on pathological back-refs). See the "Cross-graft pipelines" subsection of `vesl-core`'s `reference/sdk.md`.

**`rbac-graft` (priority 80)** — pubkey-keyed permission table. Causes carry perms as `(list @t)` so Rust callers hand a flat slice of perm names; the graft `silt`s into a `(set @t)` internally:

```rust
use vesl_core::{build_rbac_grant_poke, build_rbac_revoke_poke};

poke(&mut app, build_rbac_grant_poke(1, &["read", "write"])).await?;
// → %rbac-granted added=("read" "write")

poke(&mut app, build_rbac_grant_poke(1, &["audit"])).await?;
// Union with held → final perms = {read, write, audit}.
// Effect surfaces only the diff: %rbac-granted added=("audit").

poke(&mut app, build_rbac_revoke_poke(1, &["write", "ghost"])).await?;
// "ghost" wasn't held — intersect-then-noop. Effect:
// %rbac-revoked removed=("write"). Held perms = {read, audit}.
```

Two-level capacity (`roles-cap = 10M`, `perms-per-role-cap = 1k`) prevents both global fan-out and per-pubkey perm-set blow-up. Revoking the last permission auto-clears the pubkey from the `roles` map. Peek paths: `[%rbac-perm-count pubkey=@]` and `[%rbac-has-perm pubkey=@ perm=@t]`.

**`registry-graft` (priority 90)** — strict structured registry. Strict put (error on overwrite), strict update (error on missing key, surfaces old + new), strict delete (error on missing key). Records are opaque `*` (any noun); pre-jam them on the Rust side:

```rust
use vesl_core::{
    build_registry_del_poke, build_registry_put_poke, build_registry_update_poke,
};

let manifest_jammed = jam_to_bytes(&mut stack, my_manifest_noun);
poke(&mut app, build_registry_put_poke(key_id, &manifest_jammed)).await?;
// → %registry-stored. Re-put on existing key → %registry-error.

poke(&mut app, build_registry_update_poke(key_id, &new_manifest_jammed)).await?;
// → %registry-updated old=… new=… (audit-friendly diff).
// Update on missing key → %registry-error.

poke(&mut app, build_registry_del_poke(key_id)).await?;
// → %registry-deleted. Del on missing key → %registry-error.
```

Peek path is `[%registry-entry key=@]`. Registry has the heaviest C1 surface in Phase 02 — both put and update cue caller-supplied bytes inside their poke arms under a `mule` guard, so malformed jam surfaces as `%registry-error` rather than crashing the kernel. `kv-graft` is the loose counterpart (overwrite-on-set, noop-on-missing-delete, atom values); pick by stance.

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
3. `graft-inject --apply hoon/app/app.hoon` — same as Step 3 above. Safe to run against a populated kernel; it only edits marker lines. Bare invocation (no `--apply`) previews.
4. Recompile (`hoonc hoon/app/app.hoon hoon/`) and rebuild (`cargo +nightly build`).
5. Call `vesl_core::build_settle_register_poke`, `build_settle_note_poke`, `build_settle_verify_poke` from your existing `main.rs` alongside your domain pokes. No rewrite needed.

If `graft-inject` reports `warning — markers not found: ...`, you missed a marker or a two-space law violation. The tool is pure text — it does what the regex says.

## Customizing

The grafted kernel is opinionated: default hash gate, single hull namespace, hardcoded state layout. Every app needs to override at least one of these.

### Add your own state fields

Your app almost certainly has state beyond vesl's commitment tracking — counters, maps, user records, pending jobs. Add them after `settle=settle-state` in `versioned-state`:

```hoon
+$  versioned-state
  $:  %v1
      settle=settle-state
      counter=@ud
      items=(map @ @t)
  ==
```

Any new field needs handling in `++load` (migration from older state versions) and `++poke` (the arms that read or write it).

### Add your own domain pokes

Vesl handles `%settle-register`, `%settle-verify`, and `%settle-note`. Your app handles everything else — order placement, message sending, whatever your domain is. The minimum per domain command is three blocks of Hoon: one state field (if the command needs state), one cause variant, and one `?-` arm.

Worked example — a **badge issuer** that increments a per-subject counter and emits `%badge-issued`:

```hoon
::  in versioned-state, after `settle=settle-state`:
badges=(map @ud @ud)
```

```hoon
::  in the cause $% union, alongside settle-cause:
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

The Rust side needs three primitives the `build_*_poke` helpers hide for you — `NounSlab`, a long-tag builder, and a wide-atom builder:

```rust
use nockapp::{AtomExt, Bytes, NockApp, noun::slab::NounSlab, wire::{SystemWire, Wire}};
use nockvm::noun::{Atom, T};
use nock_noun_rs::atom_from_u64;

async fn issue_badge(app: &mut NockApp, subject: u64) -> anyhow::Result<()> {
    let mut slab = NounSlab::new();
    let tag  = Atom::from_bytes(&mut slab, &Bytes::copy_from_slice(b"issue-badge")).as_noun();
    let subj = atom_from_u64(&mut slab, subject);
    let noun = T(&mut slab, &[tag, subj]);
    slab.set_root(noun);
    let _ = app.poke(SystemWire.to_wire(), slab).await?;
    Ok(())
}
```

Three rules the graft builders apply for you but that you inherit directly when you construct causes manually:

- **Long tags** (> 8 bytes) can't go through `D(tas!(b"…"))` — it panics at compile time. Use `Atom::from_bytes(slab, &Bytes::copy_from_slice(b"…"))` for anything from `settle-register` upward.
- **`AtomExt::from_bytes` takes `&bytes::Bytes`**, not `&[u8]`, via the `nockapp::Bytes` re-export.
- **Wide `u64` values** (hashes, IDs where the top bit may be set) panic under `D(value)` with `Number is greater than DIRECT_MAX` — route them through `nock_noun_rs::atom_from_u64(slab, value)`. The Troubleshooting section covers the mechanism.

The pattern generalizes to N arguments — construct one atom per cause field, then `T(&mut slab, &[tag, arg1, arg2, …])`. For a 3-arg `[%submit-artifact name=@t hash=@ submitter=@ux]`:

```rust
fn submit_artifact(name: &[u8], hash: u64, submitter: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag  = Atom::from_bytes(&mut slab, &Bytes::copy_from_slice(b"submit-artifact")).as_noun();
    let nm   = Atom::from_bytes(&mut slab, &Bytes::copy_from_slice(name)).as_noun();
    let h    = atom_from_u64(&mut slab, hash);
    let s    = atom_from_u64(&mut slab, submitter);
    let noun = T(&mut slab, &[tag, nm, h, s]);
    slab.set_root(noun);
    slab
}
```

The rule of thumb: byte-strings and short tas-atoms go through `Atom::from_bytes`; any integer wider than `DIRECT_MAX` (hashes, hull-ids, submitter IDs with the top bit set) goes through `atom_from_u64`; direct atoms ≤ `DIRECT_MAX` can stay on `D(v)`. Order arguments in `T(&[...])` to match the cause tuple layout in your `app.hoon`.

Seven lines of custom Hoon total for the 1-arg example, eleven for the 3-arg. Two of those (the state field and the cause variant) are pure type declarations; the rest is the arm itself. The arm's `:_ state(...)` / `^- (list effect)` / `~[[...]]` shape is NockApp's required `[effects state]` return — the same in any nockapp, graft or no graft.

The vesl arms stay put. You're adding arms, not replacing them.

Future direction: `graft-inject` is being rearchitected (see `.dev/PARAMETIZATION.md`) so that user-defined domains can ship as their own grafts with a TOML manifest — which will mechanize the state-field and cause-variant declarations. The arm body is the part that stays yours.

### Add your own peek paths

`graft-inject` wires each graft's peek handler into a chain: settle-peek, then mint-peek, then guard-peek, each one returning `~` to defer to the next. Your domain arm goes at the tail of that chain, below the last `?.  =(~ <graft>-res)  <graft>-res` line.

Worked example — a **`[%artifact-by-name @t ~]` lookup** against a `artifacts=(map @t artifact-meta)` state field:

```hoon
::  inside ++peek, below the vesl peek chain:
?.  ?=([%artifact-by-name @t ~] path)
  ~
=/  got  (~(get by artifacts.state) i.t.path)
?~  got  [~ ~]
``u.got
```

Five lines. `?=` pattern-matches the path shape; `i.t.path` is standard list traversal (`t.path` drops `%artifact-by-name`, `i.t.path` is the `@t` second element). The `(unit (unit *))` return-type convention has three shapes:

- **`~`** — "this path is not for me, let the next arm try." Use this on any path your arm doesn't recognize.
- **`[~ ~]`** — "I recognize this path, but there is no value here." The standard map-lookup miss.
- **`` ``x ``** — shorthand for `[~ ~ x]`, "I recognize this path and the value is `x`." `x` must be a noun (`*`).

The vesl peek chain follows the same convention — each graft's `<graft>-peek` returns `~` when the path is not for it, so composing arms is just a list of `?.  =(~ <res>)  <res>` guards. Put your arm at the tail; put the bare `~` fallthrough below it if nothing else matches.

### Replace the default verification gate

`graft-inject` installs a gate that tip5-hashes the raw payload bytes and checks equality against the registered root. That works for single-leaf commitments (one piece of data → one root). It breaks the moment you have anything richer:

- **Merkle manifests** (like verifiable RAG): payload is a structured manifest with multiple leaves + proofs; the gate walks each proof against the root.
- **Signatures**: payload carries a signature; the gate verifies it against a public key committed in the root.
- **STARK proofs**: payload is a proof; the gate runs the verifier.

Inside each `%settle-*` arm, replace the gate body:

```hoon
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  (my-custom-verify note-id data expected-root)
```

`verify-gate` is `$-([note-id=@ data=* expected-root=@] ?)`. `note-id` is bound so domain gates can enforce `note-id == deterministic-fn(data)`, closing the pre-commit race (audit H-03). `data` is whatever your Rust side jammed into the `payload` atom; your gate casts it (`;;(manifest data)`, `;;(my-intent data)`, etc.) and returns a loobean. The caller decides what the data shape is — the graft doesn't care. The installed three-arg signature matches `hoon/lib/settle-graft.toml:34`.

### Drive a catalog gate from Rust

When your manifest selects one of the Tier 1a catalog gates via `[graft.gates]` (`sig-verify-schnorr`, `sig-verify-ed25519`, `manifest-verify`, `set-membership-verify`, `bounded-value-verify`), the gate's `data` field is no longer a flat byte slice — it's a structured cell. `vesl-core` ships per-gate poke builders that thread the right cell shape; pick the one matching your gate. Worked Schnorr example, end-to-end:

```rust
use vesl_core::{
    Mint, build_settle_register_poke, build_settle_note_schnorr_poke,
    derive_pubkey, sign,
    pubkey_canonical_bytes, pack_schnorr_signature, schnorr_message_digest_for_data,
};
use nockchain_math::belt::Belt;

let mut sk = [Belt(0); 8];
sk[0] = Belt(0xabad_f00d);                       // your real key, not this fixture
let pubkey = derive_pubkey(&sk);

let pk_bytes = pubkey_canonical_bytes(&pubkey);
let leaf_root = Mint::new().commit(&[&pk_bytes]); // hull commits to the pubkey
poke(&mut app, build_settle_register_poke(1, &leaf_root)).await?;

let message: &[u8] = b"attest: 32-byte hash fingerprint"; // arbitrary &[u8]
let digest = schnorr_message_digest_for_data(message);
let sig    = sign(&sk, &digest)?;
let slab   = build_settle_note_schnorr_poke(101, 1, &leaf_root, message, &sig, &pubkey);
poke(&mut app, slab).await?;                       // -> %settle-noted
```

`pack_schnorr_signature` and `pubkey_canonical_bytes` produce the exact wire shapes `sig-verify-schnorr` expects (`(chal << 256) | s` and the 97-byte `ser-a-pt:cheetah` encoding); `schnorr_message_digest_for_data` mirrors the gate's `(hash-leaf-digest data)` reduction (chunked tip5 over arbitrary `&[u8]`) so the signature you produce verifies.

The other catalog gates each ship a parallel builder:

```rust
use vesl_core::{
    build_settle_note_ed25519_poke,
    build_settle_note_membership_poke,
    build_settle_note_bounded_poke,
    build_settle_note_manifest_poke,
};
```

For a future gate not yet covered by a convenience builder, drop down to the closure escape hatch:

```rust
use vesl_core::{build_settle_note_poke_with_data, NounSlab};
use nock_noun_rs::make_atom_in;
use nockvm::noun::T;

let slab = build_settle_note_poke_with_data(note_id, hull, &root, |slab| {
    // Construct whatever cell shape your gate's ;; cast expects.
    let a = make_atom_in(slab, b"...");
    let b = make_atom_in(slab, b"...");
    T(slab, &[a, b])
});
```

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
The composed `?-` over `-.u.act` isn't exhaustive. Usually this means one of the graft manifests is stale — re-install the vesl graft package (or re-run `sync.sh` in a dev checkout) to pick up the latest arm set. If the missing tag is `%settle-rotate-epoch`, your manifest predates the C-01 remediation that removed it; re-sync.

**`hoonc` fails with `missing dependency /jams/constraints-0-1.jam`**
Forge-graft pulls in the STARK prover tree, which depends on pre-jammed constraint tables. Copy `hoon/dat/` and `hoon/jams/` from `vesl-nockup/` into your project, or skip forge via `graft-inject --exclude forge-graft`.

**`cargo build` fails on `ibig` with "expected `UBig`, found `ibig::ubig::UBig`"**
You pulled `ibig` from crates.io instead of the nockchain fork. Vesl-core pins the nockchain fork — if you've added your own `ibig` dep, remove it.

**`Number is greater than DIRECT_MAX` panic**
A `u64` you're feeding into `D()` has its top bit set. Use `nock_noun_rs::atom_from_u64(alloc, value)` instead of `D(value)` for hashed IDs. All vesl-core pokes already route hull-ids through `atom_from_u64` internally.

**`%settle-note` returns no effects, stderr shows `DETERMINISTIC error mote=Exit`**
The verify-gate returned `%.n`. The `?>` in `lib/settle-graft.hoon`'s `%settle-note` arm crashes on gate failure by design — a rejected payload must remain an unprovable STARK state rather than an emitted error. From the Rust side, `app.poke(...).await` resolves `Ok(effects)` with `effects.len() == 0`; treat that as a gate rejection and inspect stderr for the trace. The most common cause is committing multiple leaves with the default single-leaf hash-gate (see Step 6's *Why a single-leaf commit?* note).

**Peek returns `~` on what looks like a valid path**
Settle-graft's peek paths are **namespaced**: `[%settle-registered hull ~]`, `[%settle-noted note-id ~]`, `[%settle-root hull ~]`, `[%settle-epoch ~]`, `[%settle-count ~]`. Pre-Phase-10 unprefixed forms (`%registered` / `%settled` / `%root` / `%epoch`) and the transitional Phase-10 `%vesl-*` forms are both retired — Phase 12A landed `%settle-*` as the final naming. Rust callers going through `vesl-core` are unaffected; the builders construct pokes, not peek paths.

## Reference

- Marker source-of-truth: `tools/graft-inject/src/main.rs`
- Manifest schema: `docs/graft-manifest.md`
- Hoon grafts + manifests: `hoon/lib/{settle,mint,guard,forge}-graft.{hoon,toml}`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- STARK prover / lower (forge deps): `hoon/lib/vesl-prover.hoon`, `hoon/lib/vesl-lower.hoon`
- Rust SDK (upstream, consumed as a dep): `<vesl>/crates/vesl-core/src/`
  - Poke builders: `graft_pokes/{settle,mint,guard,forge}.rs`
- Test harness: `test/vesl-test/src/lib.rs`
- Integration tests: `tools/graft-inject/tests/{mint_lifecycle,guard_lifecycle,forge_compile,integration}.rs`
- Test scaffolding: `tools/graft-inject/tests/fixtures/mod.rs`

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
