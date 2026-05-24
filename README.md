# vesl-nockup

Add vesl to a nockup project in three commands.

```bash
nockup project init                                  # fetches vesl template + zkvesl/vesl-graft
nockup graft inject --apply hoon/app/app.hoon        # composes grafts into the kernel
cargo +nightly run --release                         # builds out.jam, runs the kernel
```

The new-project flow uses the `vesl` template shipped from this repo via nockup's `template_git` extension hook. No Cargo.toml fixups, no `[patch.crates-io] ibig` block to remember by hand.

> **Why `--release`?** The nockvm runtime ships `debug_assert!`s that check stack-frame invariants under debug-build assumptions and are compiled out in release. Booting a 14-graft kernel under debug panics on the first poke (`nockvm::mem::is_in_frame`). `--release` is the supported development mode for vesl-nockup; an upstream fix to loosen the assertion is tracked separately.

## Prerequisites

1. **Clone the nockchain monorepo** — source for `nockup`, and for the `nockchain` binary later if you run against fakenet/dumbnet (the three-command flow below doesn't need the chain binary on `PATH`):

   ```bash
   git clone https://github.com/nockchain/nockchain.git
   ```

2. **Install `nockup`** — the project scaffolder. `nockup install` downloads `hoon`, `hoonc`, and `nockup` itself into `~/.nockup/bin/` and prepends that to your `PATH`. Either script install or build from the cloned monorepo:

   ```bash
   # Script install
   curl -fsSL https://raw.githubusercontent.com/nockchain/nockchain/refs/heads/master/crates/nockup/install.sh | bash

   # Or build from source
   cd nockchain && cargo install --path crates/nockup --locked
   ```

3. **Rust nightly** — `rustup toolchain install nightly`.

4. **`nockup-graft`** — the vesl-flavored graft composer; sidecar binary built from this repo:

   ```bash
   cargo install --git https://github.com/zkvesl/vesl-nockup --bin nockup-graft
   ```

   After install, `nockup graft <subcmd>` resolves the binary via nockup's plugin discovery.

Verify:

```bash
hoonc --version && nockup --help >/dev/null && cargo +nightly --version && nockup-graft --version
```

## Three-command setup

Write `nockapp.toml` declaring the package and the `vesl` template source:

```bash
cat > nockapp.toml <<'TOML'
[package]
name = "my-app"
version = "0.1.0"
description = "grafted NockApp"
template = "vesl"
template_git = "https://github.com/zkvesl/vesl-nockup"
template_path = "templates"

[dependencies]
"zkvesl/vesl-graft" = "latest"
TOML

nockup project init
cd my-app
```

`nockup project init` does three things:

1. Fetches the `vesl` template from this repo via `template_git` and renders it into `my-app/`.
2. Runs `nockup package install` to fetch `zkvesl/vesl-graft` and symlink the graft library into `hoon/lib/`.
3. Walks vesl-graft's `[[patches]]` array (mechanism: [nockchain/nockchain#117](https://github.com/nockchain/nockchain/pull/117)), prints a summary of the planned `Cargo.toml` reshapes, and prompts `apply patches? [y/N]`. Press `y`.

After step 3, your `Cargo.toml` has git-deps to nockchain and vesl-core pinned at the rev vesl-graft was published against, plus the two `[patch]` blocks (the nockchain transitive-dep unifier and the `[patch.crates-io] ibig` redirect). No sibling clones, no fixups.

For non-interactive runs (CI), pipe `yes y | nockup project init` or split into `nockup project init` followed by `nockup package install --accept-patches`. `nockup patches list` shows the applied patches; `nockup patches eject zkvesl/vesl-graft` releases vesl-graft's claim on `Cargo.toml` if you'd rather hand-manage deps (e.g. against a sibling-clone development layout).

```bash
nockup graft inject hoon/app/app.hoon            # preview
nockup graft inject --apply hoon/app/app.hoon    # write
```

The template's `app.hoon` ships with ten `::  nockup:*` markers. `nockup graft inject` discovers every `<name>-graft.toml` under `hoon/lib/`, composes their per-marker blocks, and (with `--apply`) writes the result. About 80 lines per graft. Preview is the default — nothing lands on disk until `--apply`. See [Inject](https://github.com/zkvesl/zkvesl-docs/blob/main/docs/build/inject.md) for marker semantics, lint families, and the per-graft sha256 banner.

Inject also refuses to compose when the project has no `nockapp.toml` — the file scaffolded above is the trust anchor (see [Manifest Schema → Trust Model](https://github.com/zkvesl/zkvesl-docs/blob/main/docs/build/grafts/manifest-schema.md#trust-model)). Without it, inject would splice arbitrary Hoon from any directory into your kernel; running from inside the scaffolded project keeps this check satisfied.

```bash
hoonc hoon/app/app.hoon hoon/ && [ -s out.jam ] || \
  (echo "hoonc: silent-failed — exit 0 but no out.jam" >&2; exit 1)

cargo +nightly run --release
```

The `[ -s out.jam ]` guard is load-bearing: hoonc can exit 0 with no jam written under structural type errors. First Cargo build fetches and compiles the full nockchain stack — expect 2–5 minutes.

## Expected output

```
  effect: %settle-registered
  effect: %settle-noted
```

You now have a grafted NockApp with on-kernel Merkle verification and replay-protected settlement.

`vesl-core` exports `build_settle_verify_poke(note_id, hull, root, data)` for pure verification (no state transition), and `build_mint_commit_poke` / `build_guard_register_poke` / `build_guard_check_poke` / `build_forge_prove_poke` for the other three commitment primitives. See *Customizing* below for multi-leaf gates, signed gates, and STARK gates.

### Cause-builder reference

`vesl-core` ships a `build_*_poke` helper for every primary cause across all 12 graft families. The full per-graft tables — including refinement variants (`_with_data` closures, `_from_noun` payload builders, gate-specific settle forms) — live in the [zkVesl SDK reference](https://docs.zkvesl.dev/reference/sdk.html#graft-poke-builders). The table below is the visual quick-reference for the primary builders so you don't have to scroll back through Step 6 prose to recall a signature.

> **Long-tag rule.** Cause tags >8 bytes panic at compile time under `tas!()` (e.g. `submit-artifact`, `register-thing`). Use `Atom::from_bytes(slab, &Bytes::copy_from_slice(b"<tag>"))` for any tag from `settle-register` upward. Wide `u64` values (hashes, IDs where the top bit is set) panic under `D(value)` with `Number is greater than DIRECT_MAX` — route them through `nock_noun_rs::atom_from_u64(slab, value)`.

| Family | Builder | Effect(s) |
|---|---|---|
| Commitment | `build_settle_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab` | `%settle-registered` / `%settle-error` |
| Commitment | `build_settle_verify_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab` | `%settle-verified ok=?` |
| Commitment | `build_settle_note_poke(note_id: u64, hull: u64, root: &Tip5Hash, data: &[u8]) -> NounSlab` | `%settle-noted` / `%settle-error` |
| Commitment | `build_mint_commit_poke(hull: u64, root: &Tip5Hash) -> NounSlab` | `%mint-committed` / `%mint-error` (append-only) |
| Commitment | `build_guard_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab` | `%guard-registered` / `%guard-error` |
| Commitment | `build_guard_check_poke(hull: u64, data: &[u8]) -> NounSlab` | `%guard-checked ok=?` (soft) / `%guard-error` on unregistered hull |
| Commitment | `build_forge_prove_poke(hull: u64, note_id: u64, data: &[u8]) -> NounSlab` | `%forge-proved proof=@` / `%forge-error` |
| State | `build_kv_set_poke(key: &str, value: &[u8]) -> NounSlab` | `%kv-stored` / `%kv-error` (capacity) |
| State | `build_kv_delete_poke(key: &str) -> NounSlab` | `%kv-deleted` (idempotent on missing) |
| State | `build_counter_increment_poke(name: &str) -> NounSlab` | `%counter-incremented value=@ud` / `%counter-error 'saturated'` past `u64::MAX` |
| State | `build_counter_set_poke(name: &str, value: u64) -> NounSlab` | `%counter-set value=@ud` |
| State | `build_counter_reset_poke(name: &str) -> NounSlab` | `%counter-reset` (idempotent — initializes unset names to 0) |
| State | `build_queue_push_poke(body_jammed: &[u8]) -> NounSlab` | `%queue-pushed id=@ud` / `%queue-error` |
| State | `build_queue_pop_poke() -> NounSlab` | `%queue-popped job=(unit [id body])` (`~` on empty) |
| State | `build_queue_clear_poke() -> NounSlab` | `%queue-cleared` (next-id preserved) |
| State | `build_rbac_grant_poke(pubkey: u64, perms: &[&str]) -> NounSlab` | `%rbac-granted added=(list @t)` (set diff only) |
| State | `build_rbac_revoke_poke(pubkey: u64, perms: &[&str]) -> NounSlab` | `%rbac-revoked removed=(list @t)` (intersect-then-noop) |
| State | `build_registry_put_poke(key: u64, record_jammed: &[u8]) -> NounSlab` | `%registry-stored` / `%registry-error` (strict create) |
| State | `build_registry_update_poke(key: u64, record_jammed: &[u8]) -> NounSlab` | `%registry-updated old=* new=*` / `%registry-error` |
| State | `build_registry_del_poke(key: u64) -> NounSlab` | `%registry-deleted` / `%registry-error` (strict delete) |
| Behavior | `build_validate_init_poke(cause_tag: &str, rules: &[ValidateRule]) -> NounSlab` | `%validate-rules-installed` |
| Behavior | `build_validate_clear_poke(cause_tag: &str) -> NounSlab` | `%validate-rules-cleared` (idempotent) |
| Behavior | `build_log_append_poke(tag: &str, data_jammed: &[u8]) -> NounSlab` | `%log-appended seq=@ud` / `%log-error` (malformed payload) |
| Behavior | `build_clock_tick_poke() -> NounSlab` | `%clock-ticked now=@da` |
| Behavior | `build_batch_init_poke(threshold: u64) -> NounSlab` | `%batch-initialized threshold=@ud` |
| Behavior | `build_batch_add_poke(intent_jammed: &[u8]) -> NounSlab` | `%batch-added id=@ud` (plus `%batch-flushed` on auto-flush) / `%batch-error` |
| Behavior | `build_batch_flush_poke() -> NounSlab` | `%batch-flushed bundle count` (always emits — boundary signal) |

Refinement variants — `_from_noun` for in-process payloads, `_with_data` closures for custom gate payloads, and the five gate-specific settle builders (`_schnorr`, `_ed25519`, `_membership`, `_bounded`, `_manifest`) — are documented in the SDK reference linked above.

## Serving over HTTP

The same scaffold ships an HTTP server backed by the `vesl-hull` crate. Run the binary with the `serve` subcommand to boot the kernel and mount `/commit`, `/settle`, `/verify`, `/tx/:tx_id`, `/status`, and `/health` on `http://127.0.0.1:3000`:

```bash
cargo +nightly run --release -- serve --no-auth   # loopback, demo signing key
```

`--no-auth` is only honored on loopback binds; the kernel-side endpoints stay behind `HULL_API_KEY` on any non-loopback `--bind-addr`. To add domain handlers, pass your routes to `vesl_hull::serve_with_extra_routes` (or `vesl_hull::router_with_extra`) — not `Router::merge(vesl_hull::router(state), ...)`, which attaches them outside the auth / 4 MiB body-limit / rate-limit layers and leaves them unauthenticated. See [`templates/vesl/README.md`](./templates/vesl/README.md#cli) for the full flag table and endpoint catalog.

## What the template ships

- `Cargo.toml` — vesl-graft's `[[patches]]` rewrites it to git-deps + both `[patch]` blocks at install time (path-deps remain in the pre-patch template as a fallback for ejected / sibling-clone workflows)
- `build.rs` — declares the `out.jam` rerun-if-changed and runs `nockup graft doctor` on every build, forwarding project-health findings as `cargo:warning=` lines (it warns only, never fails the build)
- `src/main.rs` — clap CLI with `Demo` and `Serve` arms (Demo runs the register/settle smoke test; Serve mounts the `vesl-hull` HTTP API)
- `hoon/app/app.hoon` — markered kernel template
- `hoon/lib/lib.hoon` — domain-library stub

The template lives at `templates/vesl/` in this repo. `templates/graft-scaffold/` is the older starter that requires manual fixups; the `vesl` template supersedes it for new projects.

## Hull/kernel drift detection

The demo scaffolds' `build.rs` runs `nockup graft codegen kernel-cause-tags` after `hoonc` and writes `kernel_cause_tags.rs` into `OUT_DIR`. The path is exposed as the `KERNEL_CAUSE_TAGS_PATH` env var (mirroring `COMPILED_HOON_PATH`). Pull it into your hull:

```rust
include!(env!("KERNEL_CAUSE_TAGS_PATH"));

fn build_settle_register_poke(hull: u64, root: &Tip5Hash) -> NounSlab {
    assert_kernel_cause_tag!("settle-register");
    // ... construct the noun ...
}
```

`assert_kernel_cause_tag!` runs a const-time membership check against `KERNEL_CAUSE_TAGS`. A kernel rename (e.g. `%settle-register` → `%settle-write`) without re-running the codegen now fails `cargo build` at the macro invocation, surfacing the drift as a compile error rather than a silent `Ok(vec![])` from `app.poke(...)` at runtime.

`KERNEL_CAUSE_TAGS` is derived from the literal `+$ cause` definition in `app.hoon`, not from the union of every `--lib-dir` manifest. Two consequences:

- **Domain causes are covered.** `[%submit-artifact ...]`, `[%emit-license ...]`, etc. — the inline variants you added directly to your domain — show up in `KERNEL_CAUSE_TAGS`. `assert_kernel_cause_tag!("submit-artifact")` compiles.
- **Inactive grafts contribute nothing.** A graft sitting under `hoon/lib/` but never referenced from `+$ cause $%(...)` doesn't pollute the slice. `assert_kernel_cause_tag!("kv-set")` only compiles when `kv-graft`'s `kv-cause` actually appears in your kernel's union.

If `nockup-graft` isn't installed in the build environment, the codegen step emits a `cargo:warning` and leaves `KERNEL_CAUSE_TAGS_PATH` unset — hulls that gate the include on `cfg(env_var = "KERNEL_CAUSE_TAGS_PATH")` continue to build. Drift detection is opt-in per hull.

```bash
nockup graft codegen kernel-cause-tags hoon/app/app.hoon --out src/kernel_cause_tags.rs
nockup graft codegen kernel-cause-tags hoon/app/app.hoon --json
```

The `vesl` scaffold's `build.rs` is separate: it runs `nockup graft doctor` on every `cargo build` — project-health checks (schema-version handshake, Cargo `[patch]` consistency, hand-edited graft blocks, a missing `nockup:load-defaults` marker) surfaced as `cargo:warning=` lines. It warns, never fails the build, and is skipped when `NOCKUP_GRAFT_BIN` is unset. See *Updating an existing project*.

### mint / guard / forge: the other three primitives

If your `nockup graft inject` call composed more than just `settle-graft`, `vesl-core` also exports builders for the other primitives. All take the same shape — primitives in, `NounSlab` out:

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

Forge is the one primitive that produces a STARK. It pulls in the prover tree (~16MB of pre-jammed constraint tables compiled into your kernel) — the heaviest compile-time cost in the graft library, but required for any nockapp that needs to verify a STARK on-chain, which is most of them.

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

Beyond the four commitment grafts, `nockup graft` ships off-the-shelf state grafts in the 50–99 priority band so apps don't need to write Hoon for generic app-state. Two grafts have landed so far.

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

Compose by listing the graft alongside the others: `nockup graft inject --grafts settle,mint,kv hoon/app/app.hoon`. Peek path is `[%kv-value key=@t]` returning the stored atom or `~`. The store is capped at 10M entries (`%kv-error 'capacity'` on overflow). Overwrite of an existing key bypasses the cap.

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

> **Pre-jam payloads in custom domain arms.** If you delegate to `%registry-put` from your own kernel arm, jam the payload first (`(jam payload)` in Hoon, or pre-jam on the Rust side via `vesl_core::jam_to_bytes`). Registry's `mule (cue payload)` reads the bytes as jam — passing a raw atom may emit `%registry-stored` with garbage state OR `%registry-error 'cue failure'`, depending on what bits the atom happens to contain. The same constraint applies at the queue-pop → batch-add cross-graft seam (use `vesl_core::rejam_atom` between the two pokes).

## Adding vesl to an existing nockup project

If you already have a working nockapp, the three-command flow above doesn't directly apply — your existing `app.hoon` needs marker annotation rather than a fresh template. The five-step path:

1. **Add the package**: `nockup package add zkvesl/vesl-graft -v latest && nockup package install` drops the graft library into `hoon/lib/` and `hoon/common/`.
2. **Patch `Cargo.toml`** to match the `vesl` template's path-deps and `[patch]` blocks. Compare against `templates/vesl/Cargo.toml` in this repo. Once the in-flight patches-engine PR merges into upstream nockup, this step automates via the package's `[[patches]]` block.
3. **Annotate `app.hoon` with the ten `::  nockup:*` markers**. Easiest path: copy [`templates/app.hoon`](https://github.com/zkvesl/vesl-nockup/blob/main/templates/app.hoon) over your existing `app.hoon` — its 89 lines have all ten markers pre-placed at the right structural points. Move your existing causes, peeks, and state into the corresponding slots; don't revert the file back to the basic scaffold's shape afterwards. Or annotate your existing `app.hoon` by hand — `nockup graft inject` looks for exact comments at specific structural points:
   - `::  nockup:imports` — top of file, near other `/+` imports
   - `::  nockup:state` — inside the `versioned-state` `$:` block
   - `::  nockup:load-defaults` — inside `++ load`, where codegen lands the schema-extension overlay
   - `::  nockup:cause` — inside the `cause` `$%` union
   - `::  nockup:poke-prelude` — immediately before the `?-` poke switch
   - `::  nockup:poke` — inside the `?-` poke switch, last item before `==`
   - `::  nockup:poke-postlude` — immediately after the `?-` switch
   - `::  nockup:peek` — inside the peek handler's `?+` default arm
   - `::  nockup:domain-effect` — anchor for your `+$ domain-effect $%(...)` declaration
   - `::  nockup:effect-union` — codegen target for the typed `+$ effect` union

   Spacing: `::` followed by one or more spaces, then `nockup:<name>` — the templates use two.
4. `nockup graft inject --apply hoon/app/app.hoon` — composes graft bodies. Idempotent; safe to run against a populated kernel.
5. Recompile (`hoonc hoon/app/app.hoon hoon/`) and rebuild (`cargo +nightly build`). Call `vesl_core::build_settle_register_poke`, `build_settle_note_poke`, `build_settle_verify_poke` from your existing `main.rs` alongside your domain pokes.

If `nockup graft inject` reports `warning — markers not found: ...`, you missed a marker or mistyped one. The tool is pure text — it does what the regex says.

## Updating an existing project

A project built with vesl-nockup is a frozen snapshot. vesl-nockup reaches it through several independent channels, and none of them auto-propagate — an update is pulled, not pushed. `Cargo.lock` freezes the Rust graph, the template files are your copies, and `app.hoon` is yours. A new vesl-nockup release changes nothing in your project until you act on one of these channels:

| Channel | Carries | Reaches your project via |
|---|---|---|
| `nockup-graft` binary | the graft composer | re-running `cargo install --git … --bin nockup-graft` |
| `zkvesl/vesl-graft` package | the Hoon graft library under `hoon/lib/` | `nockup package install` |
| `vesl` template | scaffold files (`Cargo.toml`, `build.rs`, `main.rs`, `app.hoon`) | only `nockup project init` — never an existing project |
| Bundled crates (`vesl-core`, `vesl-hull`, `vesl-test`) | the Rust SDK | git-deps in `Cargo.toml`, frozen by `Cargo.lock` until `cargo update` |
| Pins (`NOCK_PIN`, `VESL_CORE_PIN`, `VESL_WALLET_PIN`) | the nockchain / vesl-core revs baked into a scaffold | template `Cargo.toml` revs, set once at scaffold time |

The `nockup-graft` binary and the `vesl-graft` package update on separate schedules and aren't version-locked to each other. Update both in the same pass so the composer and the manifests it reads stay in step.

### The update sequence

Run from the project root, in order:

1. **Commit or stash all work.** `nockup graft update` rewrites `app.hoon`; you want that diff isolated and reviewable.
2. **Snapshot live state.** If this is a running deployment, `vesl-checkpoint::snapshot` the kernel before recompiling — see *State checkpoints* below.
3. **Update the composer:** `cargo install --git https://github.com/zkvesl/vesl-nockup --bin nockup-graft --force`. Do this first — `nockup graft update` cannot replace its own running binary, and stops with this instruction if the refreshed library needs a newer one.
4. **Run `nockup graft update hoon/app/app.hoon`.** One verb for the recomposition: it runs `nockup package install` to refresh the graft library, previews the recomposition together with the `nockup graft doctor` health report, prompts for confirmation, then does `inject --apply`. Read the preview before pressing `y` — a `hand-edited-block` finding means a customization inside a banner pair is about to be overwritten. `--yes` skips the prompt for CI.
5. **Reconcile `Cargo.toml`.** A pin bump changes the nockchain / vesl-core revs your deps should resolve to. The `nockup package install` step 4 runs re-applies vesl-graft's `[[patches]]`; confirm the `[patch]` blocks still point at the rev `vesl-core` resolves to — a mismatch fails `cargo build` on `ibig` (see *Troubleshooting*) — then `cargo update -p vesl-core` rather than a blanket `cargo update`.
6. **Recompile:** `hoonc hoon/app/app.hoon hoon/ && [ -s out.jam ]`. The guard is load-bearing — hoonc can exit 0 with no jam written.
7. **Rebuild:** `cargo +nightly build`. The scaffold's `build.rs` re-runs `nockup graft doctor`, so any residual finding shows up in the build output.
8. **Resume.** If you snapshotted, `vesl-checkpoint::resume` from the new `out.jam`, then re-poke to restore state — resume reinitializes graft state to per-graft defaults.
9. **Re-run the lifecycle suite** with `vesl-test` to confirm the kernel still behaves.

`nockup graft update` absorbs the old install/preview/apply trio; running `nockup graft inject --apply` by hand still works when you want to drive composition without the orchestrator.

### Re-injection is not a merge

`nockup graft inject` owns the region between each `::  graft-inject:<graft>:<marker>:begin` and `:end` banner pair. Every `--apply` — and every `nockup graft update` — strips that region and re-emits it from the manifest. It does not merge: edits made between the banners are discarded on the next re-injection, whether or not the manifest changed.

Domain code added at the `::  nockup:*` markers but outside any banner pair — your causes, peeks, and `?-` arms — is not touched; re-injection only rewrites banner-bounded blocks. The hazard is editing *inside* a block. The most common case is replacing a verification gate by editing the gate body inside a `%settle-*` arm: that arm lives inside the `settle-graft:poke` block, so the next re-injection reverts it to the default hash-gate. Change a gate through `[graft.gates]` in the manifest instead (see *Replace the default verification gate* under *Customizing*). `nockup graft doctor` flags a hand-edited block before it is lost — it runs on every `cargo build` (see *What the template ships*) and in `nockup graft update`'s preview.

### When an update breaks the build

Most update-time failures are catalogued in *Troubleshooting* below. The ones an update specifically provokes:

- **`hoonc` exits 0 with no `out.jam`** — a newer graft library pulled a Hoon import your frozen `hoon/common`, `hoon/dat`, or `hoon/jams` subset doesn't satisfy. Refresh those trees from your vesl-nockup checkout.
- **`hoonc` fails `mint-lost` / `-lost %<tag>`** — the composer and the manifests are out of step. Re-run steps 3 and 4 together.
- **`cargo build` fails on `ibig` / `UBig`** — a pin moved and the `[patch]` block no longer matches the nockchain rev `vesl-core` resolves to. Realign the patch (step 7).
- **A poke returns `Ok(vec![])` with `slog: invalid cause` on stderr** — the kernel re-composed with a renamed cause-tag the hull still calls by its old name. Update the hull's `build_*_poke` calls; guard future renames at compile time with `assert_kernel_cause_tag!` (see *Hull/kernel drift detection*).
- **Post-resume pokes emit nothing** — the snapshot was taken against a different graft composition. See *State checkpoints*.
- **`nockup graft inject` or `nockup graft update` errors `manifest schema too new`** — the graft library declares a newer manifest schema than your installed `nockup-graft`. Update the binary (step 3) and re-run.

## State checkpoints

Operators upgrading a kernel without losing state — adding a graft, fixing a transition bug, retuning a verification gate — need a way to capture the current kernel state, recompile, and rehydrate. `vesl-checkpoint` (synced from vesl-core into `crates/vesl-checkpoint/`) wraps the underlying `nockapp` export/import path with a typed snapshot bundle. The `vesl` template wires it into `[dev-dependencies]` alongside `vesl-test`, so scaffolded projects get `snapshot` / `resume` without adding a dependency.

```rust
use vesl_checkpoint::{snapshot, resume};

// 1. Boot + register a hull (any normal lifecycle).
let mut harness = GraftTestHarness::boot("out.jam").await?;
harness.register(1, &root).await?;

// 2. Snapshot before re-composing the kernel.
let snap_dir = std::path::Path::new("snapshots/before-mint-graft");
let snap = snapshot(harness.app(), snap_dir, "hoon/app/app.hoon").await?;
drop(harness);

// 3. Re-run nockup graft inject + hoonc to add a graft, then resume.
//    (snap.state_jam() points at the bundled state.jam — `resume`
//     wires it through cli.state_jam internally.)
let resumed = resume("out.jam", &snap, "after-mint-graft").await?;

// 4. Peek the new kernel — pre-snapshot state survives.
let peek_path = vesl_core::build_hull_peek_path("settle-root", 1);
let result = resumed.peek(peek_path).await?;
let stored_root = vesl_core::unwrap_triple_unit_atom(&result);
assert_eq!(stored_root.as_deref(), Some(&root_bytes[..]));
```

Bundle layout written to disk:

```
snapshots/before-mint-graft/
├── state.jam   (bincode-encoded ExportedState — same format
│                that `nockapp::Cli::state_jam` accepts on import)
└── meta.toml   ([snapshot] source_sha256, timestamp,
                 vesl_checkpoint_version)
```

**Same-composition resume** (the new kernel has the same set of grafts as the snapshot) roundtrips cleanly — the snapshot's state is preserved, and both pre- and post-resume pokes emit effects. There are no new graft axes, so the defaults overlay is a no-op and nothing is reset.

**Schema-extension resume** (the new kernel adds grafts that weren't in the snapshot) works in v0.2 via `nockup graft inject` codegen at the `nockup:load-defaults` marker. The marker template ships an identity `++load` placeholder; `nockup graft inject` replaces it with a `=/  defaults  ^*(versioned-state)` + `%_  defaults  <field>  ^*(<field>-state)  ...  ==` overlay so resumed snapshots with a smaller noun shape get type defaults at the new graft axes instead of panicking inside the wrapper's mule guard. Pre-v0.2 (no marker, identity load) silently dropped effects on every graft past the first added priority band; the fix landed under RM4 §1 v0.2.

For test setups that need state-equivalence assertions, see `tools/graft-inject/tests/checkpoint_lifecycle.rs` (state survives same-composition resume modulo the v0.2 defaults overlay) and `tools/graft-inject/tests/resume_emits_effects.rs` (post-resume effect emission across priority bands, including the schema-extension test that flipped from `#[ignore]` to active under v0.2).

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

**Jam-shape payloads.** Grafts that store structured data (`registry`, `log`, `queue`, `batch`) take a pre-jammed `&[u8]` for the payload — the kernel re-cues inside a mule, so a raw atom passes the type check but cues to garbage. Always jam your payload first, or use the `_from_noun` paired helper:

```rust
// Direct (when you already have jammed bytes — e.g., forwarded from another graft):
let slab = build_registry_put_poke(key, &jammed_bytes);

// Via NounSlab (when you have a structured payload in-process):
let mut record = NounSlab::new();
record.set_root(your_noun);
let slab = build_registry_put_poke_from_noun(key, &record);
```

The `_from_noun` helper jams internally; the raw-bytes form trusts the caller. Currently shipped paired helpers: `build_registry_put_poke_from_noun`, `build_registry_update_poke_from_noun`, `build_log_append_poke_from_noun`, `build_queue_push_poke_from_noun`, `build_batch_add_poke_from_noun`. For the cross-graft seam where bytes come from a cue-emitting source (`%queue-popped` body) and need to land in a cue-consuming graft (`%batch-add`, `%registry-put`), pair the byte-taking builder with `vesl_core::rejam_atom` — the popped atom isn't jam-encoded, so feeding it straight in fails or hangs `cue` on pathological back-refs.

Seven lines of custom Hoon total for the 1-arg example, eleven for the 3-arg. Two of those (the state field and the cause variant) are pure type declarations; the rest is the arm itself. The arm's `:_ state(...)` / `^- (list effect)` / `~[[...]]` shape is NockApp's required `[effects state]` return — the same in any nockapp, graft or no graft.

The vesl arms stay put. You're adding arms, not replacing them.

Future direction: `nockup graft` is being rearchitected (see `.dev/PARAMETIZATION.md`) so that user-defined domains can ship as their own grafts with a TOML manifest — which will mechanize the state-field and cause-variant declarations. The arm body is the part that stays yours.

### Coordinating multiple grafts in one arm

When your domain arm threads state through more than one graft — increment a counter, write to a `kv` slot, append to the audit log, all in one poke — the hand-coded shape gets repetitive fast. Each graft poke is the same three lines (`=/  cause`, `=/  [efx state]  (graft-poke …)`, then a state-field update at the bottom), then a `(weld …)` to fold the effect lists together.

`vesl-core` ships a small library, `domain-patterns`, that bundles those shapes into one-line helpers. Import it manually (it has no graft manifest, so `nockup graft inject` doesn't auto-wire it):

```hoon
::  near the top of your app.hoon, alongside the other /+ lines:
/+  *domain-patterns
```

Two helper families:

- **`apply-<graft>`** — one wet-gate per shipped data/behavior graft (`apply-counter`, `apply-kv`, `apply-queue`, `apply-rbac`, `apply-registry`, `apply-log`, `apply-clock`, `apply-validate`, `apply-batch`). Each takes the graft's cause + your `versioned-state`, calls the underlying `<graft>-poke`, and returns `[(list <graft>-effect) versioned-state]` suitable for `=^` binding.
- **`audit-write`** — bundles "delegate to a storage graft (kv / registry / queue) + append to the log graft + return combined effects." Takes `log-tag` and `log-body` separately so the write payload and the audit-log payload can differ (e.g., `%revoke-license` writes a key delete but logs the human-readable name).

Worked example — an **`%audited-set` arm** that increments a per-key request counter, writes to the `kv` store, audit-logs the write, then emits a domain effect:

```hoon
::  in the cause $% union, alongside the graft-injected variants:
[%audited-set key=@t value=@]
```

```hoon
::  in the domain-effect $% union, alongside any other domain tags:
[%set-audited key=@t]
```

```hoon
::  inside ?-, alongside the graft-injected arms. The kernel must
::  carry counter=counter-state, kv=kv-state, log=log-state in its
::  versioned-state — the convention every shipped graft documents
::  in its `Usage:` block.
::
  %audited-set
=^  efx-c  state  (apply-counter [%counter-increment key.u.act] state)
=^  efx-aw  state
  (audit-write state [%kv-set key.u.act value.u.act] %set (jam value.u.act))
:_  state
(welp efx-c (welp efx-aw ~[[%set-audited key.u.act]]))
```

Five lines for three graft pokes plus a domain effect — the same arm written without the helpers runs to twelve lines (each graft poke gets its own `=/ cause`, `=/ [efx state]  (poke …)`, and the `state(counter …, kv …, log …)` update threads three field-updates on the bottom line). The R6 dogfood log measures a 6-line saving on this single arm; multi-arm domains scale that linearly.

The convention `apply-<graft>` relies on: each graft's state lives at the field named after the graft (`counter.state`, `kv.state`, …). Every shipped template + the `nockup graft inject` codegen emits state fields with these names already, so the helpers compose with anything `nockup graft inject` produces. If your kernel renames the field (`cnt.state` instead of `counter.state`), `hoonc` rejects with `find . counter` at the `apply-counter` call site — loud, attributable.

The full helper surface and the kernel-composite scope decisions live in `docs/graft-manifest.md` §"Library helpers — domain-patterns".

### Without the helpers — manual cross-graft widening

When you want to understand what `domain-patterns` does under the hood (or, rarely, when a project drops the library entirely), the multi-graft arm has to be hand-written with explicit `(list effect)` widening at each `=/` binding. Hoonc rejects a bare `weld` over heterogeneous `(list X-effect)` lists with a `nest-fail`; the widening cast at the binder bridges them. Copy this shape:

```hoon
  %audited-set
=/  [efx-r=(list effect) new-registry=registry-state]
  (registry-poke registry.state [%registry-put key.u.act value.u.act])
=/  [efx-l=(list effect) new-log=log-state]
  (log-poke log.state [%log-append %set (jam value.u.act)])
=.  state  state(registry new-registry, log new-log)
:_  state
^-  (list effect)
(welp efx-r (welp efx-l ~[[%set-audited key.u.act]]))
```

The `(list effect)` annotation at each `=/` widens the graft's narrow `(list X-effect)` into the kernel's typed effect-union; `welp` then operates on monomorphic lists. The helpers from `domain-patterns` (`apply-counter`, `apply-kv`, `audit-write`, …) bundle exactly this pattern into one-liners — same widening cast, hidden behind a wet-gate. See `zkvesl-docs/guides/grafting.md` §"Composing two graft arms in one domain cause" for the underlying type-theory note.

### Validate rules apply universally

A rule installed via `%validate-init` for a cause-tag fires on **every** poke matching that tag — graft-injected pokes (`%queue-push`, `%batch-add`, `%settle-note`, etc.) and domain pokes alike. The validate prelude runs once before the kernel's `?-` switch dispatches to any arm; rule failure short-circuits with `%validate-rejected` and leaves state untouched.

This makes `validate-graft` the right primitive for kernel-wide write policies (signing requirements, body-shape guards, rate limits) regardless of whether the policy targets a user-written or a grafted poke. Use it carefully: an over-broad rule on a graft cause-tag (e.g. `%non-empty` on `%settle-note`) will block every settle attempt with an empty-shape payload, regardless of who initiated it.

### Add your own peek paths

`nockup graft inject` wires each graft's peek handler into a chain: settle-peek, then mint-peek, then guard-peek, each one returning `~` to defer to the next. Your domain arm goes at the tail of that chain, below the last `?.  =(~ <graft>-res)  <graft>-res` line.

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

`nockup graft inject` installs a gate that tip5-hashes the raw payload bytes and checks equality against the registered root. That works for single-leaf commitments (one piece of data → one root). It breaks the moment you have anything richer:

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

**Swapping a gate selection mid-project.** When you change `[graft.gates] gate = "..."` in a manifest (e.g., promoting a project from `sig-verify-schnorr` in development to `manifest-verify` in production), re-run `nockup graft inject --apply hoon/app/app.hoon` — the composer detects the manifest drift via the `sha256:<short>` prefix it embeds in each `::  graft-inject:<graft>:<marker>:begin` banner, strips the stale block, and re-injects from the new manifest. The drift event is announced on stderr (`graft-inject: settle-graft: manifest drift at poke (banner sha256 eec1fca7a063 → current 3c43c1086620). Re-injecting.`). Pre-Phase-03h kernels whose banners predate the sha256 suffix are detected as legacy and force-re-injected once on first run after the upgrade — the new format is stamped in place, no manual cleanup needed.

### Removing a graft

You added `rbac-graft` to try it; now you're taking it back out. Drop the name from `--grafts` and re-run with `--apply`:

```bash
nockup graft inject --grafts settle-graft,registry-graft,log-graft --apply hoon/app/app.hoon
```

`nockup graft inject` auto-prunes the banner-pair-bounded blocks the dropped graft owned. The per-graft summary surfaces it:

```
  rbac-graft       no-manifest    pruned 5/5 (imports, state, cause, poke, peek) (orphan blocks from previous injection)
```

The lib files (`hoon/lib/rbac-graft.hoon`, `hoon/lib/rbac-graft.toml`) stay where they are — `nockup graft inject` only edits `app.hoon`. Delete them manually if you want them gone for good. Re-add the graft later by putting its name back in `--grafts`; the round-trip is byte-identical.

If your installed `nockup graft` predates RH1 step 1, you'll see the orphan blocks left behind and `hoonc` will fail with a wall of `hoonc.hoon` internals (the orphan arms reference an `effect` union variant that's no longer there). The workaround is a sed-range delete:

```bash
sed -i '/graft-inject:rbac-graft:[a-z-]*:begin/,/:end/d' hoon/app/app.hoon
```

Then `cargo install --path tools/graft-inject --force` to upgrade and never need that workaround again.

**`hoon/common/` transitive-import note.** When you slim the sandbox before a non-forge compile (a `rm hoon/lib/forge-graft.*` and `rm -rf hoon/dat hoon/jams` pass), strip the corresponding `hoon/common/` files too — `nock-prover.hoon`, `nock-verifier.hoon`, `pow.hoon`, `tx-engine{,-0,-1}.hoon`, and the `v0-v1`/`v2`/`stark` subtrees transitively `/#` into `hoon/dat/`. hoonc's eager-parse pass over the entire `hoon/common/` tree pulls them in regardless of whether your kernel reaches them, and the unsatisfied `/dat/` references show up as the misleading "no panic!" silent-fail (RM2 seed-A.md DOC-GAP-1 RECUR). vesl-core's `.dev/DOGFOOD.md` slim-cp recipe ships the canonical strip list. Pair the slim-cp with `nockup graft lint hoon/app/app.hoon` (RM2 §1.1 transitive-imports) to surface any further unsatisfied edges before hoonc runs.

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

**`sig-verify-schnorr` requires the cheetah curve jets registered.** Without them each verify takes seconds-to-minutes — effectively unusable. The scaffold default already wires them in; if you've stripped the dep or the `&[]` hot-state, restore both edits:

```toml
# Cargo.toml [dependencies]
zkvm-jetpack = { path = "../../nockchain/crates/zkvm-jetpack" }
```

```rust
use zkvm_jetpack::hot::produce_prover_hot_state;
let mut app: NockApp =
    boot::setup(&kernel, cli, &produce_prover_hot_state(), "my-app", None).await?;
```

This is cheetah-curve-specific. `set-membership-verify`, `manifest-verify`, and `bounded-value-verify` verify in milliseconds without jets.

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

### Operator triage: distinguishing denial paths

A write that doesn't land surfaces as a typed [`vesl_core::PokeOutcome`](crates/vesl-core/src/poke.rs) — match on the variant to identify the denial path without scraping stderr.

| Denial path | Where it fires | `PokeOutcome` variant | Effect list | Recovery |
|---|---|---|---|---|
| Gate clean-deny | Verify-gate returns `%.n` (e.g. `set-membership-verify` rejects, `sig-verify-schnorr` finds an invalid signature). settle-graft catches the `%.n` and emits a typed `%settle-denied` effect. | `Rejected { reason: GateDenied { reason, raw_effects } }` | `[%settle-denied reason=@t]` | The cause was rejected by policy; user must re-submit with valid input. The `reason` cord identifies which gate denied. |
| Gate crash | Gate panicked inside `mule`; settle-graft wraps the crash. | `Rejected { reason: KernelError { cord, raw_effects } }` (cord = `'settle-graft: verify gate crashed'`) | `[%settle-error msg='settle-graft: verify gate crashed']` | The gate has a bug; investigate the gate body or the data shape. |
| Pre-gate failure | Replay (note-id reused), root mismatch, unregistered hull, malformed payload, capacity. | `Rejected { reason: KernelError { cord, raw_effects } }` | `[%settle-error msg='<reason>']` | Pre-gate guard rejected the poke; check note-id uniqueness, registered-root match, or payload shape per the cord. |
| Rbac denial | Hull-side: `[%rbac-has-perm pubkey perm ~]` peek returned `%.n`; the poke is never sent to the kernel. Enabled when `[rbac] enabled = true` is set in the hull's TOML config. | `Rejected { reason: RbacDenied { pubkey, perm } }` | (none — never reaches the kernel) | The acting pubkey lacks the required perm; grant first or reject the request. HTTP 403 from `/commit` and `/settle`. |

**Multi-graft caveat.** In kernels with ≥10 grafts, a Hoon `?>` crash (e.g. from a custom graft that still uses the pre-typed-denial pattern) emits a `mule`-trace large enough to terminate the hull process. The typed `%settle-denied` path does not crash and is safe to continue against; treat any remaining `?>`-based deny as terminal for the kernel session and restart.

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

### Inspecting a kernel from the outside

Once a kernel is compiled, you don't always want to write a Rust hull to ask "what's the current value of state X?" — `vesl-test` ships a CLI bin that boots an `out.jam` and runs a peek for you.

```bash
# keyless: [%log-len ~]
vesl-test inspect peek out.jam --path-tag log-len

# hull-keyed: [%settle-registered hull=1 ~]
vesl-test inspect peek out.jam --path-tag settle-registered --hull 1

# cord-keyed: [%kv-value @t %greeting ~]
vesl-test inspect peek out.jam --path-tag kv-value --key greeting

# stable JSON for downstream tooling
vesl-test inspect peek out.jam --path-tag log-len --json
```

Output reports one of three states per peek:
- **unrecognized** — the kernel's `++peek` arm returned bare `~`. Either the path is malformed or the graft owning that tag isn't composed.
- **present-but-empty** — `[~ ~]`. Path is recognized; no value at that key.
- **present** — `[~ [~ value]]`. Value renders as a recursive cell tree; atoms show as both Hoon-style decimal-with-dots and (when LE bytes form printable UTF-8) ASCII.

Hoon-literal path parsing (`[%kv-value @t %my-key]` directly) is out of scope for the v1 cut. The `--path-tag` + `--hull`/`--key` form covers every peek shape the v0.1 grafts use; richer paths land when a real consumer needs them.

#### `watch` — REPL-style live-trace tool

`inspect peek` is one-shot. When you need to see the kernel reacting to a sequence of pokes — what cause came in, what effects went out, which slogs fired — `vesl-test watch <out.jam>` is the redis-cli MONITOR analog. It boots the kernel, runs `app.run()` in the background, subscribes to its `effect_broadcast`, and prints one structured row per kernel event while reading poke/peek commands from stdin.

```bash
# interactive: type pokes at the prompt, watch effects render below
vesl-test watch out.jam

# pipe a script of pokes from another terminal
cat pokes.txt | vesl-test watch out.jam --json

# only show events whose cause is settle-register
vesl-test watch out.jam --filter cause=settle-register
```

**Stdin grammar.** One command per line:

| Command | Meaning |
|---------|---------|
| `poke-tag <tag>` | Tag-only poke (`[%<tag> ~]`). |
| `poke-jam <hex> [tag=<name>]` | Pre-jammed cause noun (hex-encoded). The optional `tag=` annotation lets the rendered row carry a meaningful `cause_tag`; without it the cause shows as `poke-jam`. Pair with `vesl_test::watch::jam_slab` + `hex_encode` from a Rust hull to round-trip pokes built with `vesl-core` poke-builders. |
| `peek-tag <tag>` | Keyless peek (`[%<tag> ~]`). |
| `peek-hull <tag> <decimal>` | Hull-keyed peek (`[%<tag> hull ~]`). |
| `peek-key <tag> <string>` | Cord-keyed peek (`[%<tag> %key ~]`). |
| `state` | Heartbeat — current event count + jam path. |
| `quit` \| `exit` | Clean shutdown. |
| `# anything` | Comment. Blank lines are ignored. |

**Output (default human).** One row per command:

```
watch: subscribed to out.jam (filter: none)
[#1] cause=settle-register ack=ack effects=[settle-registered]
[#2] cause=settle-register ack=ack effects=[settle-registered]
[#3] cause=settle-register ack=ack effects=[settle-registered]
```

**Output (`--json`).** One JSON object per line. Schema:

```jsonc
{ "kind": "heartbeat", "jam": "<path>", "filter": null }
{
  "event_num": 1,
  "wall_clock": 1746715723.488,     // unix seconds, fractional
  "cause_tag": "settle-register",   // from stdin command (poke-tag <tag>) or `tag=` annotation on poke-jam
  "ack": "ack",                     // "ack" | "nack" | "error"
  "err": null,                      // crown-error string if ack="error"
  "effect_tags": ["settle-registered"], // head-tags of every NounSlab on the broadcast within --effect-window-ms
  "slogs": [],                      // [{kind:"invalid-cause"|"other", ...}]
  "peek": null                      // only on peek-* commands: "present" | "absent"
}
{ "event_num": 4, "kind": "kernel-died", "reason": "kernel task panicked: ..." }
```

**Latency.** After each poke acks, `watch` drains the broadcast for `--effect-window-ms` (default 100 ms) before rendering. The kernel emits effects asynchronously from a spawned task post-ack, so the window is the floor on visible-event latency. Bump it if a slow kernel emits effects late, drop it for sharper render cadence on a hot machine.

**Filter.** `--filter cause=<tag>` keeps only events whose cause matches the stdin command's tag (we know it pre-poke). `--filter effect=<tag>` keeps only events whose effect-list includes `<tag>` (we know it post-broadcast). No filter emits everything.

**Kernel-died.** When the spawned `app.run()` task panics or returns an error, watch prints a `kernel-died: <reason>` row instead of itself crashing — see RM4 round.md HARD-BUG-1 for the surface this is built to diagnose.

**When you'd reach for `watch` over `inspect peek`:** any time you can't tell from the bare poke return whether the kernel saw what you sent. The two HARD-BUGs in RM4 (registry-del crash + post-resume effect-loss) both presented as opaque return values from the hull side; with `watch` running next door, the cause is on the wire and the effect-list is structured.

## Troubleshooting

**`nockup graft inject` reports `warning — markers not found: imports, state, ...`**
You edited `app.hoon` without the marker comments, or a marker is mistyped. A marker comment is `::` followed by one or more spaces, then `nockup:<name>`.

**`nockup graft inject` errors with `unknown graft: <name>`**
`--grafts <csv>` names a graft whose `.toml` isn't in `--lib-dir`. Check `nockup graft list` to see what's installed. Auto-discovery (bare invocation) won't produce this error — it just picks what's there.

**`hoonc` exits 0 but no `out.jam`**
Type error in the kernel. Most common cause: your `effect` type is narrower than the union the grafted arms produce. Use `+$  effect  *` unless you've explicitly constrained it.

**`hoonc` fails with `mint-lost` / `-lost %<tag>` on a multi-graft compose**
The composed `?-` over `-.u.act` isn't exhaustive. Usually this means one of the graft manifests is stale — re-install the vesl graft package (or re-run `sync.sh` in a dev checkout) to pick up the latest arm set. If the missing tag is `%settle-rotate-epoch`, your manifest predates the C-01 remediation that removed it; re-sync.

**`hoonc` fails with `missing dependency /jams/constraints-0-1.jam`**
Forge-graft pulls in the STARK prover tree, which depends on pre-jammed constraint tables. Copy `hoon/dat/` and `hoon/jams/` from `vesl-nockup/` into your project to satisfy the dependency.

**`cargo build` fails on `ibig` with "expected `UBig`, found `ibig::ubig::UBig`"**
vesl-core's transitive `vesl-signing` dep declares `ibig = "0.3"` from crates.io, while vesl-core's signing module uses the nockchain-vendored `ibig` — same upstream (tczajka/ibig-rs v0.3.6), but Cargo treats path-dep and crates.io as distinct, producing two `UBig` types in the dep graph. If you skipped Step 1's `[patch.crates-io] ibig` block, add it now. Same path as the git-patch line: `ibig = { path = "…/nockchain/crates/nockvm/rust/ibig" }`.

**`Number is greater than DIRECT_MAX` panic**
A `u64` you're feeding into `D()` has its top bit set. Use `nock_noun_rs::atom_from_u64(alloc, value)` instead of `D(value)` for hashed IDs. All vesl-core pokes already route hull-ids through `atom_from_u64` internally.

**`%settle-note` returns no effects, stderr shows `DETERMINISTIC error mote=Exit`**
The verify-gate returned `%.n`. The `?>` in `lib/settle-graft.hoon`'s `%settle-note` arm crashes on gate failure by design — a rejected payload must remain an unprovable STARK state rather than an emitted error. From the Rust side, `app.poke(...).await` resolves `Ok(effects)` with `effects.len() == 0`; treat that as a gate rejection and inspect stderr for the trace. The most common cause is committing multiple leaves with the default single-leaf hash-gate (see Step 6's *Why a single-leaf commit?* note).

**Poke resolves `Ok(vec![])` and stderr shows `slog: invalid cause [%<tag> ...] (full: <noun>)`**
The hull emitted a cause-tag the kernel's `+$ cause` union doesn't accept, so `(soft cause)` returned `~` and the wrapper short-circuited before any arm ran. The diagnostic prints at the default tracing level (priority 1) — no `RUST_LOG=trace` needed. The bracketed `[%<tag> ...]` is the cord-decoded head of the rejected cause; the trailing `(full: <noun>)` is the complete cause cell for advanced inspection. If the head shows `%unknown`, the cause noun was either an atom or a cell whose head is itself a cell — both are malformed shapes for `[%tag args...]` causes. Common causes: typo in the hull-side bytestring; kernel rename without a corresponding hull update; new graft installed but the kernel hasn't been re-composed via `nockup graft inject --apply`. To catch this at compile time, see *Step 6 → Hull/kernel drift detection*.

**Peek returns `~` on what looks like a valid path**
Settle-graft's peek paths are **namespaced**: `[%settle-registered hull ~]`, `[%settle-noted note-id ~]`, `[%settle-root hull ~]`, `[%settle-epoch ~]`, `[%settle-count ~]`. Pre-Phase-10 unprefixed forms (`%registered` / `%settled` / `%root` / `%epoch`) and the transitional Phase-10 `%vesl-*` forms are both retired — Phase 12A landed `%settle-*` as the final naming. Rust callers going through `vesl-core` are unaffected; the builders construct pokes, not peek paths.

**`out.jam` changed but `nockup graft inject` reported nothing**
A comment-only or whitespace edit in a transitively-parsed `.hoon` library (anything under `hoon/lib/`, including helpers like `domain-patterns.hoon` that no marker imports directly) can shift `out.jam` even when `nockup graft inject`'s per-graft summary reports `injected 0/N; skipped` across the board. The cause is hoonc-side, not `nockup graft inject` — something position-sensitive in the source (likely span metadata) bleeds into the jammed output. `nockup graft inject` is **manifest-keyed**: it re-injects only when a `<graft>.toml` digest changes, so library `.hoon` edits slip past it. If you need byte-stable `out.jam`, treat any `.hoon` edit as material — bump the corresponding `.toml`'s body to force a re-inject pass — even if you intended only a comment.

**`nockup graft inject` (or `update`) errors with `manifest schema too new`**
The graft library in `hoon/lib/` declares a `schema_version` newer than your installed `nockup-graft` understands. The composer refuses rather than mis-compose a schema it can't model. Update the binary: `cargo install --git https://github.com/zkvesl/vesl-nockup --bin nockup-graft --force`, then re-run.

**`cargo build` prints `cargo:warning=doctor: ...` lines**
The `vesl` scaffold's `build.rs` runs `nockup graft doctor` on every build. Each `doctor:` line is a project-health finding — a schema-version skew, a Cargo `[patch]` inconsistency, a hand-edited graft block, or a missing `nockup:load-defaults` marker. They never fail the build; run `nockup graft doctor hoon/app/app.hoon` for the full report with remediation detail.

## Reference

- Marker source-of-truth: `tools/graft-inject/src/marker.rs` (`Marker::ALL` + `label()`); the composer is split across `lib.rs` (entry), `manifest.rs`, `gates.rs`, `inject.rs`, `codegen.rs`, `lint.rs`, `cli.rs`, `util.rs`
- Manifest schema: `docs/graft-manifest.md`
- Hoon grafts + manifests: `hoon/lib/{settle,mint,guard,forge}-graft.{hoon,toml}`
- Merkle primitives: `hoon/lib/vesl-merkle.hoon`
- STARK prover / lower (forge deps): `hoon/lib/vesl-prover.hoon`, `hoon/lib/vesl-lower.hoon`
- Rust SDK (upstream, consumed as a dep): `<vesl>/crates/vesl-core/src/`
  - Poke builders: `graft_pokes/{settle,mint,guard,forge}.rs`
- Test harness: `test/vesl-test/src/lib.rs`
- Integration tests: `tools/graft-inject/tests/{mint_lifecycle,guard_lifecycle,forge_compile,integration}.rs`
- Test scaffolding: `tools/graft-inject/tests/fixtures/mod.rs`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the canonical-path table (which files live here vs. in vesl-core / vesl-wallet) and the PR-landing flow. Editing a synced path will fail CI's `sync-verify`; check the table before opening a PR.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
