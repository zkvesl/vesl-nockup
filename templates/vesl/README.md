# {{project_name}}

A grafted NockApp scaffolded from the `vesl` template.

## Three-command path to a running kernel

```bash
nockup graft inject --apply hoon/app/app.hoon   # composes graft bodies into the kernel
./compile.sh                                    # verified Hoon compile (hoonc + the out.jam check)
cargo +nightly run --release                    # boots the kernel and runs the Demo arm
```

Expected stdout end:

```
  effect: %settle-registered
  effect: %settle-noted
```

## CLI

The scaffolded binary is a clap dispatch over two subcommands. Both
boot the kernel from `out.jam` and pass the booted `NockApp` to the
selected arm.

```bash
cargo +nightly run --release                # Demo arm (default): register a root, settle a note
cargo +nightly run --release -- serve       # Serve arm: HTTP API on http://127.0.0.1:3000
```

### `serve` flags

- `--port <PORT>`  — listen port (default 3000)
- `--bind-addr <ADDR>` — bind address (default `127.0.0.1`; `--no-auth` is refused on non-loopback binds)
- `--no-auth` — disable API-key auth (loopback only; otherwise `HULL_API_KEY` env var is required)

### Endpoint catalog

The Serve arm wires `vesl_hull::serve(...)` which mounts:

- `POST /commit` — commit key-value fields to a Merkle tree + register the root
- `POST /settle` — settle a note against the current root
- `POST /verify` — verify a field's Merkle proof
- `GET  /tx/:tx_id` — fetch a chain-attested receipt (requires fakenet/dumbnet settlement mode)
- `GET  /status`   — current state snapshot (fields, tree, hull-id, note counter, settlement mode, active gate, composed grafts, per-graft manifest sha256s)
- `GET  /health`   — liveness probe (always unauthenticated)

`/status` reads `hoon/lib/` once at boot to surface `gate` / `grafts` / `manifest_shas`. After swapping a gate (`[graft.gates]` in a graft TOML) + re-running `nockup graft inject --apply` + restart, `curl .../status | jq .gate` confirms the new selection.

`/settle` adapts to the active gate. Stock `vesl_hull::settle_handler` dispatches through `vesl_hull::SettlePayloadBuilder`; the binary picks the impl from `manifest.gate` at boot. Two impls ship:

| Gate | Body shape | Notes |
|---|---|---|
| `default-hash` | `{}` (re-mints from `field[0]`) or `{"data": "<hex>"}` | The original default. |
| `manifest-verify` | `{"fields": [{"name": "...", "value": "..."}, ...]}` | Hull re-derives proofs from the committed tree. |

Adding a new catalog-gate impl (schnorr, ed25519, membership, bounded) is a `SettlePayloadBuilder` impl in `crates/vesl-hull/src/settle_builder.rs` plus a `payload_builder_for_gate` match arm. Unknown gates warn and fall back to default-hash.

Source: `vesl-nockup/crates/vesl-hull/src/api.rs`. Mount your own
endpoints by passing them to `vesl_hull::serve_with_extra_routes` (or
`vesl_hull::router_with_extra` if you need the assembled `axum::Router`):

```rust
let my_routes = axum::Router::new()
    .route("/echo", axum::routing::post(my_echo_handler));
vesl_hull::serve_with_extra_routes(state, port, &bind_addr, my_routes).await?;
```

Layers wrap the merged Router uniformly:

- **API-key auth** — bearer-token check against `HULL_API_KEY`; `/health` is exempt.
- **Body-size cap (two-stage, 4 MiB)** — an upfront `Body::size_hint` precheck (413s every known-length body, including wire requests with honest `Content-Length` and in-process `Body::from(Vec<u8>)`) plus tower-http's streaming `RequestBodyLimitLayer` for chunked or unknown-length bodies. A handler that ignores its body still gets the upfront 413 when the size is known.
- **Rate limit** — 200 req / 60 s + 256 buffer; overflow yields 429.

Do **not** use `Router::merge(vesl_hull::router(state), ...)` directly —
axum's flat merge attaches your routes outside the already-applied
layer stack, leaving them unauthenticated and unrate-limited.

## Layout

- `Cargo.toml` — vesl-graft's `[[patches]]` rewrites the deps to git-deps pinned at the synced rev and adds both `[patch]` blocks during `nockup package install`. The pre-patch template ships path-deps as a fallback for sibling-clone workflows or eject mode (`nockup patches eject zkvesl/vesl-graft`).
- `build.rs` — runs the `nockup-graft doctor` project-health pass each build; `out.jam` is built separately by `./compile.sh`.
- `compile.sh` — verified Hoon compile: runs `hoonc` and fails loud if it exits 0 without producing `out.jam`.
- `src/main.rs` — clap CLI: `Demo` arm (register a Merkle root + settle a note) and `Serve` arm (HTTP API via `vesl_hull::serve`).
- `hoon/app/app.hoon` — markered kernel template; `nockup graft inject` composes graft bodies into the `::  nockup:*` anchors.
- `hoon/lib/lib.hoon` — stub `/+ lib` import for your domain library.

## Testing

`vesl-test` ships in `[dev-dependencies]`. Add a `#[tokio::test]` against `vesl_test::GraftTestHarness` to exercise the register / settle / replay lifecycle, or call `vesl-test inspect peek out.jam --path-tag <tag>` for one-shot kernel peeks. See the zkvesl-docs Testing page for the canonical lifecycle test.

## Where to go next

- `vesl-nockup/README.md` — the canonical 6-step tour, including the Customizing section (multi-leaf gates, signed gates, STARK gates) and the state-graft catalog.
- `zkvesl-docs/` — published reference covering the graft manifest schema, peek paths, and the typed effect-union codegen.
