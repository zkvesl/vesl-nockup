# {{project_name}}

A grafted NockApp scaffolded from the `vesl` template.

## Three-command path to a running kernel

```bash
nockup graft inject --apply hoon/app/app.hoon   # composes graft bodies into the kernel
hoonc hoon/app/app.hoon hoon/                   # produces out.jam
cargo +nightly run                              # boots the kernel and runs the Demo arm
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
cargo +nightly run                  # Demo arm (default): register a root, settle a note
cargo +nightly run -- serve         # Serve arm: HTTP API on http://127.0.0.1:3000
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
- `GET  /status`   — current state snapshot
- `GET  /health`   — liveness probe (always unauthenticated)

Source: `vesl-nockup/crates/vesl-hull/src/api.rs`. Mount your own
endpoints by passing them to `vesl_hull::serve_with_extra_routes` (or
`vesl_hull::router_with_extra` if you need the assembled `axum::Router`):

```rust
let my_routes = axum::Router::new()
    .route("/echo", axum::routing::post(my_echo_handler));
vesl_hull::serve_with_extra_routes(state, port, &bind_addr, my_routes).await?;
```

Layers (API-key auth, 4 MiB body limit, 200 req / 60 s rate limit + 256
buffer) wrap the merged Router, so they apply uniformly to your custom
routes. Do **not** use `Router::merge(vesl_hull::router(state), ...)`
directly — axum's flat merge attaches your routes outside the
already-applied layer stack, leaving them unauthenticated and
unrate-limited.

## Layout

- `Cargo.toml` — vesl-graft's `[[patches]]` rewrites the deps to git-deps pinned at the synced rev and adds both `[patch]` blocks during `nockup package install`. The pre-patch template ships path-deps as a fallback for sibling-clone workflows or eject mode (`nockup patches eject zkvesl/vesl-graft`).
- `build.rs` — no-op; `out.jam` is built explicitly via `hoonc`.
- `src/main.rs` — clap CLI: `Demo` arm (register a Merkle root + settle a note) and `Serve` arm (HTTP API via `vesl_hull::serve`).
- `hoon/app/app.hoon` — markered kernel template; `nockup graft inject` composes graft bodies into the `::  nockup:*` anchors.
- `hoon/lib/lib.hoon` — stub `/+ lib` import for your domain library.

## Testing

`vesl-test` ships in `[dev-dependencies]`. Add a `#[tokio::test]` against `vesl_test::GraftTestHarness` to exercise the register / settle / replay lifecycle, or call `vesl-test inspect peek out.jam --path-tag <tag>` for one-shot kernel peeks. See the zkvesl-docs Testing page for the canonical lifecycle test.

## Where to go next

- `vesl-nockup/README.md` — the canonical 6-step tour, including the Customizing section (multi-leaf gates, signed gates, STARK gates) and the state-graft catalog.
- `zkvesl-docs/` — published reference covering the graft manifest schema, peek paths, and the typed effect-union codegen.
