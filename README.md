# vesl-nockup

Project scaffold + graft tooling for building NockApps on Vesl. Pairs with `nockup` (the project scaffolder from the [nockchain monorepo](https://github.com/nockchain/nockchain)) to compose verification primitives — mint, guard, settle, forge, plus state and behavior grafts — into a single Hoon kernel that boots inside a Rust hull.

The full walkthrough lives at [docs.zkvesl.org](https://docs.zkvesl.org); project home is [zkvesl.org](https://zkvesl.org). This repo is what `nockup project init` pulls in when you scaffold against the `vesl` template.

## Installation

Five pieces: the nockchain monorepo, the `nockup` scaffolder, `honk` (the Hoon compiler), the pinned Rust nightly, and the `nockup-graft` plugin shipped from here.

1. Clone the nockchain monorepo:

   ```bash
   git clone https://github.com/nockchain/nockchain.git
   ```

   Vesl builds against upstream `master`. The exact SHA is `NOCK_PIN` in [`.github/workflows/ci.yml`](.github/workflows/ci.yml); `scripts/check-pins.sh` keeps every pin site in agreement.

2. Install `nockup` — drops `hoon`, `hoonc`, and `nockup` into `~/.nockup/bin/` and prepends that to `PATH`:

   ```bash
   # Script install
   curl -fsSL https://raw.githubusercontent.com/nockchain/nockchain/refs/heads/master/crates/nockup/install.sh | bash

   # Or build from source
   cd nockchain && cargo install --path crates/nockup --locked
   ```

3. `honk` — the Hoon compiler vesl compiles kernels with:

   ```bash
   cargo install --locked --force --path nockchain/crates/honk --bin honk
   ```

   honk is primary because its output bytes are reproducible from any checkout location. `hoonc` comes along with `nockup` and still works, but it bakes absolute build paths into the JAM, so two machines compiling the same source get different bytes.

   CI pins `HONK_REV` to a `sobchek/nockchain` rev — `master` plus compiler fixes staged pending upstream review. If honk from upstream `master` misreports source paths in an error trace, build it from that rev instead.

4. Rust nightly, pinned to the date nockchain pins:

   ```bash
   rustup toolchain install nightly-2026-04-03
   ```

   Not a floating `nightly` — `nockvm` uses the unstable `core::hint::cold_path()`, so an arbitrary nightly is a build waiting to break.

5. `nockup-graft` — vesl's graft composer, shipped as a `nockup` plugin:

   ```bash
   cargo install --git https://github.com/zkvesl/vesl-nockup --bin nockup-graft
   ```

   Once installed, `nockup graft <subcmd>` resolves the binary via nockup's plugin discovery and dispatches to it.

Verify the toolchain (`honk` takes no `--version`, so this just checks it resolves):

```bash
command -v honk && nockup --help >/dev/null && cargo +nightly-2026-04-03 --version && nockup-graft --version
```

## Quickstart

Four commands from an empty directory to a kernel that emits `%settle-registered` + `%settle-noted`:

```bash
nockup project init                                    # fetches vesl template + zkvesl/vesl-graft
nockup graft inject --apply hoon/app/app.hoon          # composes grafts into the kernel
./compile.sh                                           # honk-compiles the kernel to out.jam
cargo +nightly-2026-04-03 run --release                # boots the kernel
```

The full guide, including the `nockapp.toml` you write before `init`, is at [docs.zkvesl.org/setup/quickstart](https://docs.zkvesl.org/setup/quickstart).

## What's in this repo

- `templates/` — the `vesl` template plus per-graft scaffolds (`graft-scaffold`, `graft-mint`, `graft-settle`, etc.)
- `hoon/lib/` — the shipped graft library
- `crates/` — `vesl-hull` (HTTP server crate) plus a synced bundle of `vesl-core` and `vesl-wallet` crates
- `tools/graft-inject/` — `nockup-graft` source + the harness used by tests
- `test/vesl-test/` — the `vesl-test` CLI for poking compiled kernels

## Documentation

| Where | What |
|---|---|
| [zkvesl.org](https://zkvesl.org) | project home |
| [docs.zkvesl.org](https://docs.zkvesl.org) | full walkthrough — install, scaffold, customize, ship |
| [zkvesl/vesl-core](https://github.com/zkvesl/vesl-core) | protocol kernels + the `vesl-core` SDK |
| [zkvesl/vesl-wallet](https://github.com/zkvesl/vesl-wallet) | signing + wallet crates |
| [nockchain/nockchain](https://github.com/nockchain/nockchain) | nockchain itself + the `nockup` scaffolder |
| [zkvesl/hull-llm](https://github.com/zkvesl/hull-llm) | reference RAG/LLM hull |

## Maintainer

sobchek · <sobchek@zkvesl.org>

## License

Apache-2.0 OR MIT.
