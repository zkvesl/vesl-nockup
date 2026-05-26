# Security Policy

## Reporting a Vulnerability

If you find a security issue in vesl-nockup — anything in the CLI
tools (`nockup-graft`, `vesl-test`), the supply-chain machinery
(`sync.sh`, `scripts/`, `.github/workflows/`), the HTTP hull library
(`crates/vesl-hull`), or any shipped template — please report it
privately via GitHub Security Advisories:

**[github.com/zkvesl/vesl-nockup/security/advisories/new](https://github.com/zkvesl/vesl-nockup/security/advisories/new)**

Do **not** open a public issue, post to chat, or otherwise disclose
the finding before a fix is shipped. We will coordinate disclosure
with you once a fix is ready.

## In scope

- Supply-chain integrity (`sync.sh` rewrites, pinned upstream SHAs,
  the vesl-core ↔ vesl-nockup mirror gate)
- CLI safety (`nockup-graft inject`, `doctor`, `rename-kernel`,
  `lint`, `update`; `vesl-test`)
- Template `build.rs` — anything that gives a malicious binary on
  PATH the ability to hijack `cargo build` or substitute kernel JAMs
- vesl-hull HTTP surface — rate limiting, body-size caps, signing
  paths, RBAC pre-checks, replay protection, TLS / loopback gating
- The mirrored copies of `vesl-core` and `vesl-wallet` crates under
  `crates/` (note: source-of-truth fixes land in the sibling repos
  first, then propagate here via `sync.sh`)

## Out of scope

- Bugs in upstream nockchain (report to `nockchain/nockchain` directly)
- Vulnerabilities in unmodified `vesl-core` / `vesl-wallet` code —
  please report at the source repos:
  - [vesl-core](https://github.com/zkvesl/vesl-core/security/advisories/new)
  - [vesl-wallet](https://github.com/zkvesl/vesl-wallet/security/advisories/new)
- Style, documentation, or non-security correctness bugs — use the
  regular issue tracker

## Supported versions

The `dev` branch HEAD is the only supported surface today. After the
public beta tag lands, see the Releases page for the supported
version line.

## Acknowledgements

Security researchers who follow responsible disclosure are credited
by name in `CHANGELOG.md` and the corresponding GitHub Release notes,
unless they prefer anonymity.
