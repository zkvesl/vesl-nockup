# vesl-wallet-spec — BIP44 5-level wallet layout

**Status:** v0.1 (held-pre-tag, alongside `vesl-signing` v0.1.0)
**Crate:** `vesl-wallet-spec` (workspace member of [`vesl-wallet`](https://github.com/zkvesl/vesl-wallet))
**Depends on:** [`vesl-signing`](../vesl-signing/) for domain separators
**Closes:** OD#1 (BIP44 layout for x402 — `role=4` reservation)
**Open:** OD#11 (SLIP-44 coin_type registration — see §4)

---

## §1 Path shape

Every Vesl-stack key lives at the canonical BIP44 5-level path:

```
m / 44' / <coin_type>' / <agent_account>' / <role> / <index>
```

| Level | Value | Hardening | Semantics |
|---|---|---|---|
| `purpose'` | `44'` (constant) | hardened | BIP44 marker |
| `coin_type'` | TBD upstream — see §4 | hardened | SLIP-44 coin type |
| `agent_account'` | `0'`, `1'`, … | hardened | Per-agent account; one account = one logical agent identity |
| `role` | `0`–`4` (reserved); `5+` (open) | non-hardened | See §2 |
| `index` | `0`, `1`, … | non-hardened | Rotation / sequence index within a role |

### Hardening MUST hold at the account boundary

Account-level hardening MUST hold (BIP44 standard isolation). Compromise of any child key (signing, encryption, session) cannot derive sibling keys or the account-level xpub. Implementations MUST set the hardened bit (`0x80000000`) on `purpose`, `coin_type`, and `agent_account`.

### One agent = one `agent_account'`

A user running two separate agents (e.g., trading + research) derives them at `m/44'/X'/0'/...` and `m/44'/X'/1'/...` respectively, keeping balances, histories, and compromise blast-radii separate.

---

## §2 Role assignments

### Role 0 — Intent signing

> Scheme: Schnorr over Cheetah, per substrate. Usage: signs the `RawTransaction` that carries the intent publication. This is the canonical "agent authority" key — every published intent traces back to this signer. Lifetime: long — rotated only on compromise or periodic hygiene rotation (multi-month cadence). Storage: user-held.

**Status (2026-05-25): placeholder passthrough.** Upstream intent scripting has not landed yet. The vesl-wallet `sign_intent` accessor is currently a raw Schnorr signer over the role-0 key — it does NOT apply the `VESL_INTENT` domain separator internally. Callers that need cross-protocol separation today MUST hash their payload under `VESL_INTENT` themselves (via `vesl_signing::domain::hash_canonical` or equivalent) before calling `sign_intent`. The path slot is reserved; the binding will become enforceable once the upstream verifier ships.

**Domain separator (reserved):** When upstream intent scripting lands, role-0 intent signatures will use `vesl_signing::domain::domain_separators::VESL_INTENT` (= `"vesl-intent-v1"`). The same role-0 key may also sign x402 payments (`X402` = `"x402-nockchain-v2"`) and SIWN messages (`SIWN` = `"siwn-v1"`); non-overlapping separators are the only thing preventing cross-protocol signature reuse. See §3.

**Rust constant:** `vesl_wallet_spec::ROLE_INTENT = 0`

### Role 1 — Receiving / payout

> Scheme: derives a standard Nockchain address (base58-encoded Cheetah pubkey). Usage: the address users send NOCK to when funding the agent. Also the recipient of bounty refunds when intents expire unfulfilled. Lifetime: long; rotated rarely because it's publicly advertised. Storage: pubkey public, private key needed only for sweeping refunds or consolidating balances.

**Rust constant:** `vesl_wallet_spec::ROLE_RECEIVING = 1`

### Role 2 — Encryption / delivery decryption

> Status: placeholder, pending intent delivery semantics in the Vesl white paper. Usage (if Option-A-style encrypted chain-write becomes the delivery model): publisher-side key that miners encrypt delivered payloads to. Ciphertexts land on-chain; agent decrypts locally.

Reserving `role=2` holds the HD path slot regardless of which encryption primitive lands. Cheetah pubkeys are signing keys, not KEM keys — the encryption scheme is a separate research/protocol-author question (X25519+AES-GCM, ECIES over Cheetah, or a Nockchain-native KEM are candidates).

**Rust constant:** `vesl_wallet_spec::ROLE_ENCRYPTION = 2`

### Role 3 — Delegation / session keys

> Scheme: same Schnorr-over-Cheetah as role 0, derived at a separate path. Usage: runtime-held signing keys for long-running agent processes. The operator can hand a session private key to the agent runtime without exposing the role-0 master. Rotation is cheap — bump index, re-derive, revoke the old. Lifetime: short — hours to days depending on policy. Storage: in-process, encrypted on disk, or in a local keystore.

Compromise of a single session key limits damage to that session's outstanding intents and balance — the role-0 master stays cold.

**Rust constant:** `vesl_wallet_spec::ROLE_SESSION = 3`

### Role 4 — x402 spending keys *(new — closes OD#1)*

x402 payment-authorization spending keys derive at `m/44'/<coin_type>'/<agent_account>'/4/<index>`. This reservation:

- Resolves the structural incompatibility between x402's flat depth-1 layout (`Master / Child(N)-hardened`, per `nockchain/nockchain#102`) and vesl-agent's 5-level path. A user funding both x402 payments and vesl-agent intents from one seed gets unambiguous role separation.
- Preserves the role-separation discipline of roles 0-3 — payment authority is a distinct role, not overloaded onto the intent-signing key.
- Domain-separated: x402 payments MUST sign under `vesl_signing::domain::domain_separators::X402` (= `"x402-nockchain-v2"`), not `VESL_INTENT`. See §3.

x402-nockchain's `NockchainWalletClient` should accept a `DerivationPath` (or equivalent) rather than a raw `[Belt; 8]` scalar — see `x402-nockchain/docs/CURRENT_STATE.md §2 gap #5` ("HD-derivation seam"). This spec ships the constant that consumer wires against.

**Rust constant:** `vesl_wallet_spec::ROLE_X402 = 4`

---

## §3 Domain separator registry

Tip5 domain separators are reserved in [`vesl-signing`](../vesl-signing/). This crate does **not** redefine them — consumers import directly:

```rust
use vesl_signing::domain::domain_separators::{
    X402,            // "x402-nockchain-v2" — x402 payment authorization (role 4 keys)
    SIWN,            // "siwn-v1"          — Sign-In-With-Nockchain
    VESL_INTENT,     // "vesl-intent-v1"   — vesl-agent intent signing (role 0 keys)
    VESL_RECEIPT,    // "vesl-receipt-v1"  — receipt-schema v2 outer-proof binding
    VESL_AUTHORITY,  // "vesl-authority-v1" — trust-anchor signed statements
};
```

Non-collision across these five tags is enforced by `vesl_signing::domain::domain_separators::ALL` and asserted in vesl-signing's test suite. New domain separators MUST be added to that registry — never redefined here.

**Role-to-separator binding (informative):**

| Role | Typical separator(s) |
|---|---|
| 0 (intent) | `VESL_INTENT` |
| 1 (receiving) | n/a — addresses, not signatures |
| 2 (encryption) | n/a — KEM/DEM, not Schnorr |
| 3 (session) | inherits the role-0 separator (`VESL_INTENT`) when signing intents on the operator's behalf |
| 4 (x402) | `X402` |

The same Schnorr-over-Cheetah primitive is reused across roles 0, 3, and 4 — domain separation is what makes them non-fungible.

---

## §4 SLIP-44 coin_type — TBD upstream *(OD#11)*

Nockchain has no assigned [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) coin_type. This spec uses `<coin_type>'` as a symbolic placeholder; the value is **not** fixed by `vesl-wallet-spec`.

### Interim options

Until SLIP-44 assigns a value, implementations may either:

1. **Use an unassigned slot** (e.g., `4919'` — arbitrary, unreserved) and document the choice in their config. Migration follows when SLIP-44 lands.
2. **Use a non-BIP44 purpose prefix** (e.g., Cardano's `1852'` instead of `44'`) signaling "this is not a Bitcoin-descendant wallet." Side-steps SLIP-44 entirely; sacrifices the BIP44 mental model and most BIP44-aware wallet UIs.

### Implementation guidance

- `vesl-wallet` takes `coin_type` as a constructor parameter — it does not hardcode a value. Hull authors set it via `nockup.toml`.
- Hardware-wallet integrations and external consumers SHOULD coordinate on a single interim value to avoid fragmentation. A coordination thread is open against Nockchain maintainers — see OD#11 ("SLIP-44 coin_type for Nockchain").

### Follow-up

OD#11 tracks the coordination work to:
- File a SLIP-44 PR upstream against `satoshilabs/slips` claiming a coin_type for Nockchain.
- Once assigned, mint a `vesl-wallet-spec` amendment specifying the canonical value.
- Communicate migration guidance to any consumers using interim values.

---

## §5 Roles 5+

Roles `5` and above are explicitly **open** for future assignments. Future amendments to this spec mint new role assignments rather than redefining existing ones (see §6). Candidate future uses include threshold-Schnorr signing keys, additional encryption schemes, on-chain-delegation authority keys (when Nockchain adds account-abstraction primitives), and oracle-attestation keys.

Implementations MUST NOT use roles 5+ until this spec assigns them, to avoid silent collisions across consumers.

---

## §6 Versioning policy

This spec follows BIP-style amendment conventions:

- **Breaking changes** mint new role assignments at currently-unreserved slots. Existing role assignments (roles 0-4) are **not** retroactively edited.
- **Non-breaking clarifications** (typo fixes, expanded prose, new examples) ship as in-place edits and are reflected in the crate's `CHANGELOG.md`.
- **The Rust constant set is append-only.** New roles add new `pub const ROLE_*` constants; no constant value ever changes once shipped.

The crate version (`vesl-wallet-spec` package version in `Cargo.toml`) tracks documentation revisions and any additive Rust-surface changes. The first published version will be `v0.1.0`, minted alongside `vesl-signing` v0.1.0 once end-to-end verification across `vesl-wallet` / `vesl-core` / `vesl-nockup` / `x402-nockchain` completes.

---

## Cross-references

- [`vesl-signing::domain::domain_separators`](../vesl-signing/src/domain.rs) — reserved Tip5 domain separators (single source of truth).
- `x402-nockchain/docs/CURRENT_STATE.md §2 gap #5` — HD-derivation seam consuming `ROLE_X402`.
- OD#1 (closed by this spec) and OD#11 (open SLIP-44 coordination) are tracked in the maintainers' decisions log.
