# Per-role wallet config (TOML config-toggle pattern)

`vesl-core` ships a high-level Hull-author wallet (`VeslWallet`, re-exported from `vesl-core::*`) backed by BIP-39 seed handling and a custom Cheetah-BIP32-over-Tip5 HD derivation tree. The wallet is paired with a `[wallet]` config block in `vesl.toml` so that an intent app and a payment app can run the same Rust code and pick their key role from the operator's config alone.

This document shows the canonical TOML shape and the Rust snippet that consumes it. Drop the TOML into your template's `vesl.toml`; copy the snippet into your settlement bootstrap.

## TOML

```toml
# vesl.toml — settlement + wallet configuration.

settlement_mode  = "dumbnet"
chain_endpoint   = "http://node:9090"

[wallet]
seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# coin_type defaults to vesl_wallet::VESL_COIN_TYPE_PLACEHOLDER until SLIP-44
# upstream registers a Nockchain coin_type. Override here when ready.
coin_type   = 0x7E51_C0DE
# account is the per-agent BIP-44 account index. Most apps stay at 0; multi-agent
# operators bump it per agent identity.
account     = 0

[wallet.intent]
# role defaults to vesl_wallet::ROLE_INTENT (= 0). Override only if you know
# what you are doing — the intent role is reserved for `vesl-intent-v1`-domain
# Schnorr signatures.
role  = 0
index = 0

[wallet.payment]
# role defaults to vesl_wallet::ROLE_X402 (= 4). Reserved for x402 spending keys.
role  = 4
index = 0
```

The seed phrase can also come from the `VESL_SEED_PHRASE` environment variable (CLI override > env > TOML, in that order). CLI overrides for the `account` field are also supported via `SettlementCliOverrides::account`; per-role role/index overrides live in TOML only by design (preventing silent key re-derivation from a stray command-line flag).

## Rust

```rust
use vesl_core::{
    SettlementCliOverrides, SettlementConfig, SettlementMode, SettlementToml,
};

fn run(toml: SettlementToml, cli: SettlementCliOverrides) -> anyhow::Result<()> {
    let cfg = SettlementConfig::resolve_checked(&cli, &toml, /* default_signing_key */ None)
        .map_err(anyhow::Error::msg)?;

    // Same code, different role: an intent-only app calls intent_signer_belts(),
    // a payment-only app calls payment_signer_belts(). Returns Ok(None) when no
    // [wallet] block / seed phrase was supplied.
    let intent_key  = cfg.intent_signer_belts()?;   // m/44'/coin'/account'/0/index
    let payment_key = cfg.payment_signer_belts()?;  // m/44'/coin'/account'/4/index

    if let Some(key) = intent_key {
        // Sign an intent with `vesl_core::sign(key, &message)`.
        let _ = key;
    }
    if let Some(key) = payment_key {
        // Submit a payment-authorized transaction with this key.
        let _ = key;
    }
    Ok(())
}
```

For full control (e.g. to derive a session key at a custom role/index), build the wallet directly from the resolved `WalletConfig`:

```rust
use vesl_core::{DerivationPath, ROLE_SESSION, VeslWallet};

if let Some(w) = cfg.wallet.as_ref() {
    if let Some(wallet) = w.build_wallet()? {
        let session = wallet.derive(DerivationPath::new(
            w.coin_type,
            w.account,
            ROLE_SESSION,
            42,
        ))?;
        let _ = session.private_key;
    }
}
```

## What this guarantees

- A single Rust binary can serve as either an intent app or a payment app — flip a TOML section, redeploy, no recompile.
- Intent and payment keys are cryptographically isolated: even with the same seed phrase + account, `m/44'/coin'/account'/0/0` and `m/44'/coin'/account'/4/0` derive different scalars under the Cheetah-BIP32-over-Tip5 tree, and a signature produced by one role's key does not verify under the other role's pubkey.
- Hardware-wallet portability of the seed: the BIP-39 mnemonic round-trips through any compliant BIP-39 implementation. The HD derivation downstream of the seed is custom (Tip5 instead of HMAC-SHA512) so no off-the-shelf hardware wallet can re-derive the keys today; a future Cheetah-aware hardware wallet would re-implement the same Tip5 transcript.
