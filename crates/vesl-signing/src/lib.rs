//! `vesl-signing` — Schnorr-over-Cheetah signing, Tip5 domain separators,
//! SIWN (CAIP-122). The foundation primitive of the `vesl-wallet`
//! workspace; usable independently by any consumer that needs
//! Schnorr-over-Cheetah signing without a wallet (hardware-wallet
//! vendors, light-clients, oracle services, trust-anchor signed
//! statements).
//!
//! ## API tiers
//!
//! - **Low-level**: [`schnorr`] — `SchnorrPrivateKey`, `schnorr_sign`,
//!   `schnorr_verify`. The raw signing primitive.
//! - **Mid-level**: [`domain`] — reserved Tip5 domain-separator constants
//!   and helpers (`tip5_with_domain`, `hash_canonical`).
//!   [`replay_cache`] — nonce-deduplication trait + in-memory impl.
//! - **High-level**: [`caip122`] (feature `siwn`) — Sign-In-With-Nockchain
//!   per CAIP-122; `SiwnSigner`, `verify`, `VerifiedIdentity`.
//! - **Prelude**: [`prelude`] — curated subset for downstream crates that
//!   need raw `Belt` access (for example x402-nockchain-crypto's
//!   `sign_message.rs` or vesl-core's signing shim).
//!
//! ## Math substrate
//!
//! The Goldilocks `Belt`, Tip5 sponge hash, F6 sextic extension, and Cheetah
//! curve primitives are vendored under [`math`] (private to the crate) and
//! tested for parity with `nockchain-math`. This makes vesl-signing
//! adoptable without a Nockchain monorepo checkout — see the README for
//! the architectural rationale.

pub mod domain;
pub mod prelude;
pub mod replay_cache;
pub mod schnorr;

#[cfg(feature = "siwn")]
pub mod caip122;

pub(crate) mod math;

// Convenience re-exports — the most-used surface for consumers.
pub use domain::domain_separators;
pub use schnorr::{schnorr_sign, schnorr_verify, SchnorrError, SchnorrPrivateKey};
