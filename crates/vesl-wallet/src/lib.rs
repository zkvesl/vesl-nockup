//! `vesl-wallet` — high-level Hull-author wallet API.
//!
//! Bundles three layers into a single Hull-author surface:
//!
//! 1. **BIP-39 mnemonic <-> seed** via the [`bip39`] crate
//!    (PBKDF2-HMAC-SHA512 per the specification, the one piece that
//!    has to follow BIP-39 verbatim so 12/24-word phrases round-trip
//!    through any compliant implementation).
//! 2. **SLIP-10-over-Cheetah HD derivation**, conforming to nockchain's
//!    own `hoon/common/slip10.hoon` — so the keys this crate derives are
//!    the keys the reference CLI wallet derives from the same phrase.
//!    See [`hd`] for the arm-by-arm correspondence.
//! 3. **BIP-44 layout** from [`vesl_wallet_spec`]: role constants 0-6,
//!    [`DerivationPath`] type, hardening boundary at purpose / coin_type
//!    / account.
//!
//! ## Quick start
//!
//! ```ignore
//! use vesl_signing::prelude::Belt;
//! use vesl_wallet::{VeslWallet, VESL_COIN_TYPE_PLACEHOLDER};
//!
//! let wallet = VeslWallet::from_seed_phrase(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon \
//!      abandon abandon abandon about",
//!     "",
//!     VESL_COIN_TYPE_PLACEHOLDER,
//! )?;
//!
//! let msg = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
//! let (chal, sig) = wallet.sign_intent(0, &msg)?;
//! # Ok::<(), vesl_wallet::WalletError>(())
//! ```
//!
//! ## TOML config-toggle
//!
//! Downstream `vesl-core` exposes a per-role config-toggle pattern: an
//! intent app calls [`VeslWallet::intent_signer`] (role 0), a payment app
//! calls [`VeslWallet::payment_signer`] (role 4); the same code drives
//! different roles based on the TOML wallet section the operator
//! provides at deploy time.
//!
//! [`Tip5`]: vesl_signing::domain
//! [`vesl-hd-v1`]: vesl_signing::domain::domain_separators::VESL_HD
//! [`DerivationPath`]: vesl_wallet_spec::DerivationPath

mod error;
mod hd;
mod wallet;

pub use error::WalletError;
// Re-export the path constants so callers can name everything via
// `vesl_wallet::*` without a second `use vesl_wallet_spec::...` line.
pub use vesl_wallet_spec::{
    DerivationPath, BIP44_PURPOSE, ROLE_ENCRYPTION, ROLE_INTENT, ROLE_RECEIVING, ROLE_SESSION,
    ROLE_VOID, ROLE_WITHDRAWAL, ROLE_X402,
};
pub use wallet::{DerivedKey, VeslWallet};

/// The frozen SLIP-10 conformance vectors. A unit test rather than an
/// integration one because it pins the master key and depth-1 children,
/// which the public API does not expose.
#[cfg(test)]
mod slip10_conformance;

/// Placeholder coin_type for the BIP-44 path's second hardened
/// component. Pending upstream SLIP-44 registration of a Nockchain
/// coin_type assignment, the wallet ships with this sentinel value;
/// callers that want a different coin_type can supply one explicitly to
/// [`VeslWallet::from_seed_phrase`] or [`VeslWallet::from_seed`].
///
/// The chosen value is well outside the SLIP-44 numeric range that
/// upstream is likely to assign to any real chain (the high bit is
/// clear so it's a legitimate u32 coin_type, but the magic suffix
/// `0xC0DE` makes it loud in logs and configs).
pub const VESL_COIN_TYPE_PLACEHOLDER: u32 = 0x7E51_C0DE;
