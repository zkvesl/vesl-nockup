//! Error types for `vesl-wallet`.

use thiserror::Error;
use vesl_signing::schnorr::SchnorrError;

/// Errors raised by the wallet API.
#[derive(Debug, Error)]
pub enum WalletError {
    /// The mnemonic could not be parsed as a BIP39 phrase (wrong word count,
    /// invalid checksum, or unknown word in the configured wordlist).
    #[error("invalid BIP39 mnemonic: {0}")]
    InvalidMnemonic(String),

    /// The derived scalar landed outside `[1, G_ORDER)`. With Tip5 this is
    /// cryptographically negligible but we still surface a typed error
    /// rather than panicking; callers can rotate the index and try again.
    #[error("derived scalar is invalid for Cheetah (zero or >= G_ORDER); rotate the path index")]
    InvalidScalar,

    /// The supplied [`vesl_wallet_spec::DerivationPath`] has a non-BIP44
    /// purpose component. The wallet only honours `purpose = 44` (the
    /// BIP-44 standard); other purposes would silently change the meaning
    /// of the role byte.
    #[error("derivation path purpose must be 44 (BIP-44); got {0}")]
    NonBip44Purpose(u32),

    /// A hardened derivation index would overflow a 31-bit integer
    /// (BIP-32 reserves the high bit for the hardening flag).
    #[error("derivation index {0} exceeds 31-bit BIP-32 limit")]
    IndexOverflow(u32),

    /// An HD scalar did not fit the 32-byte big-endian transcript buffer.
    /// Unreachable for any `ExtKey` this crate produces — every scalar is
    /// reduced mod `G_ORDER` (~255 bits) — but surfaced as a typed error,
    /// not a slice-out-of-bounds panic, so a future construction path that
    /// skips the reduction fails loudly. AUDIT 2026-05-21 L-23.
    #[error("HD scalar exceeds the 32-byte transcript width")]
    ScalarTooWide,

    /// Bubbled up from the underlying Schnorr layer (e.g. signing or
    /// verification failure on a derived key).
    #[error(transparent)]
    Signing(#[from] SchnorrError),
}
