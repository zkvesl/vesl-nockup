//! Vesl wallet derivation spec — BIP44 5-level layout.
//!
//! Canonical role assignments and the typed [`DerivationPath`] holder used
//! by every Vesl-stack key derivation. The normative source is `SPEC.md`
//! at the crate root; this crate ships role-number constants and a typed
//! path holder so downstream crates and Hull authors refer to roles by
//! name rather than magic number.
//!
//! Key derivation lives in `vesl-wallet`. This crate intentionally has
//! no curve, no seed handling, no signing API.
//!
//! ## Path shape
//!
//! ```text
//! m / 44' / <coin_type>' / <agent_account>' / <role> / <index>
//! ```
//!
//! ## Roles
//!
//! - [`ROLE_INTENT`]    (`0`) — long-lived intent signing key
//! - [`ROLE_RECEIVING`] (`1`) — receiving / payout address
//! - [`ROLE_ENCRYPTION`](`2`) — encryption / delivery decryption (placeholder)
//! - [`ROLE_SESSION`]   (`3`) — short-lived delegation / session keys
//! - [`ROLE_X402`]      (`4`) — x402 spending keys
//!
//! Roles `5+` are reserved for future assignments — see `SPEC.md §5`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// BIP44 purpose value (constant per BIP44 spec).
pub const BIP44_PURPOSE: u32 = 44;

/// Role 0 — long-lived intent signing key (Schnorr-over-Cheetah).
///
/// Signs under the `vesl_signing::domain::domain_separators::VESL_INTENT`
/// (`"vesl-intent-v1"`) Tip5 domain separator.
pub const ROLE_INTENT: u32 = 0;

/// Role 1 — receiving / payout address.
pub const ROLE_RECEIVING: u32 = 1;

/// Role 2 — encryption / delivery decryption.
///
/// Placeholder; the encryption primitive is pending the Vesl whitepaper.
/// Reserving the slot keeps the path stable across future encryption-scheme
/// choices.
pub const ROLE_ENCRYPTION: u32 = 2;

/// Role 3 — short-lived delegation / session keys.
///
/// Same Schnorr-over-Cheetah scheme as [`ROLE_INTENT`], derived at a
/// separate path so session-key compromise doesn't expose the role-0 master.
pub const ROLE_SESSION: u32 = 3;

/// Role 4 — x402 spending keys.
///
/// Signs under the `vesl_signing::domain::domain_separators::X402`
/// (`"x402-nockchain-v2"`) Tip5 domain separator.
pub const ROLE_X402: u32 = 4;

/// Typed BIP44 5-level derivation path.
///
/// Holds the four post-purpose components; the purpose is fixed at
/// [`BIP44_PURPOSE`]. No derivation logic lives here — see `vesl-wallet`
/// for HD key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// SLIP-44 coin_type (TBD upstream — see `SPEC.md §4`).
    pub coin_type: u32,
    /// Per-agent account index.
    pub account: u32,
    /// One of the `ROLE_*` constants in this crate.
    pub role: u32,
    /// Rotation / sequence index within the role.
    pub index: u32,
}

impl DerivationPath {
    /// Construct a [`DerivationPath`] from its four post-purpose components.
    pub const fn new(coin_type: u32, account: u32, role: u32, index: u32) -> Self {
        Self {
            coin_type,
            account,
            role,
            index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_constants_are_stable() {
        assert_eq!(BIP44_PURPOSE, 44);
        assert_eq!(ROLE_INTENT, 0);
        assert_eq!(ROLE_RECEIVING, 1);
        assert_eq!(ROLE_ENCRYPTION, 2);
        assert_eq!(ROLE_SESSION, 3);
        assert_eq!(ROLE_X402, 4);
    }

    #[test]
    fn derivation_path_eq_hash() {
        let p = DerivationPath::new(0, 0, ROLE_X402, 0);
        let q = DerivationPath {
            coin_type: 0,
            account: 0,
            role: 4,
            index: 0,
        };
        assert_eq!(p, q);

        // Hash equality follows from Eq + Hash derive contract; smoke-check
        // by inserting both into a HashSet and observing the dedupe.
        use std::collections::HashSet;
        let mut s: HashSet<DerivationPath> = HashSet::new();
        s.insert(p);
        s.insert(q);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn derivation_path_distinct_when_role_differs() {
        let intent = DerivationPath::new(0, 0, ROLE_INTENT, 0);
        let payment = DerivationPath::new(0, 0, ROLE_X402, 0);
        assert_ne!(intent, payment);
    }
}
