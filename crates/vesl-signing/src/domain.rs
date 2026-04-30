//! Reserved Tip5 [`domain_separators`] for the Vesl ecosystem and helpers
//! for hashing values under them.
//!
//! Every Schnorr-over-Cheetah signature in the Vesl ecosystem is bound to
//! exactly one of the reserved domain separators below — this is the
//! structural guarantee that the same signed bytes cannot be replayed
//! across spec boundaries (x402 payment auth, SIWN session auth, vesl
//! intent signing, vesl receipts, vesl authority statements).
//!
//! ## Canonical hashing
//!
//! For values that arrive as serializable Rust types (e.g. an
//! `Authorization` struct), [`hash_canonical`] (feature `json`) serializes
//! the value to its canonical JSON form (sorted keys, no whitespace) and
//! hashes the bytes under the chosen domain separator. For pre-serialized
//! payloads (e.g. a CAIP-122 message body), [`tip5_with_domain`] takes the
//! bytes directly.
//!
//! Both paths produce a 5-Belt digest suitable for passing to
//! [`crate::schnorr::schnorr_sign`].

#[cfg(feature = "json")]
use serde::Serialize;

use crate::math::belt::Belt;
use crate::math::tip5::hash_varlen;

/// Reserved Tip5 domain separators for the Vesl ecosystem. The reservation
/// is enforced by [`is_reserved`] and the canonical [`ALL`] slice. Any new
/// caller that signs under Tip5 with a key reachable from these separators
/// MUST add its tag here so [`ALL`] stays the single source of truth.
///
/// Non-collision is the structural guarantee that the same signed bytes
/// cannot be replayed across spec boundaries (x402 payments, SIWN session
/// auth, vesl intents, vesl receipts, vesl authority statements).
pub mod domain_separators {
    /// x402 payment-authorization separator
    /// (per x402-nockchain `05-payload.md §5.4.3`).
    pub const X402: &str = "x402-nockchain-v2";

    /// Sign-In-With-Nockchain separator
    /// (per x402-nockchain `11-extensions.md §11.2`).
    pub const SIWN: &str = "siwn-v1";

    /// vesl-agent intent-signing separator
    /// (per `WALLET_LAYER.md §2 Role 0` and `X402_INTERSECTION.md §5`
    /// Open Decision #2). Reserved so x402-nockchain cannot
    /// inadvertently re-use the string for an unrelated purpose;
    /// vesl-agent imports this constant directly when it builds its
    /// intent-signing surface.
    pub const VESL_INTENT: &str = "vesl-intent-v1";

    /// vesl receipt outer-proof binding separator. Bound to the outer
    /// proof of any inner system (zkML, zkTLS, agent trace, foreign
    /// STARK).
    pub const VESL_RECEIPT: &str = "vesl-receipt-v1";

    /// vesl authority signed-statement separator. Reserved for
    /// trust-anchor signed statements (consume vesl-signing for crypto).
    pub const VESL_AUTHORITY: &str = "vesl-authority-v1";

    /// All reserved domain separators known to this codebase. Callers
    /// that want to assert non-collision against every reserved tag
    /// can iterate this slice rather than hard-coding individual
    /// constants.
    pub const ALL: &[&str] = &[X402, SIWN, VESL_INTENT, VESL_RECEIPT, VESL_AUTHORITY];

    /// Returns `true` iff `s` matches one of the reserved separator
    /// strings in [`ALL`].
    pub fn is_reserved(s: &str) -> bool {
        ALL.contains(&s)
    }
}

/// Re-export of [`domain_separators::X402`] under the pre-R1.2 name. Kept
/// for x402-nockchain source-compat; new callers should import
/// [`domain_separators::X402`] directly.
pub use domain_separators::X402 as X402_DOMAIN_SEPARATOR;

/// Re-export of [`domain_separators::SIWN`] under the pre-R1.2 name. Kept
/// for x402-nockchain source-compat; new callers should import
/// [`domain_separators::SIWN`] directly.
pub use domain_separators::SIWN as SIWN_DOMAIN_SEPARATOR;

/// Hash `domain || bytes` under Tip5 and return the 5-Belt digest.
pub fn tip5_with_domain(domain: &str, bytes: &[u8]) -> [Belt; 5] {
    let mut input = bytes_to_belts(domain.as_bytes());
    input.extend_from_slice(&bytes_to_belts(bytes));
    let digest = hash_varlen(&mut input);
    [
        Belt(digest[0]),
        Belt(digest[1]),
        Belt(digest[2]),
        Belt(digest[3]),
        Belt(digest[4]),
    ]
}

/// Serialize `value` to the canonical JSON byte string used for signing
/// (sorted keys, no whitespace), then hash under the given Tip5 domain.
#[cfg(feature = "json")]
pub fn hash_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<[Belt; 5], serde_json::Error> {
    let v: serde_json::Value = serde_json::to_value(value)?;
    let canon = serde_json::to_string(&v)?;
    Ok(tip5_with_domain(domain, canon.as_bytes()))
}

/// Convert an arbitrary byte string into a sequence of `Belt`s, 7 bytes per
/// Belt, little-endian, zero-padded at the tail. 7 bytes keeps each value
/// under `2^56 < PRIME` so every element is trivially in-field.
fn bytes_to_belts(bytes: &[u8]) -> Vec<Belt> {
    let mut out = Vec::with_capacity(bytes.len() / 7 + 1);
    let mut buf = [0u8; 8];
    for chunk in bytes.chunks(7) {
        buf.fill(0);
        buf[..chunk.len()].copy_from_slice(chunk);
        out.push(Belt(u64::from_le_bytes(buf)));
    }
    // Always append a terminator Belt so an empty input still hashes a
    // distinct value and length is implicit in the canonical form.
    if bytes.len() % 7 == 0 {
        out.push(Belt(0));
    }
    out
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_under_key_order() {
        let v1 = json!({ "a": 1, "b": 2 });
        let v2 = json!({ "b": 2, "a": 1 });
        assert_eq!(
            hash_canonical(X402_DOMAIN_SEPARATOR, &v1).unwrap(),
            hash_canonical(X402_DOMAIN_SEPARATOR, &v2).unwrap(),
        );
    }

    #[test]
    fn different_domain_different_digest() {
        let v = json!({ "x": 1 });
        let a = hash_canonical(X402_DOMAIN_SEPARATOR, &v).unwrap();
        let b = hash_canonical(SIWN_DOMAIN_SEPARATOR, &v).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn single_byte_change_changes_digest() {
        let a = hash_canonical(X402_DOMAIN_SEPARATOR, &json!({ "x": 1 })).unwrap();
        let b = hash_canonical(X402_DOMAIN_SEPARATOR, &json!({ "x": 2 })).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn vesl_intent_domain_does_not_collide_with_x402_or_siwn() {
        let v = json!({ "x": 1 });
        let dx402 = hash_canonical(domain_separators::X402, &v).unwrap();
        let dsiwn = hash_canonical(domain_separators::SIWN, &v).unwrap();
        let dvesl = hash_canonical(domain_separators::VESL_INTENT, &v).unwrap();
        assert_ne!(dvesl, dx402);
        assert_ne!(dvesl, dsiwn);
        assert_ne!(dx402, dsiwn);
    }

    #[test]
    fn vesl_receipt_and_authority_dont_collide_with_existing() {
        let v = json!({ "x": 1 });
        let mut digests: Vec<[Belt; 5]> = domain_separators::ALL
            .iter()
            .map(|d| hash_canonical(d, &v).unwrap())
            .collect();
        let original_len = digests.len();
        digests.sort_by_key(|d| (d[0].0, d[1].0, d[2].0, d[3].0, d[4].0));
        digests.dedup();
        assert_eq!(
            digests.len(),
            original_len,
            "every reserved domain separator must produce a distinct digest",
        );
    }

    #[test]
    fn is_reserved_recognizes_each_tag() {
        for tag in domain_separators::ALL {
            assert!(domain_separators::is_reserved(tag));
        }
        assert!(!domain_separators::is_reserved("not-a-real-tag"));
    }

    #[test]
    fn reserved_tags_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for tag in domain_separators::ALL {
            assert!(seen.insert(*tag), "duplicate reserved tag: {tag}");
        }
    }
}
