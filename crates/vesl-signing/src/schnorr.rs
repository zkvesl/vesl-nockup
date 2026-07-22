//! Schnorr-over-Cheetah signing and verification, matching the Hoon
//! reference at `hoon/common/ztd/three.hoon#+schnorr:cheetah`.
//!
//! Wire format of a signature is two 256-bit scalars (`chal`, `sig`),
//! each exported as eight little-endian 32-bit chunks (see
//! [`SchnorrSignatureJson`], gated on feature `json`). This mirrors the
//! Hoon `t8` type used by the chain-side verifier.

use ibig::UBig;
use thiserror::Error;

use crate::math::belt::Belt;
use crate::math::cheetah::{ch_add, ch_neg, ch_scal_big, A_GEN, F6_ZERO};
// Re-export the public-key types so downstream consumers (e.g.,
// x402-nockchain-crypto's `signer.rs` / `verifier.rs`, vesl-core's
// signing shim) can name them without reaching into `pub(crate) mod
// math`. `F6lt` is needed alongside `CheetahPoint` so shim crates
// can construct points from raw coordinate Belts (matching the
// `CheetahPoint { x: F6lt(...), y: F6lt(...), inf }` literal form).
//
// `G_ORDER` and `trunc_g_order` are re-exported so the vesl-wallet HD
// layer (or any other consumer that derives Cheetah scalars from a
// hash transcript) can reduce arbitrary digest output into a valid
// scalar without re-vendoring the curve constants.
pub use crate::math::cheetah::{trunc_g_order, CheetahError, CheetahPoint, F6lt, G_ORDER};
use crate::math::tip5::hash_varlen;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SchnorrError {
    #[error("private key must be in [1, G_ORDER)")]
    BadPrivateKey,
    #[error("challenge or signature out of range")]
    OutOfRange,
    #[error("signature does not verify")]
    BadSignature,
    #[error("curve error: {0}")]
    Curve(#[from] CheetahError),
    #[error("scalar chunk exceeds u32: {0}")]
    ChunkOverflow(u64),
    #[error("scalar chunk {0} is not a decimal integer")]
    BadChunk(usize),
    #[error("base58 pubkey decode failed: {0}")]
    BadPubkey(String),
}

// ---------------------------------------------------------------------------
// Wire types (feature = "json")
// ---------------------------------------------------------------------------

#[cfg(feature = "json")]
mod wire {
    use serde::{Deserialize, Serialize};

    /// JSON encoding of a Schnorr-over-Cheetah signature together with
    /// the signer's public key. Shape per x402-nockchain
    /// `05-payment-payload.md §5.3.1`.
    ///
    /// `schnorr.chal` and `schnorr.sig` are exactly 8 Belt (base-field)
    /// values, transported as decimal strings to preserve u64 precision
    /// across JSON parsers.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SchnorrSignatureJson {
        /// Base58-encoded Schnorr (Cheetah) public key of the signer.
        pub pubkey: String,
        /// Challenge + signature, each 8 Belt values as decimal strings.
        pub schnorr: SchnorrPair,
    }

    /// Challenge / signature scalar pair: each is 8 little-endian 32-bit
    /// chunks of a 256-bit scalar, transported as decimal strings.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SchnorrPair {
        /// Challenge hash — 8 Belt values as decimal strings.
        pub chal: [String; 8],
        /// Signature scalar — 8 Belt values as decimal strings.
        pub sig: [String; 8],
    }
}

#[cfg(feature = "json")]
pub use wire::{SchnorrPair, SchnorrSignatureJson};

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Schnorr private key: a scalar in `[1, G_ORDER)`.
///
/// AUDIT 2026-05-20 M-13: the scalar is an `ibig::UBig` (heap bignum, no
/// `Zeroize` impl) — it is *not* wiped on drop. Cleanly zeroizing it needs
/// a byte-backed key representation (`Zeroizing<[u8; 32]>` materialized to
/// `UBig` transiently); that refactor was deferred. The root 64-byte seed
/// and the BIP-39 mnemonic these descend from ARE zeroized.
#[derive(Clone)]
pub struct SchnorrPrivateKey(UBig);

// AUDIT 2026-05-20 M-12: redact the raw scalar. A derived Debug would
// print the secret key verbatim through any `{:?}` (e.g. a stray
// `tracing::debug!`), so the impl is hand-written to never touch it.
impl std::fmt::Debug for SchnorrPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SchnorrPrivateKey(<redacted>)")
    }
}

impl SchnorrPrivateKey {
    pub fn new(scalar: UBig) -> Result<Self, SchnorrError> {
        if scalar == UBig::from(0u64) || scalar >= *G_ORDER {
            return Err(SchnorrError::BadPrivateKey);
        }
        Ok(Self(scalar))
    }

    /// Derive from 8 little-endian 32-bit chunks (Hoon `t8` layout).
    pub fn from_t8(chunks: &[u32; 8]) -> Result<Self, SchnorrError> {
        let mut n = UBig::from(0u64);
        for (i, c) in chunks.iter().enumerate() {
            n += UBig::from(*c) << (32 * i);
        }
        Self::new(n)
    }

    /// Derive from 8 [`Belt`] values in the same little-endian 32-bit
    /// chunked layout. Each `Belt`'s low 32 bits are taken as one chunk;
    /// upper bits are silently discarded (callers MUST supply values that
    /// already fit in u32, matching the Hoon `t8` invariant). Used by
    /// `vesl-core`'s signing shim that bridges between
    /// `nockchain-math::Belt` and vesl-signing's `Belt`.
    pub fn from_belts(belts: &[Belt; 8]) -> Result<Self, SchnorrError> {
        let chunks: [u32; 8] = std::array::from_fn(|i| belts[i].0 as u32);
        Self::from_t8(&chunks)
    }

    /// Canonical 8 × 32-bit little-endian chunks. Leading zero chunks are
    /// preserved so the output is always exactly 8 long.
    pub fn to_t8(&self) -> [u32; 8] {
        scalar_to_t8(&self.0)
    }

    /// Like [`Self::to_t8`] but returns each chunk wrapped in a [`Belt`].
    /// Mirror of [`Self::from_belts`] for shim consumers.
    pub fn to_belts(&self) -> [Belt; 8] {
        let chunks = self.to_t8();
        std::array::from_fn(|i| Belt(chunks[i] as u64))
    }

    /// The public key `sk · G`.
    ///
    /// AUDIT 2026-05-21 L-26: fallible rather than `.expect()`-panicking.
    /// `ch_scal_big` cannot fail for a valid scalar against the fixed
    /// generator, but returning a `Result` keeps a future change to the
    /// curve constants from turning into a panic.
    pub fn public_key(&self) -> Result<CheetahPoint, SchnorrError> {
        Ok(ch_scal_big(&self.0, &A_GEN)?)
    }

    pub(crate) fn scalar(&self) -> &UBig {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Signature wire ↔ scalar conversion
// ---------------------------------------------------------------------------

pub(crate) fn scalar_to_t8(n: &UBig) -> [u32; 8] {
    let mask = UBig::from(u32::MAX);
    std::array::from_fn(|i| {
        let chunk = (n >> (32 * i)) & &mask;
        u32::try_from(&chunk).unwrap_or(0)
    })
}

#[cfg(feature = "json")]
pub(crate) fn t8_to_scalar(chunks: &[String; 8]) -> Result<UBig, SchnorrError> {
    let mut n = UBig::from(0u64);
    for (i, s) in chunks.iter().enumerate() {
        let v: u64 = s.parse().map_err(|_| SchnorrError::BadChunk(i))?;
        if v > u32::MAX as u64 {
            return Err(SchnorrError::ChunkOverflow(v));
        }
        n += UBig::from(v) << (32 * i);
    }
    Ok(n)
}

#[cfg(feature = "json")]
pub(crate) fn t8_chunks_to_decimal(chunks: &[u32; 8]) -> [String; 8] {
    std::array::from_fn(|i| chunks[i].to_string())
}

/// Decode a wire-format `SchnorrSignatureJson` to `(pubkey, chal, sig)`.
#[cfg(feature = "json")]
pub fn decode_signature(
    sig: &SchnorrSignatureJson,
) -> Result<(CheetahPoint, UBig, UBig), SchnorrError> {
    let pk = CheetahPoint::from_base58(&sig.pubkey)
        .map_err(|e| SchnorrError::BadPubkey(e.to_string()))?;
    let chal = t8_to_scalar(&sig.schnorr.chal)?;
    let sigv = t8_to_scalar(&sig.schnorr.sig)?;
    Ok((pk, chal, sigv))
}

/// Encode `(pubkey, chal, sig)` into the wire form. `pubkey` must be
/// non-identity (we never sign with the infinity point).
#[cfg(feature = "json")]
pub fn encode_signature(
    pubkey: &CheetahPoint,
    chal: &UBig,
    sig: &UBig,
) -> Result<SchnorrSignatureJson, SchnorrError> {
    let pubkey_b58 = pubkey
        .into_base58()
        .map_err(|e| SchnorrError::BadPubkey(e.to_string()))?;
    Ok(SchnorrSignatureJson {
        pubkey: pubkey_b58,
        schnorr: SchnorrPair {
            chal: t8_chunks_to_decimal(&scalar_to_t8(chal)),
            sig: t8_chunks_to_decimal(&scalar_to_t8(sig)),
        },
    })
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

fn f6_to_belts(f: &crate::math::cheetah::F6lt) -> [Belt; 6] {
    f.0
}

/// Signs a 5-Belt digest `m` with `sk`, producing `(chal, sig)` matching
/// the Hoon `sign:affine:schnorr` flow: the nonce is derived
/// deterministically from the transcript `[pk.x | pk.y | m | sk_t8]`
/// (RFC6979-style).
pub fn schnorr_sign(sk: &SchnorrPrivateKey, m: &[Belt; 5]) -> Result<(UBig, UBig), SchnorrError> {
    let pk = sk.public_key()?;
    let sk_chunks = sk.to_t8();

    // Deterministic nonce = trunc_g_order(hash_varlen(pk.x | pk.y | m | sk_t8)).
    let mut transcript: Vec<Belt> = Vec::with_capacity(6 + 6 + 5 + 8);
    transcript.extend_from_slice(&f6_to_belts(&pk.x));
    transcript.extend_from_slice(&f6_to_belts(&pk.y));
    transcript.extend_from_slice(m);
    for c in sk_chunks.iter() {
        transcript.push(Belt(*c as u64));
    }
    let nonce_hash = hash_varlen(&mut transcript);
    let nonce = trunc_g_order(&nonce_hash);
    if nonce == UBig::from(0u64) {
        return Err(SchnorrError::BadPrivateKey);
    }

    let scalar_point = ch_scal_big(&nonce, &A_GEN)?;

    let mut pre_image: Vec<Belt> = Vec::with_capacity(6 + 6 + 6 + 6 + 5);
    pre_image.extend_from_slice(&f6_to_belts(&scalar_point.x));
    pre_image.extend_from_slice(&f6_to_belts(&scalar_point.y));
    pre_image.extend_from_slice(&f6_to_belts(&pk.x));
    pre_image.extend_from_slice(&f6_to_belts(&pk.y));
    pre_image.extend_from_slice(m);
    let chal_hash = hash_varlen(&mut pre_image);
    let chal = trunc_g_order(&chal_hash);
    if chal == UBig::from(0u64) {
        return Err(SchnorrError::BadSignature);
    }

    let sig = (&nonce + &chal * sk.scalar()) % &*G_ORDER;
    if sig == UBig::from(0u64) {
        return Err(SchnorrError::BadSignature);
    }
    Ok((chal, sig))
}

/// Verifies a Schnorr signature against the 5-Belt digest `m` using
/// exactly the algorithm from the Hoon reference.
pub fn schnorr_verify(
    pubkey: &CheetahPoint,
    m: &[Belt; 5],
    chal: &UBig,
    sig: &UBig,
) -> Result<(), SchnorrError> {
    // AUDIT 2026-05-19 H-14: reject an off-curve pubkey before any curve
    // arithmetic. A caller that builds a CheetahPoint from raw F6
    // coordinates (bypassing decode_signature's in_curve check) would
    // otherwise get a soundness-broken "valid" result.
    if !pubkey.in_curve() {
        return Err(SchnorrError::BadSignature);
    }
    let zero = UBig::from(0u64);
    if chal <= &zero || chal >= &*G_ORDER {
        return Err(SchnorrError::OutOfRange);
    }
    if sig <= &zero || sig >= &*G_ORDER {
        return Err(SchnorrError::OutOfRange);
    }

    let left = ch_scal_big(sig, &A_GEN)?;
    let right = ch_neg(&ch_scal_big(chal, pubkey)?);
    let scalar = ch_add(&left, &right)?;
    if scalar.x == F6_ZERO {
        return Err(SchnorrError::BadSignature);
    }

    let mut pre_image: Vec<Belt> = Vec::with_capacity(6 + 6 + 6 + 6 + 5);
    pre_image.extend_from_slice(&f6_to_belts(&scalar.x));
    pre_image.extend_from_slice(&f6_to_belts(&scalar.y));
    pre_image.extend_from_slice(&f6_to_belts(&pubkey.x));
    pre_image.extend_from_slice(&f6_to_belts(&pubkey.y));
    pre_image.extend_from_slice(m);
    let hash = hash_varlen(&mut pre_image);
    let expected = trunc_g_order(&hash);

    if expected == *chal {
        Ok(())
    } else {
        Err(SchnorrError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sk() -> SchnorrPrivateKey {
        SchnorrPrivateKey::new(UBig::from(123_456_789u64)).unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let (c, s) = schnorr_sign(&sk, &m).unwrap();
        schnorr_verify(&pk, &m, &c, &s).unwrap();
    }

    #[test]
    fn tampered_digest_rejected() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let m2 = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(6)];
        let (c, s) = schnorr_sign(&sk, &m).unwrap();
        assert!(schnorr_verify(&pk, &m2, &c, &s).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let (c, s) = schnorr_sign(&sk, &m).unwrap();
        let bad = &s + UBig::from(1u64);
        assert!(schnorr_verify(&pk, &m, &c, &bad).is_err());
    }

    #[test]
    fn determinism() {
        let sk = test_sk();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let (c1, s1) = schnorr_sign(&sk, &m).unwrap();
        let (c2, s2) = schnorr_sign(&sk, &m).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(s1, s2);
    }

    #[cfg(feature = "json")]
    #[test]
    fn t8_roundtrip() {
        let s = UBig::from(0x0123_4567_89ab_cdef_u64);
        let chunks = scalar_to_t8(&s);
        let decimal: [String; 8] = t8_chunks_to_decimal(&chunks);
        let back = t8_to_scalar(&decimal).unwrap();
        assert_eq!(back, s);
    }

    #[cfg(feature = "json")]
    #[test]
    fn big_scalar_t8_roundtrip() {
        // Near the top of G_ORDER — exercise all 8 chunks.
        let s = &*G_ORDER - UBig::from(42u64);
        let chunks = scalar_to_t8(&s);
        let decimal: [String; 8] = t8_chunks_to_decimal(&chunks);
        assert_eq!(t8_to_scalar(&decimal).unwrap(), s);
    }

    #[test]
    fn from_belts_roundtrips_through_to_belts() {
        let sk = test_sk();
        let belts = sk.to_belts();
        let sk2 = SchnorrPrivateKey::from_belts(&belts).unwrap();
        assert_eq!(sk.scalar(), sk2.scalar());
    }

    #[test]
    fn from_belts_rejects_zero_scalar() {
        let belts = [Belt(0); 8];
        assert!(matches!(
            SchnorrPrivateKey::from_belts(&belts),
            Err(SchnorrError::BadPrivateKey),
        ));
    }
}
