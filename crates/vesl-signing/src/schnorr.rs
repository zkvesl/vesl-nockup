//! Schnorr-over-Cheetah signing and verification, matching the Hoon
//! reference at `hoon/common/ztd/three.hoon#+schnorr:cheetah`.
//!
//! A signature is two 256-bit scalars (`chal`, `sig`) — a
//! [`SchnorrSig`] of two [`Scalar`]s, each eight little-endian 32-bit
//! limbs. The wire form ([`SchnorrSignatureJson`], gated on feature
//! `json`) carries the same limbs as decimal strings. This mirrors the
//! Hoon `t8` type used by the chain-side verifier.

use ibig::UBig;
use thiserror::Error;

use crate::math::belt::Belt;
use crate::math::cheetah::{ch_add, ch_neg, ch_scal_big, A_GEN, F6_ZERO};
pub use crate::scalar::{Scalar, G_ORDER};
// Re-export the public-key types so downstream consumers (e.g.,
// x402-nockchain-crypto's `signer.rs` / `verifier.rs`, vesl-core's
// signing shim) can name them without reaching into `pub(crate) mod
// math`. `F6lt` is needed alongside `CheetahPoint` so shim crates
// can construct points from raw coordinate Belts (matching the
// `CheetahPoint { x: F6lt(...), y: F6lt(...), inf }` literal form).
pub use crate::math::cheetah::{CheetahError, CheetahPoint, F6lt};
use crate::math::tip5::hash_varlen;

/// Reduce an array of at least four `u64` digits (a Tip5 digest) to a
/// scalar mod [`G_ORDER`], exactly as the Hoon `trunc-g-order` does.
/// Only the first four digits are read.
///
/// # Panics
///
/// If `a` holds fewer than four elements.
pub fn trunc_g_order(a: &[u64]) -> Scalar {
    Scalar::from_ubig(&crate::math::cheetah::trunc_g_order(a))
}

/// A Schnorr signature: the challenge `chal` and the response `sig`,
/// both in `[1, G_ORDER)` when produced by [`schnorr_sign`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchnorrSig {
    /// The challenge hash, reduced mod [`G_ORDER`].
    pub chal: Scalar,
    /// The response scalar.
    pub sig: Scalar,
}

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
/// AUDIT 2026-05-20 M-13: the scalar is held internally as an
/// `ibig::UBig` (heap bignum, no `Zeroize` impl) — it is *not* wiped on
/// drop. Cleanly zeroizing it needs a byte-backed key representation
/// (`Zeroizing<[u8; 32]>` materialized to `UBig` transiently); that
/// refactor was deferred. The root 64-byte seed and the BIP-39 mnemonic
/// these descend from ARE zeroized.
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
    /// From a scalar, which must lie in `[1, G_ORDER)`.
    pub fn new(scalar: Scalar) -> Result<Self, SchnorrError> {
        if scalar.is_zero() || scalar >= G_ORDER {
            return Err(SchnorrError::BadPrivateKey);
        }
        Ok(Self(scalar.to_ubig()))
    }

    /// Derive from 8 little-endian 32-bit chunks (Hoon `t8` layout).
    pub fn from_t8(chunks: &[u32; 8]) -> Result<Self, SchnorrError> {
        Self::new(Scalar::from_t8(*chunks))
    }

    /// Derive from 8 [`Belt`] values in the same little-endian 32-bit
    /// chunked layout. Each `Belt`'s low 32 bits are taken as one chunk;
    /// upper bits are silently discarded (callers MUST supply values that
    /// already fit in u32, matching the Hoon `t8` invariant). Used by
    /// `vesl-core`'s signing shim that bridges between
    /// `nockchain-math::Belt` and vesl-signing's `Belt`.
    pub fn from_belts(belts: &[Belt; 8]) -> Result<Self, SchnorrError> {
        Self::new(Scalar::from_belts(belts))
    }

    /// Canonical 8 × 32-bit little-endian chunks. Leading zero chunks are
    /// preserved so the output is always exactly 8 long.
    pub fn to_t8(&self) -> [u32; 8] {
        Scalar::from_ubig(&self.0).to_t8()
    }

    /// Like [`Self::to_t8`] but returns each chunk wrapped in a [`Belt`].
    /// Mirror of [`Self::from_belts`] for shim consumers.
    pub fn to_belts(&self) -> [Belt; 8] {
        Scalar::from_ubig(&self.0).to_belts()
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

#[cfg(feature = "json")]
pub(crate) fn t8_to_scalar(chunks: &[String; 8]) -> Result<Scalar, SchnorrError> {
    let mut limbs = [0u32; 8];
    for (i, s) in chunks.iter().enumerate() {
        let v: u64 = s.parse().map_err(|_| SchnorrError::BadChunk(i))?;
        limbs[i] = u32::try_from(v).map_err(|_| SchnorrError::ChunkOverflow(v))?;
    }
    Ok(Scalar::from_t8(limbs))
}

#[cfg(feature = "json")]
pub(crate) fn t8_chunks_to_decimal(chunks: &[u32; 8]) -> [String; 8] {
    std::array::from_fn(|i| chunks[i].to_string())
}

/// Decode a wire-format `SchnorrSignatureJson` to `(pubkey, signature)`.
#[cfg(feature = "json")]
pub fn decode_signature(
    sig: &SchnorrSignatureJson,
) -> Result<(CheetahPoint, SchnorrSig), SchnorrError> {
    let pk = CheetahPoint::from_base58(&sig.pubkey)
        .map_err(|e| SchnorrError::BadPubkey(e.to_string()))?;
    let chal = t8_to_scalar(&sig.schnorr.chal)?;
    let sigv = t8_to_scalar(&sig.schnorr.sig)?;
    Ok((pk, SchnorrSig { chal, sig: sigv }))
}

/// Encode `(pubkey, signature)` into the wire form. `pubkey` must be
/// non-identity (we never sign with the infinity point).
#[cfg(feature = "json")]
pub fn encode_signature(
    pubkey: &CheetahPoint,
    sig: &SchnorrSig,
) -> Result<SchnorrSignatureJson, SchnorrError> {
    let pubkey_b58 = pubkey
        .into_base58()
        .map_err(|e| SchnorrError::BadPubkey(e.to_string()))?;
    Ok(SchnorrSignatureJson {
        pubkey: pubkey_b58,
        schnorr: SchnorrPair {
            chal: t8_chunks_to_decimal(&sig.chal.to_t8()),
            sig: t8_chunks_to_decimal(&sig.sig.to_t8()),
        },
    })
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

fn f6_to_belts(f: &crate::math::cheetah::F6lt) -> [Belt; 6] {
    f.0
}

/// Signs a 5-Belt digest `m` with `sk`, producing a [`SchnorrSig`] matching
/// the Hoon `sign:affine:schnorr` flow: the nonce is derived
/// deterministically from the transcript `[pk.x | pk.y | m | sk_t8]`
/// (RFC6979-style).
pub fn schnorr_sign(sk: &SchnorrPrivateKey, m: &[Belt; 5]) -> Result<SchnorrSig, SchnorrError> {
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
    let nonce = crate::math::cheetah::trunc_g_order(&nonce_hash);
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
    let chal = crate::math::cheetah::trunc_g_order(&chal_hash);
    if chal == UBig::from(0u64) {
        return Err(SchnorrError::BadSignature);
    }

    let sig = (&nonce + &chal * sk.scalar()) % &*crate::math::cheetah::G_ORDER;
    if sig == UBig::from(0u64) {
        return Err(SchnorrError::BadSignature);
    }
    Ok(SchnorrSig {
        chal: Scalar::from_ubig(&chal),
        sig: Scalar::from_ubig(&sig),
    })
}

/// Verifies a Schnorr signature against the 5-Belt digest `m` using
/// exactly the algorithm from the Hoon reference.
pub fn schnorr_verify(
    pubkey: &CheetahPoint,
    m: &[Belt; 5],
    signature: &SchnorrSig,
) -> Result<(), SchnorrError> {
    // AUDIT 2026-05-19 H-14: reject an off-curve pubkey before any curve
    // arithmetic. A caller that builds a CheetahPoint from raw F6
    // coordinates (bypassing decode_signature's in_curve check) would
    // otherwise get a soundness-broken "valid" result.
    if !pubkey.in_curve() {
        return Err(SchnorrError::BadSignature);
    }
    let chal = &signature.chal.to_ubig();
    let sig = &signature.sig.to_ubig();
    let zero = UBig::from(0u64);
    let g_order = &*crate::math::cheetah::G_ORDER;
    if chal <= &zero || chal >= g_order {
        return Err(SchnorrError::OutOfRange);
    }
    if sig <= &zero || sig >= g_order {
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
    let expected = crate::math::cheetah::trunc_g_order(&hash);

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
        SchnorrPrivateKey::new(Scalar::from_u64(123_456_789)).unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let sig = schnorr_sign(&sk, &m).unwrap();
        schnorr_verify(&pk, &m, &sig).unwrap();
    }

    #[test]
    fn tampered_digest_rejected() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let m2 = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(6)];
        let sig = schnorr_sign(&sk, &m).unwrap();
        assert!(schnorr_verify(&pk, &m2, &sig).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let mut bad = schnorr_sign(&sk, &m).unwrap();
        bad.sig = bad.sig.add_mod_order(&Scalar::from_u64(1));
        assert!(schnorr_verify(&pk, &m, &bad).is_err());
    }

    #[test]
    fn out_of_range_scalars_rejected() {
        let sk = test_sk();
        let pk = sk.public_key().unwrap();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        let good = schnorr_sign(&sk, &m).unwrap();
        for bad in [Scalar::ZERO, G_ORDER, Scalar::from_t8([u32::MAX; 8])] {
            let chal = SchnorrSig { chal: bad, ..good };
            let sig = SchnorrSig { sig: bad, ..good };
            assert!(matches!(
                schnorr_verify(&pk, &m, &chal),
                Err(SchnorrError::OutOfRange)
            ));
            assert!(matches!(
                schnorr_verify(&pk, &m, &sig),
                Err(SchnorrError::OutOfRange)
            ));
        }
    }

    #[test]
    fn determinism() {
        let sk = test_sk();
        let m = [Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)];
        assert_eq!(
            schnorr_sign(&sk, &m).unwrap(),
            schnorr_sign(&sk, &m).unwrap()
        );
    }

    #[test]
    fn private_key_range_is_enforced() {
        assert!(SchnorrPrivateKey::new(Scalar::ZERO).is_err());
        assert!(SchnorrPrivateKey::new(G_ORDER).is_err());
        let top = Scalar::from_ubig(&(&*crate::math::cheetah::G_ORDER - UBig::from(1u64)));
        assert_eq!(SchnorrPrivateKey::new(top).unwrap().to_t8(), top.to_t8());
    }

    #[cfg(feature = "json")]
    #[test]
    fn t8_roundtrip() {
        let s = Scalar::from_u64(0x0123_4567_89ab_cdef);
        let decimal: [String; 8] = t8_chunks_to_decimal(&s.to_t8());
        assert_eq!(t8_to_scalar(&decimal).unwrap(), s);
    }

    #[cfg(feature = "json")]
    #[test]
    fn big_scalar_t8_roundtrip() {
        // Near the top of G_ORDER — exercise all 8 chunks.
        let s = Scalar::from_ubig(&(&*crate::math::cheetah::G_ORDER - UBig::from(42u64)));
        let decimal: [String; 8] = t8_chunks_to_decimal(&s.to_t8());
        assert_eq!(t8_to_scalar(&decimal).unwrap(), s);
    }

    #[cfg(feature = "json")]
    #[test]
    fn t8_rejects_a_limb_wider_than_u32() {
        let mut decimal: [String; 8] = t8_chunks_to_decimal(&[0; 8]);
        decimal[3] = (u32::MAX as u64 + 1).to_string();
        assert!(matches!(
            t8_to_scalar(&decimal),
            Err(SchnorrError::ChunkOverflow(_))
        ));
        decimal[3] = "x".into();
        assert!(matches!(
            t8_to_scalar(&decimal),
            Err(SchnorrError::BadChunk(3))
        ));
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
