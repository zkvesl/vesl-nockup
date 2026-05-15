//! Pure-Rust hierarchical-deterministic derivation over the Cheetah
//! curve, parameterised by the [`VESL_HD`] Tip5 domain separator.
//!
//! This is a custom BIP32 analog. The shape mirrors BIP32 (master + chain
//! code, hardened and non-hardened child key derivation), but the
//! pseudo-random function is Tip5 instead of HMAC-SHA512, the scalar
//! field is Cheetah's `G_ORDER` (≈ 255 bits) instead of secp256k1's
//! curve order, and the key-add step uses ibig over `G_ORDER` instead
//! of secp256k1's group law.
//!
//! ## Why Tip5 (not HMAC-SHA512)
//!
//! - **STARK compatibility**: a future receipt that proves "this
//!   signature came from a key derived from a known seed under known
//!   account hierarchy" is practical with Tip5 (effectively free in a
//!   Nockchain trace) and impractical with HMAC-SHA512 (~10⁴-10⁵
//!   constraints per block in Plonky2). This is the dominant
//!   consideration.
//! - **Hardware-wallet portability** is preserved at the layer that
//!   matters: BIP-39 mnemonics stay standard, so a 12/24-word phrase
//!   round-trips through any compliant BIP-39 implementation. A future
//!   Cheetah-aware hardware wallet must already implement Tip5 for
//!   signing; using Tip5 for derivation too means one primitive in
//!   firmware, not two.
//!
//! ## Output expansion
//!
//! BIP32 splits one 64-byte HMAC-SHA512 output into a 32-byte tweak +
//! 32-byte chain code. Tip5 yields five 64-bit Belts (40 bytes), too
//! narrow for that split, so we use two domain-separated Tip5 calls (one
//! for the scalar tweak, one for the chain code) keyed on
//! [`VESL_HD`] + an inner subdomain literal. The inner subdomains
//! never overlap with [`vesl_signing::domain::domain_separators::ALL`].
//!
//! [`VESL_HD`]: vesl_signing::domain::domain_separators::VESL_HD

use ibig::UBig;
use vesl_signing::domain::{domain_separators, tip5_with_domain};
use vesl_signing::prelude::Belt;
use vesl_signing::schnorr::{trunc_g_order, CheetahPoint, SchnorrPrivateKey, G_ORDER};

use crate::error::WalletError;

/// 32-byte chain code carried alongside a derived scalar. Matches
/// BIP-32's chain-code width so the construction reads naturally; the
/// 32-byte input width is also a comfortable fit for a Tip5 transcript
/// (4 × 8-byte Belts).
pub(crate) type ChainCode = [u8; 32];

/// Inner subdomain prepended to the tweak hash input. Together with the
/// outer [`VESL_HD`] separator this gives a unique transcript per
/// hashing role; chain-code transcripts use a different inner literal so
/// the two outputs are independent.
const SUBDOMAIN_TWEAK: &[u8] = b"vesl-hd:tweak\x00";
/// Inner subdomain for chain-code expansion.
const SUBDOMAIN_CHAIN_CODE: &[u8] = b"vesl-hd:cc\x00";
/// Inner subdomain for the master-key derivation transcript.
const SUBDOMAIN_MASTER: &[u8] = b"vesl-hd:master\x00";
/// Hardened-CKD discriminator byte (BIP-32 prepends `0x00` before the
/// parent private key for hardened derivation; we keep the same shape
/// for transcript clarity).
const TAG_HARDENED: u8 = 0x00;
/// Non-hardened-CKD discriminator byte.
const TAG_NON_HARDENED: u8 = 0x01;

/// Derived material: a Cheetah scalar and the chain code that lets the
/// wallet derive its children.
#[derive(Clone, Debug)]
pub(crate) struct ExtKey {
    pub(crate) scalar: UBig,
    pub(crate) chain_code: ChainCode,
}

impl ExtKey {
    pub(crate) fn private_key(&self) -> Result<SchnorrPrivateKey, WalletError> {
        SchnorrPrivateKey::new(self.scalar.clone()).map_err(WalletError::Signing)
    }
}

/// Derive the master extended key from a 64-byte BIP-39 seed.
pub(crate) fn master_from_seed(seed: &[u8; 64]) -> Result<ExtKey, WalletError> {
    let mut transcript = Vec::with_capacity(SUBDOMAIN_MASTER.len() + seed.len());
    transcript.extend_from_slice(SUBDOMAIN_MASTER);
    transcript.extend_from_slice(seed);

    let scalar = scalar_from_transcript(&transcript)?;
    let chain_code = chain_code_from_transcript(&transcript);
    Ok(ExtKey { scalar, chain_code })
}

/// Hardened child-key derivation. The parent's *private* scalar is fed
/// into the transcript so non-hardened siblings cannot be recovered from
/// a leaked extended public key.
pub(crate) fn ckd_hardened(parent: &ExtKey, index: u32) -> Result<ExtKey, WalletError> {
    if index >= 1u32 << 31 {
        return Err(WalletError::IndexOverflow(index));
    }
    let hardened_index = index | (1u32 << 31);
    let mut transcript = Vec::with_capacity(1 + 32 + 32 + 4);
    transcript.push(TAG_HARDENED);
    transcript.extend_from_slice(&parent.chain_code);
    transcript.extend_from_slice(&ubig_to_be_32(&parent.scalar));
    transcript.extend_from_slice(&hardened_index.to_be_bytes());

    let tweak = scalar_from_transcript(&transcript)?;
    let child_scalar = (&parent.scalar + &tweak) % &*G_ORDER;
    if child_scalar == UBig::from(0u64) {
        return Err(WalletError::InvalidScalar);
    }
    let chain_code = chain_code_from_transcript(&transcript);
    Ok(ExtKey {
        scalar: child_scalar,
        chain_code,
    })
}

/// Non-hardened child-key derivation. The parent's *public* point is
/// fed into the transcript instead of the private scalar.
pub(crate) fn ckd_non_hardened(parent: &ExtKey, index: u32) -> Result<ExtKey, WalletError> {
    if index >= 1u32 << 31 {
        return Err(WalletError::IndexOverflow(index));
    }
    let parent_sk = SchnorrPrivateKey::new(parent.scalar.clone())?;
    let parent_pk = parent_sk.public_key();

    let mut transcript = Vec::with_capacity(1 + 32 + 97 + 4);
    transcript.push(TAG_NON_HARDENED);
    transcript.extend_from_slice(&parent.chain_code);
    transcript.extend_from_slice(&serialize_point(&parent_pk));
    transcript.extend_from_slice(&index.to_be_bytes());

    let tweak = scalar_from_transcript(&transcript)?;
    let child_scalar = (&parent.scalar + &tweak) % &*G_ORDER;
    if child_scalar == UBig::from(0u64) {
        return Err(WalletError::InvalidScalar);
    }
    let chain_code = chain_code_from_transcript(&transcript);
    Ok(ExtKey {
        scalar: child_scalar,
        chain_code,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Hash the transcript under the tweak subdomain and reduce to a
/// non-zero scalar in `[1, G_ORDER)`. Returns
/// [`WalletError::InvalidScalar`] when the reduction lands at zero
/// (cryptographically negligible with Tip5 + a 255-bit modulus).
fn scalar_from_transcript(transcript: &[u8]) -> Result<UBig, WalletError> {
    let mut input = Vec::with_capacity(SUBDOMAIN_TWEAK.len() + transcript.len());
    input.extend_from_slice(SUBDOMAIN_TWEAK);
    input.extend_from_slice(transcript);
    let belts = tip5_with_domain(domain_separators::VESL_HD, &input);
    let digits = belts_to_digits(&belts);
    let scalar = trunc_g_order(&digits);
    if scalar == UBig::from(0u64) {
        Err(WalletError::InvalidScalar)
    } else {
        Ok(scalar)
    }
}

/// Hash the transcript under the chain-code subdomain and pack the
/// first four output Belts (32 bytes) into a chain code.
fn chain_code_from_transcript(transcript: &[u8]) -> ChainCode {
    let mut input = Vec::with_capacity(SUBDOMAIN_CHAIN_CODE.len() + transcript.len());
    input.extend_from_slice(SUBDOMAIN_CHAIN_CODE);
    input.extend_from_slice(transcript);
    let belts = tip5_with_domain(domain_separators::VESL_HD, &input);
    chain_code_from_belts(&belts)
}

fn belts_to_digits(belts: &[Belt; 5]) -> [u64; 5] {
    [belts[0].0, belts[1].0, belts[2].0, belts[3].0, belts[4].0]
}

fn chain_code_from_belts(belts: &[Belt; 5]) -> ChainCode {
    let mut out = [0u8; 32];
    for (i, b) in belts.iter().take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&b.0.to_le_bytes());
    }
    out
}

/// Big-endian 32-byte encoding of a `UBig` in `[0, G_ORDER)`. `G_ORDER`
/// is ~255 bits so a 32-byte buffer always fits with the most-significant
/// byte clear.
fn ubig_to_be_32(n: &UBig) -> [u8; 32] {
    let bytes = n.to_be_bytes();
    let mut out = [0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    out[offset..offset + bytes.len()].copy_from_slice(&bytes);
    out
}

/// Deterministic byte serialization of a Cheetah point: 6 × 8-byte
/// little-endian Belts for `x`, then 6 × 8-byte for `y`, then a 1-byte
/// `inf` flag. 97 bytes total. Used only as PRF input — never on the
/// wire — so the serialization just needs to be a bijection.
pub(crate) fn serialize_point(p: &CheetahPoint) -> [u8; 97] {
    let mut out = [0u8; 97];
    for (i, b) in p.x.0.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&b.0.to_le_bytes());
    }
    for (i, b) in p.y.0.iter().enumerate() {
        out[48 + i * 8..48 + (i + 1) * 8].copy_from_slice(&b.0.to_le_bytes());
    }
    out[96] = u8::from(p.inf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 64] {
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        seed
    }

    #[test]
    fn master_is_deterministic() {
        let m1 = master_from_seed(&fixed_seed()).unwrap();
        let m2 = master_from_seed(&fixed_seed()).unwrap();
        assert_eq!(m1.scalar, m2.scalar);
        assert_eq!(m1.chain_code, m2.chain_code);
    }

    #[test]
    fn master_distinct_seeds_distinct_keys() {
        let seed_a = fixed_seed();
        let mut seed_b = fixed_seed();
        seed_b[63] ^= 0xFF;
        let a = master_from_seed(&seed_a).unwrap();
        let b = master_from_seed(&seed_b).unwrap();
        assert_ne!(a.scalar, b.scalar);
        assert_ne!(a.chain_code, b.chain_code);
    }

    #[test]
    fn master_scalar_is_in_field() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        assert!(m.scalar > UBig::from(0u64));
        assert!(m.scalar < *G_ORDER);
    }

    #[test]
    fn hardened_changes_with_index() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        let c0 = ckd_hardened(&m, 0).unwrap();
        let c1 = ckd_hardened(&m, 1).unwrap();
        assert_ne!(c0.scalar, c1.scalar);
        assert_ne!(c0.chain_code, c1.chain_code);
    }

    #[test]
    fn hardened_versus_non_hardened_differ() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        let h = ckd_hardened(&m, 0).unwrap();
        let n = ckd_non_hardened(&m, 0).unwrap();
        assert_ne!(h.scalar, n.scalar);
    }

    #[test]
    fn hardened_index_overflow_rejected() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        match ckd_hardened(&m, 1u32 << 31) {
            Err(WalletError::IndexOverflow(_)) => {}
            other => panic!("expected IndexOverflow, got {other:?}"),
        }
    }

    #[test]
    fn ckd_is_deterministic() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        let a = ckd_hardened(&m, 7).unwrap();
        let b = ckd_hardened(&m, 7).unwrap();
        assert_eq!(a.scalar, b.scalar);
        assert_eq!(a.chain_code, b.chain_code);
    }
}
