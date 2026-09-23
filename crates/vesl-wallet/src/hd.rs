//! SLIP-10 hierarchical-deterministic derivation over the Cheetah curve,
//! conforming to Nockchain's own consensus implementation.
//!
//! ## What this conforms to, and why that is the bar
//!
//! Nockchain ships SLIP-10 over Cheetah in its consensus tree
//! (`nockchain/hoon/common/slip10.hoon`), and its reference CLI wallet
//! derives through it (`hoon/apps/wallet/lib/s10.hoon:41`). So the bar is
//! not "agree with some third-party wallet" — it is **agree with the
//! chain's own key derivation**, which is what makes an address we derive
//! the same address the reference wallet derives from the same seed
//! phrase. Every arm below cites the upstream line it transcribes:
//!
//! | this file | upstream |
//! |---|---|
//! | [`master_from_seed`] | `+from-seed`, `slip10.hoon:59-77` |
//! | [`ckd_hardened`] | `+derive-private` hardened branch, `:153` |
//! | [`ckd_non_hardened`] | `+derive-private` normal branch, `:155` |
//! | the retry loop | `:162-181` |
//! | [`ser_a_pt`] | `+ser-a-pt`, `ztd/three.hoon:1723-1735` |
//! | `DOMAIN_SEPARATOR` | `++domain-separator`, `:38` |
//!
//! ## The retry loop is the common case, not a corner
//!
//! A derived 256-bit value is invalid when it is >= the curve order. That
//! order is **255 bits** (`ztd/three.hoon:1496`), so
//! `P(retry) = 1 - n/2^256` = **0,5197** — it fires on more than half of
//! all derivation steps, and a five-level BIP-44 path avoids it entirely
//! only 2,6 % of the time. It is therefore load-bearing rather than
//! defensive, and the conformance KAT deliberately pins a vector that
//! takes one (`tests/slip10_conformance.rs`).
//!
//! ## One deliberate divergence from upstream, unreachable
//!
//! `+from-seed` tests only `?: (lth left n)` (`slip10.hoon:70`), so it
//! would ACCEPT a zero master key; the SLIP-10 specification and iris
//! (`iris-crypto/src/slip10.rs:95`) both reject it. We follow the
//! specification. The two behaviours differ only on an event of
//! probability 2^-256, i.e. never observably — recorded here rather than
//! left silent, so a future reader does not rediscover it as a defect.
//!
//! ## History
//!
//! This replaced a custom BIP32 analog that used Tip5 as the PRF. That
//! construction's stated advantage was proving key derivation in-circuit;
//! the in-circuit signature was retired as redundant, which removed the
//! only argument for diverging from consensus code.

use hmac::{Hmac, Mac};
use ibig::UBig;
use sha2::Sha512;
use vesl_signing::schnorr::{CheetahPoint, SchnorrPrivateKey, G_ORDER};

use crate::error::WalletError;

/// 32-byte chain code carried alongside a derived scalar — SLIP-10's
/// `I_R`, the right half of each HMAC-SHA512 output.
pub(crate) type ChainCode = [u8; 32];

/// The HMAC key for master derivation: `++domain-separator`,
/// `slip10.hoon:38`, whose Hoon cord `'dees niahckcoN'` is these 14 bytes.
/// Byte-identical to iris's `iris-crypto/src/slip10.rs:89`.
const DOMAIN_SEPARATOR: &[u8] = b"Nockchain seed";

/// Hardened-CKD discriminator: `0x00 || ser256(k_par) || ser32(i)`
/// (`slip10.hoon:153`).
const TAG_HARDENED: u8 = 0x00;
/// Retry discriminator: `0x01 || I_R || ser32(i)` (`slip10.hoon:176`).
/// Also the leading byte of [`ser_a_pt`], where it is upstream's
/// most-significant `rep` block rather than a tag.
const TAG_RETRY: u8 = 0x01;

/// Derived material: a Cheetah scalar and the chain code that lets the
/// wallet derive its children.
///
/// AUDIT 2026-05-20 M-13: not zeroized on drop — `scalar` is an
/// `ibig::UBig` with no `Zeroize` impl, so this UBig-containing struct
/// cannot be cleanly `ZeroizeOnDrop` (see `SchnorrPrivateKey`). The root
/// seed and mnemonic, the secrets these descend from, ARE zeroized.
#[derive(Clone)]
pub(crate) struct ExtKey {
    pub(crate) scalar: UBig,
    pub(crate) chain_code: ChainCode,
}

// AUDIT 2026-05-20 M-12: redact — both fields (the extended private
// scalar and the chain code) are secret key material; a derived Debug
// would print them through any `{:?}`.
impl std::fmt::Debug for ExtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtKey { <redacted> }")
    }
}

impl ExtKey {
    pub(crate) fn private_key(&self) -> Result<SchnorrPrivateKey, WalletError> {
        SchnorrPrivateKey::new(self.scalar.clone()).map_err(WalletError::Signing)
    }
}

/// Derive the master extended key from a 64-byte BIP-39 seed.
///
/// `+from-seed`, `slip10.hoon:59-77`. Upstream seeds this from a BIP-39
/// mnemonic with an **empty** passphrase (`apps/wallet/lib/s10.hoon:22`);
/// producing that seed is the caller's job (`VeslWallet::from_seed_phrase`).
pub(crate) fn master_from_seed(seed: &[u8; 64]) -> Result<ExtKey, WalletError> {
    let mut digest = hmac_sha512(DOMAIN_SEPARATOR, seed);
    loop {
        let (left, chain_code) = split(&digest);
        // The `!= 0` half is the specification's, not upstream's — see the
        // module docs. Unreachable either way at 2^-256.
        if left < *G_ORDER && left != UBig::from(0u8) {
            return Ok(ExtKey {
                scalar: left,
                chain_code,
            });
        }
        // `:72` — re-hash the whole DERIVED digest under the separator.
        digest = hmac_sha512(DOMAIN_SEPARATOR, &digest);
    }
}

/// Hardened child-key derivation. The parent's *private* scalar is fed
/// into the transcript so non-hardened siblings cannot be recovered from
/// a leaked extended public key.
///
/// Takes the **raw** index and sets the hardening bit itself, so callers
/// write `ckd_hardened(&k, 44)` for `44'`. Rejects an index that is
/// already hardened rather than silently deriving somewhere else.
pub(crate) fn ckd_hardened(parent: &ExtKey, index: u32) -> Result<ExtKey, WalletError> {
    if index >= 1u32 << 31 {
        return Err(WalletError::IndexOverflow(index));
    }
    let wire_index = index | (1u32 << 31);
    // `:153` — [37 (can 3 ~[4^i 32^prv 1^0])] == 0x00 || ser256(prv) || ser32(i)
    let mut data = Vec::with_capacity(1 + 32 + 4);
    data.push(TAG_HARDENED);
    data.extend_from_slice(&ser256(&parent.scalar)?);
    data.extend_from_slice(&wire_index.to_be_bytes());
    Ok(ckd(parent, wire_index, &data))
}

/// Non-hardened child-key derivation. The parent's *public* point is fed
/// into the transcript instead of the private scalar.
pub(crate) fn ckd_non_hardened(parent: &ExtKey, index: u32) -> Result<ExtKey, WalletError> {
    if index >= 1u32 << 31 {
        return Err(WalletError::IndexOverflow(index));
    }
    let parent_pk = SchnorrPrivateKey::new(parent.scalar.clone())?.public_key()?;
    // `:155` — [101 (can 3 ~[4^i 97^(ser-p ...)])] == ser-a-pt(pub) || ser32(i)
    let mut data = Vec::with_capacity(97 + 4);
    data.extend_from_slice(&ser_a_pt(&parent_pk));
    data.extend_from_slice(&index.to_be_bytes());
    Ok(ckd(parent, index, &data))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// The shared body of `+derive-private` (`slip10.hoon:156-181`): HMAC the
/// caller's data under the parent chain code, and keep rehashing until the
/// result is a valid key.
///
/// `wire_index` is the index **as it appears on the wire** — with the
/// hardening bit set for a hardened child — because upstream's retry at
/// `:176` re-uses that same value, not the raw index.
///
/// The loop is unbounded, exactly as upstream and the specification are:
/// each round independently succeeds with probability ~0,48, so it
/// terminates with probability 1 after ~2,08 rounds on average.
fn ckd(parent: &ExtKey, wire_index: u32, data: &[u8]) -> ExtKey {
    let mut digest = hmac_sha512(&parent.chain_code, data);
    loop {
        let (left, chain_code) = split(&digest);
        // `:163` — ?: &(!=(0 key) (lth left n))
        if left < *G_ORDER {
            let scalar = (left + &parent.scalar) % &*G_ORDER;
            if scalar != UBig::from(0u8) {
                return ExtKey { scalar, chain_code };
            }
        }
        // `:176` — 0x01 || I_R || ser32(i), keyed on the PARENT chain code.
        let mut retry = Vec::with_capacity(1 + 32 + 4);
        retry.push(TAG_RETRY);
        retry.extend_from_slice(&chain_code);
        retry.extend_from_slice(&wire_index.to_be_bytes());
        digest = hmac_sha512(&parent.chain_code, &retry);
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA512 accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Split an HMAC-SHA512 output into SLIP-10's `I_L` (a big-endian scalar)
/// and `I_R` (the chain code). `slip10.hoon:63-64` does the same with
/// `cut`, where the high 32 bytes of the atom are the digest's first 32.
fn split(digest: &[u8; 64]) -> (UBig, ChainCode) {
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    (UBig::from_be_bytes(&digest[..32]), chain_code)
}

/// SLIP-10's `ser256`: big-endian 32-byte encoding of a scalar in
/// `[0, G_ORDER)`. `G_ORDER` is 255 bits so a 32-byte buffer always fits
/// with the most-significant bit clear.
///
/// AUDIT 2026-05-21 L-23: a `UBig` wider than 32 bytes would panic the
/// `copy_from_slice` below — the `saturating_sub` offset clamps to 0, so
/// the destination slice is shorter than `bytes`. Every `ExtKey` scalar is
/// reduced mod `G_ORDER`, so this is unreachable in practice; return
/// [`WalletError::ScalarTooWide`] rather than panic, for defence in depth.
fn ser256(n: &UBig) -> Result<[u8; 32], WalletError> {
    let bytes = n.to_be_bytes();
    if bytes.len() > 32 {
        return Err(WalletError::ScalarTooWide);
    }
    let mut out = [0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    out[offset..offset + bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

/// Upstream's `+ser-a-pt` (`ztd/three.hoon:1723-1735`) — the point
/// encoding SLIP-10's non-hardened branch hashes (`slip10.hoon:155`).
///
/// Upstream builds it as `(rep 6 ~[x0..x5 y0..y5 1])`, i.e. thirteen
/// 64-bit blocks with `x0` least significant. Read big-endian that is:
///
/// ```text
/// 0x01 || y5 y4 y3 y2 y1 y0 || x5 x4 x3 x2 x1 x0     (97 bytes)
/// ```
///
/// each limb big-endian. The leading `0x01` is upstream's most-significant
/// `rep` block, and is exactly the prefix byte iris pushes before its own
/// 96-byte limb dump (`iris-crypto/src/slip10.rs:39`, `cheetah.rs:139-148`)
/// — the two encodings are byte-identical.
///
/// ⚠️ This is NOT [`serialize_point`], which is a different 97-byte
/// encoding used for an unrelated local fingerprint. Do not substitute one
/// for the other: nothing would fail to compile, and every derived address
/// would silently move.
pub(crate) fn ser_a_pt(p: &CheetahPoint) -> [u8; 97] {
    let mut out = [0u8; 97];
    out[0] = TAG_RETRY;
    let mut offset = 1;
    for belt in p.y.0.iter().rev().chain(p.x.0.iter().rev()) {
        out[offset..offset + 8].copy_from_slice(&belt.0.to_be_bytes());
        offset += 8;
    }
    out
}

/// Deterministic byte serialization of a Cheetah point: 6 × 8-byte
/// little-endian Belts for `x`, then 6 × 8-byte for `y`, then a 1-byte
/// `inf` flag. 97 bytes total.
///
/// ⚠️ This is a purely LOCAL encoding, used only as Tip5 input for
/// `VeslWallet::receiving_fingerprint`'s opaque, chain-agnostic address
/// digest. It is **not** upstream's `ser-a-pt` and has no role in key
/// derivation — for that, see [`ser_a_pt`]. It needs only to be a
/// bijection, so it is deliberately left alone rather than unified.
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
    use vesl_signing::prelude::Belt;
    use vesl_signing::schnorr::F6lt;

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
    fn non_hardened_index_overflow_rejected() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        match ckd_non_hardened(&m, 1u32 << 31) {
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

    /// Every derived scalar must land in `[1, G_ORDER)` — the property the
    /// retry loop exists to guarantee. With P(retry) ~ 0,52 per step, a
    /// sweep this wide takes the retry path hundreds of times, so it also
    /// serves as a liveness check that the loop always terminates.
    #[test]
    fn every_derived_scalar_is_a_valid_key() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        for i in 0..64u32 {
            for k in [ckd_hardened(&m, i).unwrap(), ckd_non_hardened(&m, i).unwrap()] {
                assert!(k.scalar > UBig::from(0u64), "scalar 0 at index {i}");
                assert!(k.scalar < *G_ORDER, "scalar >= G_ORDER at index {i}");
            }
        }
    }

    /// `ser_a_pt` is upstream's encoding; `serialize_point` is our local
    /// one. Confusing them compiles cleanly and moves every address, so
    /// the difference is asserted rather than left to the doc comment.
    #[test]
    fn ser_a_pt_is_not_the_local_point_encoding() {
        let m = master_from_seed(&fixed_seed()).unwrap();
        let pk = SchnorrPrivateKey::new(m.scalar.clone())
            .unwrap()
            .public_key()
            .unwrap();
        let upstream = ser_a_pt(&pk);
        assert_eq!(upstream[0], 0x01, "ser-a-pt's leading rep block is 1");
        assert_ne!(
            upstream,
            serialize_point(&pk),
            "the two 97-byte encodings must not coincide"
        );
    }

    /// The limb order `ser_a_pt` claims: `0x01 || y5..y0 || x5..x0`, each
    /// limb big-endian. Pinned structurally so a reversed `.rev()` fails
    /// here — next to the claim — and not only in the conformance KAT.
    #[test]
    fn ser_a_pt_limb_order_is_y_then_x_most_significant_first() {
        let pt = CheetahPoint {
            x: F6lt([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5), Belt(6)]),
            y: F6lt([Belt(7), Belt(8), Belt(9), Belt(10), Belt(11), Belt(12)]),
            inf: false,
        };
        let out = ser_a_pt(&pt);
        assert_eq!(out[0], 0x01);
        // y5 = 12 first, then y4 = 11, ... then x5 = 6, ... down to x0 = 1.
        let want: Vec<u64> = vec![12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        for (i, w) in want.iter().enumerate() {
            let at = 1 + i * 8;
            assert_eq!(
                u64::from_be_bytes(out[at..at + 8].try_into().unwrap()),
                *w,
                "limb {i}"
            );
        }
    }
}
