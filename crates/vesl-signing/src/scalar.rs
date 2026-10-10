//! Fixed-width 256-bit scalars: the type every public signing API speaks.
//!
//! A [`Scalar`] is eight little-endian 32-bit limbs — the Hoon `t8`
//! layout (`rip 5`, zero-padded to eight) that the chain's verifier and
//! its `[Belt; 8]` signature fields already use. Limb 0 is least
//! significant.
//!
//! The big-integer arithmetic behind signing stays inside this crate;
//! callers never need a big-integer library of their own, and no
//! big-integer type crosses the public API.

use std::cmp::Ordering;

use ibig::UBig;

use crate::math::belt::Belt;

/// A 256-bit unsigned integer as eight little-endian 32-bit limbs.
///
/// Used for private keys, Schnorr challenges and signature scalars. It
/// carries no range invariant of its own: [`crate::schnorr`] checks
/// `[1, G_ORDER)` wherever a key or signature requires it.
///
/// `Ord` compares numerically (most-significant limb first), not
/// lexicographically over the limb array.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Scalar([u32; 8]);

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scalar({:?})", self.0)
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The order of the Cheetah generator, `n`
/// (`0x7af2599b…aed4accf`, 255 bits; `ztd/three.hoon:1496`).
pub const G_ORDER: Scalar = Scalar([
    0xaed4_accf, 0xd443_623e, 0x3015_7722, 0x327a_a723, 0x990a_37b5, 0x563f_bf0f, 0x3b3f_22d0,
    0x7af2_599b,
]);

impl Scalar {
    /// Zero.
    pub const ZERO: Scalar = Scalar([0; 8]);

    /// From eight little-endian 32-bit limbs (Hoon `t8`).
    pub const fn from_t8(limbs: [u32; 8]) -> Self {
        Scalar(limbs)
    }

    /// The eight little-endian 32-bit limbs (Hoon `t8`).
    pub const fn to_t8(&self) -> [u32; 8] {
        self.0
    }

    /// From a `u64`.
    pub const fn from_u64(n: u64) -> Self {
        Scalar([n as u32, (n >> 32) as u32, 0, 0, 0, 0, 0, 0])
    }

    /// From eight [`Belt`]s in the `t8` layout. Each `Belt`'s low 32 bits
    /// are taken as one limb and any upper bits are discarded, as
    /// [`crate::schnorr::SchnorrPrivateKey::from_belts`] has always done;
    /// callers must supply values that fit in `u32` (the Hoon `t8`
    /// invariant).
    pub fn from_belts(belts: &[Belt; 8]) -> Self {
        Scalar(std::array::from_fn(|i| belts[i].0 as u32))
    }

    /// The `t8` limbs, each wrapped in a [`Belt`].
    pub fn to_belts(&self) -> [Belt; 8] {
        std::array::from_fn(|i| Belt(self.0[i] as u64))
    }

    /// From 32 big-endian bytes (SLIP-10's `parse256`).
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        Scalar(std::array::from_fn(|i| {
            let at = 32 - 4 * (i + 1);
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        }))
    }

    /// To 32 big-endian bytes (SLIP-10's `ser256`).
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            let at = 32 - 4 * (i + 1);
            out[at..at + 4].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// `true` when the value is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 8]
    }

    /// `(self + rhs) mod G_ORDER` — SLIP-10's child-key step.
    pub fn add_mod_order(&self, rhs: &Scalar) -> Scalar {
        let sum = (self.to_ubig() + rhs.to_ubig()) % &*crate::math::cheetah::G_ORDER;
        Scalar::from_ubig(&sum)
    }

    pub(crate) fn to_ubig(self) -> UBig {
        let mut n = UBig::from(0u64);
        for (i, c) in self.0.iter().enumerate() {
            n += UBig::from(*c) << (32 * i);
        }
        n
    }

    /// The low 256 bits of `n`. Every caller passes a value already
    /// reduced below `G_ORDER`.
    pub(crate) fn from_ubig(n: &UBig) -> Scalar {
        let mask = UBig::from(u32::MAX);
        Scalar(std::array::from_fn(|i| {
            let chunk = (n >> (32 * i)) & &mask;
            u32::try_from(&chunk).expect("a 32-bit mask fits in u32")
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_order_matches_the_curve_constant() {
        assert_eq!(G_ORDER.to_ubig(), *crate::math::cheetah::G_ORDER);
    }

    #[test]
    fn ordering_is_numeric() {
        let low_limb_big = Scalar::from_t8([u32::MAX, 0, 0, 0, 0, 0, 0, 0]);
        let high_limb_one = Scalar::from_t8([0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(low_limb_big < high_limb_one);
        assert!(G_ORDER > Scalar::from_u64(u64::MAX));
        assert_eq!(G_ORDER.cmp(&G_ORDER), Ordering::Equal);
    }

    #[test]
    fn ubig_round_trip() {
        for s in [
            Scalar::ZERO,
            Scalar::from_u64(u64::MAX),
            G_ORDER,
            Scalar::from_t8([u32::MAX; 8]),
        ] {
            assert_eq!(Scalar::from_ubig(&s.to_ubig()), s);
        }
    }

    #[test]
    fn be_bytes_round_trip_and_agree_with_ubig() {
        let s = Scalar::from_t8([1, 2, 3, 4, 5, 6, 7, 0x8000_0009]);
        let bytes = s.to_be_bytes();
        assert_eq!(Scalar::from_be_bytes(&bytes), s);
        assert_eq!(UBig::from_be_bytes(&bytes), s.to_ubig());
    }

    #[test]
    fn from_u64_splits_into_two_limbs() {
        let s = Scalar::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(s.to_t8(), [0x89ab_cdef, 0x0123_4567, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn add_mod_order_wraps() {
        let one = Scalar::from_u64(1);
        let top = Scalar::from_ubig(&(&*crate::math::cheetah::G_ORDER - UBig::from(1u64)));
        assert_eq!(top.add_mod_order(&one), Scalar::ZERO);
        assert_eq!(top.add_mod_order(&Scalar::from_u64(2)), one);
    }
}
