//! Goldilocks base-field `Belt` and arithmetic.
//!
//! Ported from `nockchain/crates/nockchain-math/src/belt.rs`. Constants and
//! algorithms are copied verbatim for bit-compatibility with the chain-side
//! verifier.

use std::ops::{Add, Mul, Neg, Sub};

pub const PRIME: u64 = 18_446_744_069_414_584_321;
pub const PRIME_128: u128 = PRIME as u128;
const RP: u128 = 340_282_366_841_710_300_967_557_013_911_933_812_736;
pub const R2: u128 = 18_446_744_065_119_617_025;

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Belt(pub u64);

impl Belt {
    #[inline(always)]
    pub const fn zero() -> Self {
        Belt(0)
    }
    #[inline(always)]
    pub const fn one() -> Self {
        Belt(1)
    }
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Add for Belt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Belt(badd(self.0, rhs.0))
    }
}
impl Sub for Belt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Belt(bsub(self.0, rhs.0))
    }
}
impl Neg for Belt {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Belt(bneg(self.0))
    }
}
impl Mul for Belt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Belt(bmul(self.0, rhs.0))
    }
}

#[inline]
pub fn based_check(a: u64) -> bool {
    a < PRIME
}

#[inline(always)]
pub fn badd(a: u64, b: u64) -> u64 {
    let b = PRIME.wrapping_sub(b);
    let (r, c) = a.overflowing_sub(b);
    let adj = 0u32.wrapping_sub(c as u32);
    r.wrapping_sub(adj as u64)
}

#[inline(always)]
pub fn bneg(a: u64) -> u64 {
    if a != 0 {
        PRIME - a
    } else {
        0
    }
}

#[inline(always)]
pub fn bsub(a: u64, b: u64) -> u64 {
    let (r, c) = a.overflowing_sub(b);
    let adj = 0u32.wrapping_sub(c as u32);
    r.wrapping_sub(adj as u64)
}

#[inline(always)]
pub fn reduce(n: u128) -> u64 {
    reduce_159(n as u64, (n >> 64) as u32, (n >> 96) as u64)
}

#[inline(always)]
pub fn reduce_159(low: u64, mid: u32, high: u64) -> u64 {
    let (mut low2, carry) = low.overflowing_sub(high);
    if carry {
        low2 = low2.wrapping_add(PRIME);
    }
    let mut product = (mid as u64) << 32;
    product -= product >> 32;
    let (mut result, carry) = product.overflowing_add(low2);
    if carry {
        result = result.wrapping_sub(PRIME);
    }
    if result >= PRIME {
        result -= PRIME;
    }
    result
}

#[inline(always)]
pub fn bmul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

#[inline(always)]
pub fn mont_reduction(a: u128) -> u64 {
    debug_assert!(a < RP, "element must be inside the field");
    let x1: u128 = (a >> 32) & 0xffff_ffff;
    let x2: u128 = a >> 64;
    let c: u128 = {
        let x0: u128 = a & 0xffff_ffff;
        (x0 + x1) << 32
    };
    let f: u128 = c >> 64;
    let d: u128 = c - (x1 + (f * PRIME_128));
    if x2 >= d {
        (x2 - d) as u64
    } else {
        (x2 + PRIME_128 - d) as u64
    }
}

#[inline(always)]
pub fn montiply(a: u64, b: u64) -> u64 {
    mont_reduction((a as u128) * (b as u128))
}

#[inline(always)]
pub fn montify(a: u64) -> u64 {
    mont_reduction((a as u128) * R2)
}

#[inline(always)]
pub fn montwopow(a: u64, b: u32) -> u64 {
    let mut res = a;
    for _ in 0..b {
        res = montiply(res, res);
    }
    res
}

#[inline(always)]
pub fn binv(a: u64) -> u64 {
    let y = montify(a);
    let y2 = montiply(y, montiply(y, y));
    let y3 = montiply(y, montiply(y2, y2));
    let y5 = montiply(y2, montwopow(y3, 2));
    let y10 = montiply(y5, montwopow(y5, 5));
    let y20 = montiply(y10, montwopow(y10, 10));
    let y30 = montiply(y10, montwopow(y20, 10));
    let y31 = montiply(y, montiply(y30, y30));
    let dup = montiply(montwopow(y31, 32), y31);
    mont_reduction(montiply(y, montiply(dup, dup)).into())
}

#[inline(always)]
pub fn bpow(mut a: u64, mut b: u64) -> u64 {
    let mut c: u64 = 1;
    if b == 0 {
        return c;
    }
    while b > 1 {
        if b & 1 == 0 {
            a = reduce((a as u128) * (a as u128));
            b /= 2;
        } else {
            c = reduce((c as u128) * (a as u128));
            a = reduce((a as u128) * (a as u128));
            b = (b - 1) / 2;
        }
    }
    reduce((c as u128) * (a as u128))
}

impl Belt {
    #[inline(always)]
    pub fn inv(self) -> Belt {
        Belt(binv(self.0))
    }
    #[inline(always)]
    pub fn pow(self, e: u64) -> Belt {
        Belt(bpow(self.0, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        let a = Belt(12345);
        let b = Belt(67890);
        assert_eq!((a + b) - b, a);
        assert_eq!((a + b) - a, b);
    }

    #[test]
    fn inv_roundtrip() {
        for x in [1u64, 2, 3, 1_000_000, PRIME - 1] {
            let b = Belt(x);
            assert_eq!((b * b.inv()).0, 1);
        }
    }

    #[test]
    fn pow_matches_naive() {
        let b = Belt(7);
        assert_eq!(b.pow(0).0, 1);
        assert_eq!(b.pow(1).0, 7);
        assert_eq!(b.pow(2).0, 49);
        assert_eq!(b.pow(5).0, 16807);
    }
}
