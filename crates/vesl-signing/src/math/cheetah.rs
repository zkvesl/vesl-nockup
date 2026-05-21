//! Cheetah elliptic curve over `F_p^6`, in affine coordinates.
//!
//! Ported from `nockchain-math/src/crypto/cheetah.rs`. Constants (`A_GEN`,
//! `G_ORDER`, the sextic extension reduction polynomial) and algorithms are
//! copied verbatim for bit-compatibility with the chain-side verifier.

use ibig::UBig;
use once_cell::sync::Lazy;

use crate::math::belt::{bneg, Belt, PRIME};
use crate::math::bpoly::{bpegcd, bpscal};

// ---------------------------------------------------------------------------
// F6lt: sextic extension F_p[x] / (x^6 - 7)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct F6lt(pub [Belt; 6]);

pub const F6_ZERO: F6lt = F6lt([Belt(0); 6]);
pub const F6_ONE: F6lt = F6lt([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

#[inline(always)]
fn karat3(a: &[Belt; 3], b: &[Belt; 3]) -> [Belt; 5] {
    let m = [a[0] * b[0], a[1] * b[1], a[2] * b[2]];
    [
        m[0],
        (a[0] + a[1]) * (b[0] + b[1]) - (m[0] + m[1]),
        (a[0] + a[2]) * (b[0] + b[2]) - (m[0] + m[2]) + m[1],
        (a[1] + a[2]) * (b[1] + b[2]) - (m[1] + m[2]),
        m[2],
    ]
}

#[inline(always)]
pub fn f6_mul(f: &F6lt, g: &F6lt) -> F6lt {
    let f0g0 = karat3(&[f.0[0], f.0[1], f.0[2]], &[g.0[0], g.0[1], g.0[2]]);
    let f1g1 = karat3(&[f.0[3], f.0[4], f.0[5]], &[g.0[3], g.0[4], g.0[5]]);
    let foil = karat3(
        &[f.0[0] + f.0[3], f.0[1] + f.0[4], f.0[2] + f.0[5]],
        &[g.0[0] + g.0[3], g.0[1] + g.0[4], g.0[2] + g.0[5]],
    );
    let cross = [
        foil[0] - (f0g0[0] + f1g1[0]),
        foil[1] - (f0g0[1] + f1g1[1]),
        foil[2] - (f0g0[2] + f1g1[2]),
        foil[3] - (f0g0[3] + f1g1[3]),
        foil[4] - (f0g0[4] + f1g1[4]),
    ];
    F6lt([
        f0g0[0] + Belt(7) * (cross[3] + f1g1[0]),
        f0g0[1] + Belt(7) * (cross[4] + f1g1[1]),
        f0g0[2] + Belt(7) * f1g1[2],
        f0g0[3] + cross[0] + Belt(7) * f1g1[3],
        f0g0[4] + cross[1] + Belt(7) * f1g1[4],
        cross[2],
    ])
}

#[inline(always)]
pub fn f6_inv(f: &F6lt) -> Result<F6lt, CheetahError> {
    if f == &F6_ZERO {
        return Err(CheetahError::DivByZero);
    }
    let mut res = [Belt(0); 6];
    let mut d = [Belt(0); 7];
    let mut u = [Belt(0); 7];
    let mut v = [Belt(0); 6];
    bpegcd(
        &f.0,
        &[
            Belt(bneg(7)),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(1),
        ],
        &mut d,
        &mut u,
        &mut v,
    );
    let inv = d[0].inv();
    bpscal(inv, &u, &mut res);
    Ok(F6lt(res))
}

#[inline(always)]
pub fn f6_div(f1: &F6lt, f2: &F6lt) -> Result<F6lt, CheetahError> {
    Ok(f6_mul(f1, &f6_inv(f2)?))
}

#[inline(always)]
fn f6_add(f1: &F6lt, f2: &F6lt) -> F6lt {
    F6lt([
        f1.0[0] + f2.0[0],
        f1.0[1] + f2.0[1],
        f1.0[2] + f2.0[2],
        f1.0[3] + f2.0[3],
        f1.0[4] + f2.0[4],
        f1.0[5] + f2.0[5],
    ])
}

#[inline(always)]
fn f6_scal(s: Belt, f: &F6lt) -> F6lt {
    F6lt([
        f.0[0] * s,
        f.0[1] * s,
        f.0[2] * s,
        f.0[3] * s,
        f.0[4] * s,
        f.0[5] * s,
    ])
}

#[inline(always)]
fn f6_square(f: &F6lt) -> F6lt {
    f6_mul(f, f)
}

#[inline(always)]
fn f6_neg(f: &F6lt) -> F6lt {
    F6lt([-f.0[0], -f.0[1], -f.0[2], -f.0[3], -f.0[4], -f.0[5]])
}

#[inline(always)]
fn f6_sub(f1: &F6lt, f2: &F6lt) -> F6lt {
    f6_add(f1, &f6_neg(f2))
}

// ---------------------------------------------------------------------------
// Curve
// ---------------------------------------------------------------------------

pub static G_ORDER: Lazy<UBig> = Lazy::new(|| {
    UBig::from_str_radix(
        "7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf",
        16,
    )
    .expect("G_ORDER hex is valid")
});

pub static P_BIG: Lazy<UBig> = Lazy::new(|| UBig::from(PRIME));
pub static P_BIG_2: Lazy<UBig> = Lazy::new(|| &*P_BIG * &*P_BIG);
pub static P_BIG_3: Lazy<UBig> = Lazy::new(|| &*P_BIG_2 * &*P_BIG);

pub const A_GEN: CheetahPoint = CheetahPoint {
    x: F6lt([
        Belt(2754611494552410273),
        Belt(8599518745794843693),
        Belt(10526511002404673680),
        Belt(4830863958577994148),
        Belt(375185138577093320),
        Belt(12938930721685970739),
    ]),
    y: F6lt([
        Belt(15384029202802550068),
        Belt(2774812795997841935),
        Belt(14375303400746062753),
        Belt(10708493419890101954),
        Belt(13187678623570541764),
        Belt(9990732138772505951),
    ]),
    inf: false,
};

pub const A_ID: CheetahPoint = CheetahPoint {
    x: F6_ZERO,
    y: F6_ONE,
    inf: true,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct CheetahPoint {
    pub x: F6lt,
    pub y: F6lt,
    pub inf: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CheetahError {
    #[error("base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("invalid base58 length: {0}")]
    InvalidLength(usize),
    #[error("array conversion failed")]
    ArrayConversion,
    #[error("point is not on the curve")]
    NotOnCurve,
    #[error("division by zero in F6")]
    DivByZero,
}

impl CheetahPoint {
    /// 97 bytes: leading 0x01 tag + 12 × 8-byte big-endian Belts (y6 ++ x6
    /// reversed).
    const BYTES: usize = 97;

    /// Upper bound on a base58 string [`Self::from_base58`] will decode. A
    /// 97-byte point is ≈133 base58 chars; 256 leaves generous headroom
    /// while bounding the `bs58::decode` allocation against a hostile
    /// oversized string. AUDIT 2026-05-21 L-24.
    const MAX_B58_LEN: usize = 256;

    pub fn into_base58(&self) -> Result<String, CheetahError> {
        Ok(bs58::encode(self.to_bytes()?).into_string())
    }

    /// Canonical 97-byte encoding used as input to the PKH hash. Layout:
    /// `[0x01, y5, y4, y3, y2, y1, y0, x5, x4, x3, x2, x1, x0]` with each
    /// Belt as 8 big-endian bytes.
    pub fn to_bytes(&self) -> Result<[u8; Self::BYTES], CheetahError> {
        if self.inf {
            return Err(CheetahError::NotOnCurve);
        }
        let mut out = [0u8; Self::BYTES];
        out[0] = 0x1;
        let mut cursor = 1;
        for belt in self.y.0.iter().rev().chain(self.x.0.iter().rev()) {
            out[cursor..cursor + 8].copy_from_slice(&belt.0.to_be_bytes());
            cursor += 8;
        }
        Ok(out)
    }

    pub fn from_base58(b58: &str) -> Result<Self, CheetahError> {
        // AUDIT 2026-05-21 L-24: bound the input before `bs58::decode`
        // allocates — a hostile multi-megabyte base58 string would
        // otherwise drive an unbounded heap allocation before the
        // post-decode length check below ever runs.
        if b58.len() > Self::MAX_B58_LEN {
            return Err(CheetahError::InvalidLength(b58.len()));
        }
        let v = bs58::decode(b58).into_vec()?;
        if v.len() != Self::BYTES {
            return Err(CheetahError::InvalidLength(v.len()));
        }
        let mut v64 = v[1..]
            .chunks_exact(8)
            .map(|a| {
                let arr = <[u8; 8]>::try_from(a).map_err(|_| CheetahError::ArrayConversion)?;
                Ok(Belt(u64::from_be_bytes(arr)))
            })
            .collect::<Result<Vec<Belt>, CheetahError>>()?;
        v64.reverse();
        let c_pt = CheetahPoint {
            x: F6lt(<[Belt; 6]>::try_from(&v64[..6]).map_err(|_| CheetahError::ArrayConversion)?),
            y: F6lt(<[Belt; 6]>::try_from(&v64[6..]).map_err(|_| CheetahError::ArrayConversion)?),
            inf: false,
        };
        if c_pt.in_curve() {
            Ok(c_pt)
        } else {
            Err(CheetahError::NotOnCurve)
        }
    }

    pub fn in_curve(&self) -> bool {
        if *self == A_ID {
            return true;
        }
        // AUDIT 2026-05-21 L-25: an off-curve point can drive `ch_scal_big`
        // into an F6 division by zero. `in_curve` runs on attacker-supplied
        // points (`from_base58`, `schnorr_verify`), so treat a curve-arith
        // error as "not on the curve" rather than panicking.
        match ch_scal_big(&G_ORDER, self) {
            Ok(scaled) => scaled == A_ID,
            Err(_) => false,
        }
    }
}

#[inline(always)]
pub fn ch_double_unsafe(x: &F6lt, y: &F6lt) -> Result<CheetahPoint, CheetahError> {
    let slope = f6_div(
        &f6_add(&f6_scal(Belt(3), &f6_square(x)), &F6_ONE),
        &f6_scal(Belt(2), y),
    )?;
    let x_out = f6_sub(&f6_square(&slope), &f6_scal(Belt(2), x));
    let y_out = f6_sub(&f6_mul(&slope, &f6_sub(x, &x_out)), y);
    Ok(CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    })
}

#[inline(always)]
pub fn ch_double(p: CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    if p.inf {
        return Ok(A_ID);
    }
    if p.y == F6_ZERO {
        return Ok(A_ID);
    }
    ch_double_unsafe(&p.x, &p.y)
}

#[inline(always)]
fn ch_add_unsafe(p: CheetahPoint, q: CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let slope = f6_div(&f6_sub(&p.y, &q.y), &f6_sub(&p.x, &q.x))?;
    let x_out = f6_sub(&f6_square(&slope), &f6_add(&p.x, &q.x));
    let y_out = f6_sub(&f6_mul(&slope, &f6_sub(&p.x, &x_out)), &p.y);
    Ok(CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    })
}

#[inline(always)]
pub fn ch_neg(p: &CheetahPoint) -> CheetahPoint {
    CheetahPoint {
        x: p.x,
        y: f6_neg(&p.y),
        inf: p.inf,
    }
}

#[inline(always)]
pub fn ch_add(p: &CheetahPoint, q: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    if p.inf {
        return Ok(*q);
    }
    if q.inf {
        return Ok(*p);
    }
    if *p == ch_neg(q) {
        return Ok(A_ID);
    }
    if p == q {
        return ch_double(*p);
    }
    ch_add_unsafe(*p, *q)
}

pub fn ch_scal(mut n: u64, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let mut p_copy = *p;
    let mut acc = A_ID;
    while n > 0 {
        if n & 1 == 1 {
            acc = ch_add(&acc, &p_copy)?;
        }
        p_copy = ch_double(p_copy)?;
        n >>= 1;
    }
    Ok(acc)
}

pub fn ch_scal_big(n: &UBig, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let mut n_copy = n.clone();
    let zero = UBig::from(0u64);
    let mut p_copy = *p;
    let mut acc = A_ID;
    while n_copy > zero {
        if n_copy.bit(0) {
            acc = ch_add(&acc, &p_copy)?;
        }
        p_copy = ch_double(p_copy)?;
        n_copy >>= 1;
    }
    Ok(acc)
}

/// Reduce an array of ≥4 `u64` digits to a 255-bit number mod `G_ORDER`.
///
/// Treats `a` as a little-endian base-`PRIME` number: `a[0] + p·a[1] +
/// p²·a[2] + p³·a[3]`. Used to derive Schnorr challenges and deterministic
/// nonces from `Tip5` hash outputs.
pub fn trunc_g_order(a: &[u64]) -> UBig {
    let mut result = UBig::from(a[0]);
    result += &*P_BIG * UBig::from(a[1]);
    result += &*P_BIG_2 * UBig::from(a[2]);
    result += &*P_BIG_3 * UBig::from(a[3]);
    result % &*G_ORDER
}

#[cfg(test)]
mod tests {
    use super::*;

    const F6_TEST: F6lt = F6lt([
        Belt(13724052584687643294),
        Belt(6944593306454870014),
        Belt(10082672435494154603),
        Belt(6450272673873704561),
        Belt(2898784811200916299),
        Belt(15463938240345685194),
    ]);

    #[test]
    fn f6_mul_identity() {
        let f2 = F6lt([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5), Belt(6)]);
        assert_eq!(f6_mul(&F6_ONE, &f2), f2);
        assert_eq!(f6_mul(&f2, &F6_ONE), f2);
        assert_eq!(f6_mul(&F6_ZERO, &f2), F6_ZERO);
    }

    #[test]
    fn f6_inv_roundtrip() {
        // Chain-parity: values copied from nockchain-math/src/crypto/cheetah.rs tests.
        let f = F6_TEST;
        let f_inv = f6_inv(&f).unwrap();
        assert_eq!(
            f_inv,
            F6lt([
                Belt(129083178215983407),
                Belt(16804250925345184998),
                Belt(6447171951354165736),
                Belt(16181730381532049633),
                Belt(9179768094922373417),
                Belt(8139613426717722210),
            ])
        );
        assert_eq!(f6_mul(&f, &f_inv), F6_ONE);
    }

    #[test]
    fn ch_scal_3_matches_chain() {
        // Chain-parity: expected point copied from nockchain-math/src/crypto/cheetah.rs.
        let expected = CheetahPoint {
            x: F6lt([
                Belt(12461929372724418873),
                Belt(16567359094004701986),
                Belt(18139376982535661051),
                Belt(3904128592858427998),
                Belt(1409597492055585669),
                Belt(10004445677131924957),
            ]),
            y: F6lt([
                Belt(11902197035441682466),
                Belt(5072010750673887563),
                Belt(16590571040514665822),
                Belt(11686652568553538253),
                Belt(9569866106958470758),
                Belt(6839548852764696901),
            ]),
            inf: false,
        };
        assert_eq!(ch_scal(3, &A_GEN).unwrap(), expected);
    }

    #[test]
    fn gen_is_on_curve() {
        assert!(A_GEN.in_curve());
    }

    #[test]
    fn gen_base58_roundtrip() {
        let b58 = A_GEN.into_base58().unwrap();
        let back = CheetahPoint::from_base58(&b58).unwrap();
        assert_eq!(back, A_GEN);
    }

    #[test]
    fn known_base58_decodes() {
        // Chain-parity: values copied from nockchain-math Cheetah base58 tests.
        for addr in [
            "32KVTmv3ofSyACq9nC1Hgnk4Jt8rs2hj1cvDZWC1EQuiYFMDg8MaLtF3ntafJbEUH5XPV1pK3K4xkxfjRPAWprBb7LYCVv4HF7817Bwh9M9xAdmgrPt77j4xejihNFd9h5Eo",
            "2Xu6FtvopCS69Ko2YnC99B9SVVZ7PLoVn7WvEdDpJKRxW1pmj51uBQdYfADEbRUFYwG55Wi2Qwa3f6Y6WTev5jLcvfJFDEr2Wwt8rViQeLsz1XwEPah5pxtwHTm2nmecjJNW",
        ] {
            let pt = CheetahPoint::from_base58(addr).unwrap();
            assert_eq!(pt.into_base58().unwrap(), addr);
        }
    }
}
