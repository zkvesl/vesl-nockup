//! Minimal port of the Nockchain math primitives required by Schnorr/Tip5
//! signing: Goldilocks base field (`belt`), polynomial helpers for F6
//! inversion (`bpoly`), Cheetah curve in affine coordinates (`cheetah`),
//! and the Tip5 sponge hash (`tip5`).
//!
//! Constants and algorithms mirror `nockchain/crates/nockchain-math` at
//! the SHA recorded in `vesl-signing`'s parity-vector fixtures; refreshes
//! happen via the parity-regen workflow.
//!
//! Lints suppressed across the module because the port is intentionally
//! verbatim:
//!
//! - `dead_code`: items like `ch_scal` (32-bit scalar mult, used by future
//!   low-bit-budget paths) or `tip5::CAPACITY` (Tip5 sponge parameter)
//!   belong to the math API surface even when no in-tree caller exercises
//!   them yet.
//! - `clippy::wrong_self_convention`: methods like `CheetahPoint::into_base58(&self)`
//!   and `CheetahPoint::to_bytes(&self)` use the original Hoon-derived
//!   naming. Renaming would break source-compat for x402-nockchain
//!   consumers; the math surface is `pub(crate)` so the lint's
//!   external-API rationale doesn't apply here.
#![allow(dead_code, clippy::wrong_self_convention)]

pub mod belt;
pub mod bpoly;
pub mod cheetah;
pub mod tip5;
