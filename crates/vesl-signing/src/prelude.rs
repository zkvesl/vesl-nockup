//! Curated subset of the internal math substrate, exposed for downstream
//! crates that need raw `Belt` access (e.g. `x402-nockchain-crypto`'s
//! `sign_message.rs` for canonical hashing of `Authorization`, or
//! `vesl-core`'s signing shim that bridges between `nockchain-math::Belt`
//! and vesl-signing's `Belt`).
//!
//! Adding a symbol here means committing to API stability for it. Do not
//! re-export math internals (curve coordinates, F6 extensions, Tip5 sponge
//! state) through this module. New entries require a v0.x version bump.

pub use crate::math::belt::{Belt, PRIME};
pub use crate::math::tip5::hash_varlen;
