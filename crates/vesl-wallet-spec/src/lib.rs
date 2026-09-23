//! Vesl wallet derivation spec — BIP44 5-level layout.
//!
//! Canonical role assignments and the typed [`DerivationPath`] holder used
//! by every Vesl-stack key derivation. The normative source is `SPEC.md`
//! at the crate root; this crate ships role-number constants and a typed
//! path holder so downstream crates and Hull authors refer to roles by
//! name rather than magic number.
//!
//! Key derivation lives in `vesl-wallet`. This crate intentionally has
//! no curve, no seed handling, no signing API.
//!
//! ## Path shape
//!
//! ```text
//! m / 44' / <coin_type>' / <agent_account>' / <role> / <index>
//! ```
//!
//! ## Roles
//!
//! - [`ROLE_INTENT`]    (`0`) — long-lived intent signing key
//! - [`ROLE_RECEIVING`] (`1`) — receiving / payout address
//! - [`ROLE_ENCRYPTION`](`2`) — encryption / delivery decryption (placeholder)
//! - [`ROLE_SESSION`]   (`3`) — short-lived delegation / session keys
//! - [`ROLE_X402`]      (`4`) — x402 spending keys
//! - [`ROLE_VOID`]      (`5`) — x402 hold-void (cancellation) keys
//! - [`ROLE_WITHDRAWAL`](`6`) — x402 withdrawal: where a swept pool lands
//!
//! Roles `7+` are reserved for future assignments — see `SPEC.md §5`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// BIP44 purpose value (constant per BIP44 spec).
pub const BIP44_PURPOSE: u32 = 44;

/// Role 0 — long-lived intent signing key (Schnorr-over-Cheetah).
///
/// Reserved for the `vesl_signing::domain::domain_separators::VESL_INTENT`
/// (`"vesl-intent-v1"`) Tip5 domain separator. Upstream intent scripting
/// has not landed yet, so the wallet's `sign_intent` accessor is currently
/// a raw passthrough — callers needing cross-protocol separation today
/// must hash under `VESL_INTENT` themselves. The role-0 path slot stays
/// stable so future binding lands without an HD-tree migration. See
/// `SPEC.md §2 Role 0` for the placeholder status and migration plan.
pub const ROLE_INTENT: u32 = 0;

/// Role 1 — receiving / payout address.
pub const ROLE_RECEIVING: u32 = 1;

/// Role 2 — encryption / delivery decryption.
///
/// Placeholder; the encryption primitive is pending the Vesl whitepaper.
/// Reserving the slot keeps the path stable across future encryption-scheme
/// choices.
pub const ROLE_ENCRYPTION: u32 = 2;

/// Role 3 — short-lived delegation / session keys.
///
/// Same Schnorr-over-Cheetah scheme as [`ROLE_INTENT`], derived at a
/// separate path so session-key compromise doesn't expose the role-0 master.
pub const ROLE_SESSION: u32 = 3;

/// Role 4 — x402 spending keys.
///
/// Signs under the `vesl_signing::domain::domain_separators::X402`
/// (`"x402-nockchain-v2"`) Tip5 domain separator.
pub const ROLE_X402: u32 = 4;

/// Role 5 — x402 **hold-void** keys: the dedicated, discardable key that
/// authorises cancelling one parked payment.
///
/// ⚑ *In plain terms: a throwaway key whose only job is to pre-authorise
/// giving one payment back. It signs once, immediately after the payment
/// lands, and is then useless.*
///
/// ⛔⛔ **IT MUST BE DERIVED AT THE SAME INDEX AS THE PAYMENT KEY IT
/// CANCELS, AND THAT IS A PRIVACY REQUIREMENT, NOT A CONVENIENCE.** A spend
/// publishes the signer's PUBKEY in its witness, so a void key that did not
/// rotate would be a permanent, public, on-chain identifier joining every job
/// that buyer ever paid for — an exposure the per-job secret it replaced
/// structurally did not have (x402 `PLAN_B §E1`, `§E3`).
///
/// ⛔ It is a **separate role** rather than another index under
/// [`ROLE_X402`] precisely so the two key spaces cannot collide: at one
/// role, "the void key for payment `i`" would have to be some other index
/// `j`, and `j` is a payment key for some other job.
///
/// ⛔⛔ **THE VOID KEY MUST NEVER EQUAL THE PAYMENT KEY.** The hold's void
/// branch and its capture branch are both 2-of-2 with the platform, and a
/// spend's signed digest covers its outputs and fee and **not the branch it
/// reveals** — so while the two branches named one buyer key, the buyer's
/// capture co-signature also spent the *void* branch, letting the platform be
/// paid while publishing no delivery key. A live node accepted exactly that,
/// twice, before the fix (x402 `records/S118`). Separate roles make the
/// collision unreachable by construction rather than refused by a check.
pub const ROLE_VOID: u32 = 5;

/// Role 6 — x402 **withdrawal** keys: where the pool lands when the user asks
/// for their money back.
///
/// ⚑ *In plain terms: the address a cash-out is swept into. Money here is on
/// its way OUT of the wallet — it is never handed to a job and never split
/// back into spending coins.*
///
/// ⛔⛔ **IT IS A SEPARATE ROLE BECAUSE THE ALTERNATIVE IS A LOOP, AND THE
/// LOOP IS THE POINT.** A sweep that landed at a [`ROLE_RECEIVING`] address
/// would be classified as an incoming **deposit** — unmarked at a receiving
/// address is exactly the funding predicate — and fanned straight back out
/// into the spending pool the user just asked to empty. A distinct role makes
/// that unreachable **by construction** rather than dependent on a note-data
/// tag an observer can read and a stranger can write. This is the same
/// argument [`ROLE_VOID`] makes one role down, and it is why the fix is a
/// role rather than a check (x402 `PROPOSAL-concurrent-notes.md §9.4`).
///
/// ⛔ It is likewise **not** another index under [`ROLE_X402`]: any index
/// there is a spending slot for some job, so a withdrawal parked at one would
/// be handed out by the reservation ledger as if it were working capital.
///
/// ⚑ Unlike [`ROLE_VOID`], this key does **not** have to rotate with a
/// payment key — a withdrawal is a deliberate, user-visible act and carries no
/// per-job unlinkability requirement. Rotating the index per withdrawal is
/// nonetheless recommended for the same reason deposits rotate: it isolates
/// each cash-out so a second coin arriving at one reads as an anomaly.
pub const ROLE_WITHDRAWAL: u32 = 6;

/// Typed BIP44 5-level derivation path.
///
/// Holds the four post-purpose components; the purpose is fixed at
/// [`BIP44_PURPOSE`]. No derivation logic lives here — see `vesl-wallet`
/// for HD key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// SLIP-44 coin_type (TBD upstream — see `SPEC.md §4`).
    pub coin_type: u32,
    /// Per-agent account index.
    pub account: u32,
    /// One of the `ROLE_*` constants in this crate.
    pub role: u32,
    /// Rotation / sequence index within the role.
    pub index: u32,
}

impl DerivationPath {
    /// Construct a [`DerivationPath`] from its four post-purpose components.
    pub const fn new(coin_type: u32, account: u32, role: u32, index: u32) -> Self {
        Self {
            coin_type,
            account,
            role,
            index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_constants_are_stable() {
        assert_eq!(BIP44_PURPOSE, 44);
        assert_eq!(ROLE_INTENT, 0);
        assert_eq!(ROLE_RECEIVING, 1);
        assert_eq!(ROLE_ENCRYPTION, 2);
        assert_eq!(ROLE_SESSION, 3);
        assert_eq!(ROLE_X402, 4);
        assert_eq!(ROLE_VOID, 5);
        assert_eq!(ROLE_WITHDRAWAL, 6);
    }

    /// ⛔⛔ **THE ONE PROPERTY THE VOID KEY EXISTS FOR: AT EVERY INDEX IT IS
    /// A DIFFERENT PATH FROM THE PAYMENT KEY IT CANCELS.**
    ///
    /// ⚑ *In plain terms: the key that cancels a payment must never be the
    /// key that made it.* If the two coincided, the buyer's co-signature on
    /// the payout would also authorise the cancellation, and the platform
    /// could take the money without publishing the key that delivers the
    /// answer — measured accepted at consensus, twice, before the fix.
    ///
    /// ⛔ Asserted **over a range of indices, not at index 0**. A void key
    /// rotates with the payment key, so "they differ" has to hold at every
    /// index; checking one would pass for a `ROLE_VOID` that was accidentally
    /// defined as `ROLE_X402` with an offset.
    #[test]
    fn the_void_path_is_never_the_payment_path_at_any_index() {
        for index in [0u32, 1, 2, 7, 4096, u32::MAX] {
            let payment = DerivationPath::new(0, 0, ROLE_X402, index);
            let void = DerivationPath::new(0, 0, ROLE_VOID, index);
            assert_ne!(
                payment, void,
                "the void key must not be the payment key at index {index}"
            );
        }
    }

    /// ⛔⛔ **THE ONE PROPERTY THE WITHDRAWAL ROLE EXISTS FOR: AT EVERY INDEX
    /// IT IS A DIFFERENT PATH FROM A SPENDING SLOT AND FROM A DEPOSIT
    /// ADDRESS.**
    ///
    /// ⚑ *In plain terms: money on its way out must not sit where money on
    /// its way in sits, and must not sit where a job would be handed it.*
    /// Collide it with [`ROLE_RECEIVING`] and a cash-out is re-classified as a
    /// fresh deposit and fanned back into the pool — the loop this role
    /// exists to make unreachable. Collide it with [`ROLE_X402`] and the
    /// reservation ledger hands the withdrawn coin to the next job.
    ///
    /// ⛔ Asserted **over a range of indices, not at index 0**, for the same
    /// reason the void test is: a single check at 0 passes for a
    /// `ROLE_WITHDRAWAL` accidentally defined as another role plus an offset.
    #[test]
    fn the_withdrawal_path_is_never_a_pool_or_deposit_path_at_any_index() {
        for index in [0u32, 1, 2, 7, 4096, u32::MAX] {
            let withdrawal = DerivationPath::new(0, 0, ROLE_WITHDRAWAL, index);
            for (other, name) in [
                (ROLE_X402, "a spending slot"),
                (ROLE_RECEIVING, "a deposit address"),
                (ROLE_VOID, "a void key"),
            ] {
                assert_ne!(
                    DerivationPath::new(0, 0, other, index),
                    withdrawal,
                    "the withdrawal key must not be {name} at index {index}"
                );
            }
        }
    }

    #[test]
    fn derivation_path_eq_hash() {
        let p = DerivationPath::new(0, 0, ROLE_X402, 0);
        let q = DerivationPath {
            coin_type: 0,
            account: 0,
            role: 4,
            index: 0,
        };
        assert_eq!(p, q);

        // Hash equality follows from Eq + Hash derive contract; smoke-check
        // by inserting both into a HashSet and observing the dedupe.
        use std::collections::HashSet;
        let mut s: HashSet<DerivationPath> = HashSet::new();
        s.insert(p);
        s.insert(q);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn derivation_path_distinct_when_role_differs() {
        let intent = DerivationPath::new(0, 0, ROLE_INTENT, 0);
        let payment = DerivationPath::new(0, 0, ROLE_X402, 0);
        assert_ne!(intent, payment);
    }
}
