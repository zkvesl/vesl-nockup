//! RBAC-graft lifecycle integration test.
//!
//! Composes a kernel from `[settle-graft, kv-graft, counter-graft,
//! queue-graft, rbac-graft]`, compiles via `hoonc`, boots through
//! `vesl-test`, and exercises grant/revoke/auto-clear plus the
//! peek surface (perm count, individual perm membership).
//!
//! No hostile-input case: rbac-graft has no `cue payload` site —
//! the cause shape (`pubkey=@`, `perms=(list @t)`) carries typed
//! atoms / cords / list cells; structural matching at the cause
//! switch handles malformed shapes without reaching graft code.

mod fixtures;

use std::time::{Duration, Instant};

use anyhow::Result;
use nock_noun_rs::{atom_from_u64, make_tag_in, NounSlab};
use nockvm::noun::{D, T};
use vesl_core::{
    build_rbac_grant_poke, build_rbac_revoke_poke, peek_loobean, unwrap_triple_unit_atom,
};
use vesl_test::GraftTestHarness;

// Regression fence: before the fix, %rbac-revoke's `(~(int in asked)
// held)` allocated unboundedly under interpretation and hung the kernel
// >5 min. The skim-based fix lands each revoke in single-digit ms — a 2 s
// ceiling catches any future regression long before the friction-log threshold.
const REVOKE_BUDGET: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rbac_grant_revoke_auto_clear_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "rbac_lifecycle",
        &[
            "settle-graft",
            "kv-graft",
            "counter-graft",
            "queue-graft",
            "rbac-graft",
        ],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Grant {read, write} to pubkey 1.
    let tags = harness
        .poke_slab(build_rbac_grant_poke(1, &["read", "write"]))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "expected %rbac-granted on initial grant; got {tags:?}",
    );

    assert_eq!(perm_count(&mut harness, 1).await?, 2, "1 holds 2 perms");
    assert!(has_perm(&mut harness, 1, "read").await?);
    assert!(has_perm(&mut harness, 1, "write").await?);
    assert!(!has_perm(&mut harness, 1, "audit").await?);

    // Re-grant {write, audit}: union → {read, write, audit}, count 3.
    let tags = harness
        .poke_slab(build_rbac_grant_poke(1, &["write", "audit"]))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "expected %rbac-granted on union; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 3);
    assert!(has_perm(&mut harness, 1, "audit").await?);

    // Revoke {write}: count drops to 2. Time the poke — before the fix this
    // was the int:in livelock site (asked ∩ held non-empty).
    let revoke_start = Instant::now();
    let tags = harness.poke_slab(build_rbac_revoke_poke(1, &["write"])).await?.effect_head_tags();
    let revoke_elapsed = revoke_start.elapsed();
    assert!(
        revoke_elapsed < REVOKE_BUDGET,
        "revoke (intersect path) took {revoke_elapsed:?}; budget {REVOKE_BUDGET:?} (timing regression?)",
    );
    assert!(
        tags.iter().any(|t| t == "rbac-revoked"),
        "expected %rbac-revoked; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 2);
    assert!(!has_perm(&mut harness, 1, "write").await?);

    // Revoke an unheld perm — must noop, not error.
    let revoke_start = Instant::now();
    let tags = harness.poke_slab(build_rbac_revoke_poke(1, &["never-held"])).await?.effect_head_tags();
    let revoke_elapsed = revoke_start.elapsed();
    assert!(
        revoke_elapsed < REVOKE_BUDGET,
        "revoke-unheld took {revoke_elapsed:?}; budget {REVOKE_BUDGET:?} (timing regression?)",
    );
    assert!(
        tags.iter().any(|t| t == "rbac-revoked"),
        "revoke-unheld must emit %rbac-revoked (noop), not %rbac-error; got {tags:?}",
    );
    assert!(
        !tags.iter().any(|t| t == "rbac-error"),
        "revoke-unheld must not emit %rbac-error; got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 1).await?, 2);

    // Revoke remaining perms: pubkey must auto-clear from roles map. This is
    // the empty-remaining → del:by branch — also timing-fenced as a
    // del:by interpreted-allocation canary.
    let revoke_start = Instant::now();
    let _ = harness
        .poke_slab(build_rbac_revoke_poke(1, &["read", "audit"]))
        .await?;
    let revoke_elapsed = revoke_start.elapsed();
    assert!(
        revoke_elapsed < REVOKE_BUDGET,
        "revoke (auto-clear path) took {revoke_elapsed:?}; budget {REVOKE_BUDGET:?} (timing regression?)",
    );
    assert_eq!(
        perm_count(&mut harness, 1).await?,
        0,
        "after full revoke, perm-count must be 0 (auto-cleared)",
    );
    // Granting again after auto-clear must succeed (re-registration).
    let _ = harness.poke_slab(build_rbac_grant_poke(1, &["fresh"])).await?;
    assert_eq!(perm_count(&mut harness, 1).await?, 1);

    // Empty perms list grant — noop, no error.
    let tags = harness.poke_slab(build_rbac_grant_poke(2, &[])).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "empty-perms grant must emit %rbac-granted (noop), got {tags:?}",
    );
    assert_eq!(perm_count(&mut harness, 2).await?, 0, "empty grant must not register");

    Ok(())
}

/// Decode `[%rbac-perm-count pubkey=@ ~]` as `u64`.
async fn perm_count(harness: &mut GraftTestHarness, pubkey: u64) -> Result<u64> {
    let path = build_pubkey_peek_path("rbac-perm-count", pubkey);
    let result = harness.peek_raw(path).await?;
    let bytes = unwrap_triple_unit_atom(&result).unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}

/// Decode `[%rbac-has-perm pubkey=@ perm=@t ~]` as a loobean.
async fn has_perm(harness: &mut GraftTestHarness, pubkey: u64, perm: &str) -> Result<bool> {
    let path = build_pubkey_perm_peek_path("rbac-has-perm", pubkey, perm);
    let result = harness.peek_raw(path).await?;
    Ok(peek_loobean(&result).unwrap_or(false))
}

fn build_pubkey_peek_path(tag: &str, pubkey: u64) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let pk_atom = atom_from_u64(&mut slab, pubkey);
    let path = T(&mut slab, &[tag_atom, pk_atom, D(0)]);
    slab.set_root(path);
    slab
}

fn build_pubkey_perm_peek_path(tag: &str, pubkey: u64, perm: &str) -> NounSlab {
    let mut slab = NounSlab::new();
    let tag_atom = make_tag_in(&mut slab, tag);
    let pk_atom = atom_from_u64(&mut slab, pubkey);
    let perm_atom = make_tag_in(&mut slab, perm);
    let path = T(&mut slab, &[tag_atom, pk_atom, perm_atom, D(0)]);
    slab.set_root(path);
    slab
}
