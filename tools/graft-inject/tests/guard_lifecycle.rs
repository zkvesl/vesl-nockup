//! Guard-graft lifecycle integration test (Phase 8b).
//!
//! Composes a kernel from `[settle-graft, mint-graft, guard-graft]`,
//! compiles it with `hoonc`, boots it through `vesl-test`, and drives
//! the full mint → guard-register → guard-check flow. ~30-50s runtime
//! (most of it `hoonc`); treat accordingly in CI.
//!
//! Phase 11 factored the scratch/compose/peek machinery into
//! `tests/fixtures/` — what remains here is the assertion script.

mod fixtures;

use anyhow::Result;
use vesl_core::{
    Mint, Tip5Hash, build_guard_check_poke, build_guard_register_poke,
    build_mint_commit_poke, tip5_to_atom_le_bytes,
};
use vesl_test::GraftTestHarness;

const LEAF: &[u8] = b"guard-graft fixture leaf";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_register_check_happy_and_error_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "guard_lifecycle",
        &["settle-graft", "mint-graft", "guard-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let root = commit_root(LEAF);

    // Mint first — gives us a committed root under hull 1. Guard then
    // mirrors that registration for its own lookup.
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-commit: expected %mint-committed; got {tags:?}",
    );

    let tags = harness.poke_slab(build_guard_register_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "guard-register: expected %guard-registered; got {tags:?}",
    );

    let tags = harness.poke_slab(build_guard_check_poke(1, LEAF)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-checked"),
        "guard-check valid leaf: expected %guard-checked; got {tags:?}",
    );

    // Tampered data — still %guard-checked (soft ok=%.n). Guard's
    // design is crash-on-bad-leaf is settle-graft's job, not guard's.
    let tags = harness.poke_slab(build_guard_check_poke(1, b"tampered")).await?;
    assert!(
        tags.iter().any(|t| t == "guard-checked"),
        "guard-check tampered: expected %guard-checked (soft mismatch); got {tags:?}",
    );

    // Unregistered hull → %guard-error, not a silent %guard-checked.
    let tags = harness.poke_slab(build_guard_check_poke(99, LEAF)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-error"),
        "guard-check hull 99: expected %guard-error; got {tags:?}",
    );

    let got_root = fixtures::peek_hull_value(&mut harness, "guard-root", 1).await?;
    assert_eq!(
        got_root.as_deref(),
        Some(tip5_to_atom_le_bytes(&root).as_slice()),
        "guard-root peek for hull 1 should return the registered root",
    );

    let missing = fixtures::peek_hull_value(&mut harness, "guard-root", 99).await?;
    assert!(missing.is_none(), "guard-root peek hull 99: {missing:?}");

    Ok(())
}

fn commit_root(payload: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[payload])
}
