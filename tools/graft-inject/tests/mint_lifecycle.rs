//! Mint-graft lifecycle integration test (Phase 7b).
//!
//! Composes a kernel from `[settle-graft, mint-graft]`, compiles it with
//! `hoonc`, boots it through `vesl-test`, and exercises the full
//! mint-commit / peek flow. Runs end-to-end in ~30-50s (the bulk is
//! `hoonc`); treat accordingly in CI.
//!
//! Phase 11 factored the scratch/compose/peek machinery into
//! `tests/fixtures/`. The assertions below are the only thing that
//! stays test-local.

mod fixtures;

use anyhow::Result;
use vesl_core::{Mint, Tip5Hash, build_mint_commit_poke, tip5_to_atom_le_bytes};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_commit_two_hulls_then_peek() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "mint_lifecycle",
        &["settle-graft", "mint-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let root1 = commit_root(b"mint-graft fixture payload A");
    let root2 = commit_root(b"mint-graft fixture payload B");

    let tags = harness.poke_slab(build_mint_commit_poke(1, &root1)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "expected %mint-committed for hull 1; got {tags:?}",
    );

    let tags = harness.poke_slab(build_mint_commit_poke(2, &root2)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "expected %mint-committed for hull 2; got {tags:?}",
    );

    // Re-committing hull 1 must report %mint-error (append-only trellis).
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root1)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-error"),
        "expected %mint-error on re-commit of hull 1; got {tags:?}",
    );

    let got1 = fixtures::peek_hull_value(&mut harness, "mint-commit", 1).await?;
    assert_eq!(
        got1.as_deref(),
        Some(tip5_to_atom_le_bytes(&root1).as_slice()),
        "peek for hull 1 should return root1",
    );
    let got2 = fixtures::peek_hull_value(&mut harness, "mint-commit", 2).await?;
    assert_eq!(
        got2.as_deref(),
        Some(tip5_to_atom_le_bytes(&root2).as_slice()),
        "peek for hull 2 should return root2",
    );

    let missing = fixtures::peek_hull_value(&mut harness, "mint-commit", 99).await?;
    assert!(missing.is_none(), "peek for hull 99 should be empty; got {missing:?}");

    Ok(())
}

fn commit_root(payload: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[payload])
}
