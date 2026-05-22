//! Forge-graft compile-only test.
//!
//! The purpose here is narrow: prove that a kernel composed from ALL
//! FOUR grafts — vesl + mint + guard + forge — actually compiles to
//! an `out.jam` and boots through `vesl-test`, AND that
//! `build_forge_prove_poke` emits a well-formed slab the kernel
//! accepts at the `?-` dispatch level.
//!
//! We deliberately do NOT send a forge-prove poke. Actual proof
//! generation runs 5-40s per attempt and requires the full STARK
//! setup — that's out of scope for this PR. What we're guarding
//! against is: stale syncs, missing prover/lower/merkle deps,
//! mis-composed manifest blocks (e.g., cause-union forgot
//! %forge-prove), and shape mismatches in the poke builder.
//!
//! Regression check: mint-commit still dispatches on the same
//! composed kernel, so adding forge doesn't clobber earlier grafts.
//!
//! The scratch/compose machinery lives in `tests/fixtures/`; this
//! test is just the shape-check.

mod fixtures;

use anyhow::Result;
use nock_noun_rs::slab_jam_to_bytes;
use nockvm::noun::NounAllocator;
use vesl_core::{Mint, build_forge_prove_poke, build_mint_commit_poke};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_graft_compose_boots_and_accepts_forge_shape() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "forge_compile",
        &["settle-graft", "mint-graft", "guard-graft", "forge-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Regression: mint still works on the 4-graft kernel.
    let root = {
        let mut mint = Mint::new();
        mint.commit(&[b"forge_compile fixture".as_ref()])
    };
    let tags = harness.poke_slab(build_mint_commit_poke(1, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-commit regression on four-graft kernel; got {tags:?}",
    );

    // Shape check: forge-prove slab is non-empty, head tag is right.
    let slab = build_forge_prove_poke(1, 101, b"forge_compile data");
    let jam = slab_jam_to_bytes(&slab);
    assert!(!jam.is_empty(), "build_forge_prove_poke jam should be non-empty");

    let noun = unsafe { *slab.root() };
    let space = slab.noun_space();
    let cell = noun.in_space(&space).as_cell().expect("forge-prove poke is a cell");
    let tag_atom = cell.head().as_atom().expect("forge-prove tag is an atom");
    let tag_bytes = tag_atom.as_ne_bytes();
    let tag_str = std::str::from_utf8(tag_bytes)
        .unwrap_or("?")
        .trim_end_matches('\0');
    assert_eq!(tag_str, "forge-prove", "poke tag should be 'forge-prove'");

    // Intentionally NOT pokeing the slab — the prover takes 5-40s
    // per attempt, not suitable for CI. The fact that hoonc produced
    // out.jam is itself the kernel-accepts-the-shape proof: if the
    // composed `?-` didn't have a %forge-prove arm, compilation
    // would have failed.

    Ok(())
}
