//! End-to-end four-graft integration test.
//!
//! Composes `[settle-graft, mint-graft, guard-graft, forge-graft]` on
//! top of the bare `templates/app.hoon` scaffold, compiles the
//! kernel, boots it through `vesl-test`, and exercises every
//! primitive in the composed kernel:
//!
//!   * settle-graft: the full 7-test standard suite — register /
//!     duplicate-register / verify / register-b / settle /
//!     replay-settle / root-mismatch. (This is vesl-test's
//!     `run_standard_suite`; all three settle guardrails are in it.)
//!   * mint-graft: commit a new hull and peek it back.
//!   * guard-graft: register the same hull on guard, check a valid
//!     leaf, confirm the peek returns the registered root.
//!   * forge-graft: build a `%forge-prove` slab, assert head tag.
//!     Not poked — real proof runs 5-40s and is out of scope here.
//!   * template domain poke: `[%cause ~]` — confirms grafted causes
//!     live alongside the placeholder domain cause without clashing.
//!
//! ~60-90s runtime, dominated by `honk` on a four-graft compose
//! (which pulls in the STARK prover tree). Treat accordingly in CI.

mod fixtures;

use anyhow::Result;
use nock_noun_rs::{make_tag_in, slab_jam_to_bytes};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{NounAllocator, D, T};
use vesl_core::{
    Mint, Tip5Hash, build_forge_prove_poke, build_guard_check_poke,
    build_guard_register_poke, build_mint_commit_poke, tip5_to_atom_le_bytes,
};
use vesl_test::GraftTestHarness;

const DOMAIN_HULL: u64 = 7;
const DOMAIN_LEAF: &[u8] = b"integration fixture leaf";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_graft_end_to_end() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "integration",
        &["settle-graft", "mint-graft", "guard-graft", "forge-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // ---------------------------------------------------------------
    // settle-graft: standard 8-test suite — register / duplicate-register
    // / verify / register-b / settle / replay-settle / unregistered-
    // hull / root-mismatch. Every happy path plus all three settle
    // guardrails plus root-mismatch. Fail loudly if anything regresses.
    // ---------------------------------------------------------------
    let report = harness.run_standard_suite().await;
    assert!(
        report.is_success(),
        "vesl standard suite failed: {}\n  passed: {:?}\n  failed: {:?}",
        report.summary(),
        report.passed,
        report.failed,
    );
    assert_eq!(
        report.passed.len(),
        8,
        "standard suite should run 8 tests, got {}",
        report.passed.len(),
    );

    // ---------------------------------------------------------------
    // mint-graft: commit a distinct hull (hulls 1 & 2 are taken by
    // vesl's standard suite, but vesl state is independent of mint
    // state so re-use wouldn't clash — using hull 7 just makes the
    // cross-graft peek assertion below unambiguous).
    // ---------------------------------------------------------------
    let mint_root = commit_root(DOMAIN_LEAF);
    let tags = harness
        .poke_slab(build_mint_commit_poke(DOMAIN_HULL, &mint_root))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-commit: expected %mint-committed; got {tags:?}",
    );

    let mint_peek =
        fixtures::peek_hull_value(&mut harness, "mint-commit", DOMAIN_HULL).await?;
    assert_eq!(
        mint_peek.as_deref(),
        Some(tip5_to_atom_le_bytes(&mint_root).as_slice()),
        "mint-commit peek for hull {DOMAIN_HULL} should return the committed root",
    );

    // ---------------------------------------------------------------
    // guard-graft: register the same root, then check a valid leaf.
    // The cross-graft peek confirms guard stored the same root mint
    // committed — the unified-hull convention.
    // ---------------------------------------------------------------
    let tags = harness
        .poke_slab(build_guard_register_poke(DOMAIN_HULL, &mint_root))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "guard-register: expected %guard-registered; got {tags:?}",
    );

    let tags = harness
        .poke_slab(build_guard_check_poke(DOMAIN_HULL, DOMAIN_LEAF))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "guard-checked"),
        "guard-check valid leaf: expected %guard-checked; got {tags:?}",
    );

    let guard_peek =
        fixtures::peek_hull_value(&mut harness, "guard-root", DOMAIN_HULL).await?;
    assert_eq!(
        guard_peek.as_deref(),
        Some(tip5_to_atom_le_bytes(&mint_root).as_slice()),
        "guard-root peek for hull {DOMAIN_HULL} should return the same root mint committed",
    );

    // ---------------------------------------------------------------
    // forge-graft: shape-check only.
    //
    // The composed kernel compiled, which means the `?-` poke switch
    // accepted %forge-prove as a valid arm. Build the slab, assert
    // the head tag, and stop there — running the prover would add
    // 5-40s to this test and requires the full STARK setup.
    // ---------------------------------------------------------------
    let forge_slab = build_forge_prove_poke(DOMAIN_HULL, 101, DOMAIN_LEAF);
    let forge_jam = slab_jam_to_bytes(&forge_slab);
    assert!(
        !forge_jam.is_empty(),
        "build_forge_prove_poke jam should be non-empty",
    );
    let forge_root = unsafe { *forge_slab.root() };
    let forge_space = forge_slab.noun_space();
    let forge_tag = forge_root
        .in_space(&forge_space)
        .as_cell()
        .expect("forge poke is a cell")
        .head()
        .as_atom()
        .expect("forge tag is an atom");
    let forge_tag_str = std::str::from_utf8(forge_tag.as_ne_bytes())
        .unwrap_or("?")
        .trim_end_matches('\0');
    assert_eq!(forge_tag_str, "forge-prove");

    // ---------------------------------------------------------------
    // Template domain poke: `[%cause ~]` is the bare-scaffold
    // placeholder. It emits no effects (just a slog); its value here
    // is proving a grafted kernel still routes the placeholder arm
    // without crashing. If the graft-inject composer ever broke the
    // `?-` exhaustivity check on `-.u.act`, this poke would fail.
    // ---------------------------------------------------------------
    let tags = harness.poke_slab(build_template_cause_poke()).await?.effect_head_tags();
    assert!(
        tags.is_empty(),
        "template %cause placeholder should emit no effects; got {tags:?}",
    );

    Ok(())
}

fn commit_root(payload: &[u8]) -> Tip5Hash {
    let mut mint = Mint::new();
    mint.commit(&[payload])
}

/// Build the template's placeholder `[%cause ~]` poke.
fn build_template_cause_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "cause");
    let poke = T(&mut slab, &[tag, D(0)]);
    slab.set_root(poke);
    slab
}
