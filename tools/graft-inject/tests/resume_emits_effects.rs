//! Post-resume effect emission across priority bands.
//!
//! An earlier composition showed that pokes against rbac-graft (priority 80)
//! emit effects post-resume but pokes against registry-graft (priority
//! 90), log-graft (priority 130), and domain causes silently produce
//! empty effect lists. State roundtrips correctly; only effect
//! emission breaks. This test composes a kernel straddling the
//! priority threshold, pokes each pre-snapshot, snapshots, drops,
//! resumes from the same kernel, and pokes each post-resume. Effects
//! must emit at every band.

mod fixtures;

use anyhow::Result;
use nockapp::noun::slab::NounSlab;
use nockapp::wire::{SystemWire, Wire};
use nockapp::NockApp;
use vesl_checkpoint::{resume, snapshot};
use vesl_core::{
    build_guard_register_poke, build_log_append_poke, build_mint_commit_poke,
    build_rbac_grant_poke, build_registry_put_poke,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_preserves_effect_emission_across_priority_bands() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "resume_emits_effects",
        &[
            "settle-graft",
            "rbac-graft",
            "registry-graft",
            "log-graft",
        ],
    )?;
    let app_hoon = jam_path
        .parent()
        .expect("compose_and_compile out.jam has a parent")
        .join("hoon/app/app.hoon");

    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // jam(0) — minimum-size payload that registry-update / log-append
    // can cue successfully on the kernel side.
    let payload = vec![0x02u8];

    // Pre-snapshot: each priority band emits.
    let tags = harness.poke_slab(build_rbac_grant_poke(1, &["read"])).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "pre-snapshot rbac-grant (priority 80): {tags:?}",
    );
    let tags = harness.poke_slab(build_registry_put_poke(1, &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "pre-snapshot registry-put (priority 90): {tags:?}",
    );
    let tags = harness.poke_slab(build_log_append_poke("audit", &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "pre-snapshot log-append (priority 130): {tags:?}",
    );

    // Snapshot.
    let snap_dir = tempfile::tempdir()?;
    let snap = snapshot(harness.app(), snap_dir.path(), &app_hoon).await?;
    drop(harness);

    // Resume from the same kernel jam (no schema change — this isolates
    // the post-resume effect-emission path from any state-shape
    // migration concerns).
    let mut resumed = resume(&jam_path, &snap, "rm4-hard-bug-2-test").await?;

    // Post-resume, each priority band must STILL emit.
    let tags = poke_via_app(&mut resumed, build_rbac_grant_poke(1, &["write"])).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "POST-RESUME rbac-grant (priority 80) must emit: {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_registry_put_poke(2, &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "POST-RESUME registry-put (priority 90) must emit: {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_log_append_poke("audit-post", &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "POST-RESUME log-append (priority 130) must emit: {tags:?}",
    );

    Ok(())
}

/// Schema-change variant: snapshot a smaller kernel composition,
/// resume into a kernel with extra grafts injected at higher
/// priorities. Mirrors a real composition extension (the snapshot had
/// settle+mint+guard; the resume target added rbac+registry+log).
///
/// Active under the v0.2 load-defaults codegen (`nockup:load-defaults`
/// marker populated by graft-inject). The codegen replaces the marker
/// template's identity `++load` body with a `=/  defaults
/// ^*(versioned-state)` + `%_  defaults  <field>  ^*(<graft>-state) ...
/// ==` overlay, so the resumed kernel sees a fully-shaped state at B's
/// type rather than A's smaller noun — every B-graft poke arm reads its
/// state field at a defined axis. Pre-v0.2 builds (no marker, identity
/// load) silently dropped effects on every graft past the first
/// added-priority-band; this test is the regression guard.
///
/// Tradeoff: the overlay resets ALL graft state to type defaults on
/// resume, including state that existed in both A and B (settle/mint/
/// guard). Operators who need data preservation under a schema change
/// re-poke after resume. See README §"State checkpoints" for the
/// migration-semantics writeup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_into_larger_kernel_emits_effects_for_added_grafts() -> Result<()> {
    // Kernel A: settle + mint + guard (commitment family only — no
    // state/behavior grafts).
    let kernel_a = fixtures::compose_and_compile(
        "resume_schema_a",
        &["settle-graft", "mint-graft", "guard-graft"],
    )?;
    let app_hoon_a = kernel_a
        .parent()
        .expect("kernel_a out.jam has a parent")
        .join("hoon/app/app.hoon");

    // The larger kernel: the original grafts plus rbac (80),
    // registry (90), log (130). The three new grafts straddle the
    // priority threshold that matters (rbac=80 worked, registry=90
    // and above did not).
    let kernel_b = fixtures::compose_and_compile(
        "resume_schema_b",
        &[
            "settle-graft",
            "mint-graft",
            "guard-graft",
            "rbac-graft",
            "registry-graft",
            "log-graft",
        ],
    )?;

    // Boot kernel A, exercise it lightly so the snapshot has non-trivial
    // state to migrate.
    let mut harness_a = GraftTestHarness::boot(&kernel_a).await?;
    let mut mint = vesl_core::Mint::new();
    let root = mint.commit(&[b"schema-change-payload".as_ref()]);
    let tags = harness_a.register(1, &root).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "kernel A settle-register: {tags:?}",
    );

    // Snapshot kernel A's state.
    let snap_dir = tempfile::tempdir()?;
    let snap = snapshot(harness_a.app(), snap_dir.path(), &app_hoon_a).await?;
    drop(harness_a);

    // Resume from A's snapshot into B's jam — kernel-B's `++load`
    // receives kernel-A's state shape and must produce a B-shaped state.
    let mut resumed = resume(&kernel_b, &snap, "rm4-hard-bug-2-schema-change").await?;

    // The new grafts must accept pokes and emit effects. Each poke
    // touches a brand-new state field (rbac.state, registry.state,
    // log.state) that didn't exist in the snapshot.
    let payload = vec![0x02u8];
    let tags = poke_via_app(&mut resumed, build_rbac_grant_poke(1, &["read"])).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "POST-RESUME rbac-grant after schema change (priority 80): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_registry_put_poke(1, &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "POST-RESUME registry-put after schema change (priority 90): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_log_append_poke("audit", &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "POST-RESUME log-append after schema change (priority 130): {tags:?}",
    );

    Ok(())
}

async fn poke_via_app(app: &mut NockApp, slab: NounSlab) -> Result<vesl_core::PokeOutcome> {
    let outcome = match app.poke(SystemWire.to_wire(), slab).await {
        Ok(effects) => vesl_core::classify_effects(effects),
        Err(e) => vesl_core::PokeOutcome::Crashed {
            error: vesl_core::PokeCrashError::KernelPoke(e),
        },
    };
    Ok(outcome)
}

/// Exhaustive 3→6 graft schema-extension regression.
///
/// Mirrors a real composition extension with intermediate poke
/// state on every original graft (settle/mint/guard) before the
/// snapshot, then asserts each pre-snapshot poke emitted its expected
/// effect AND each post-resume poke against both the original and the
/// added grafts emits. This is the broader cousin of
/// `resume_into_larger_kernel_emits_effects_for_added_grafts` — that
/// test only exercises one pre-snapshot poke (settle-register).
///
/// Per-poke-band coverage:
/// - settle (priority 60): %settle-register, %settle-registered effect
/// - mint   (priority 70): %mint-commit, %mint-committed effect
/// - guard  (priority 75): %guard-register, %guard-registered effect
/// - rbac   (priority 80): %rbac-grant, %rbac-granted effect
/// - registry (priority 90): %registry-put, %registry-stored effect
/// - log    (priority 130): %log-append, %log-appended effect
///
/// Pre-snapshot covers settle/mint/guard; post-resume covers all six.
/// The test does NOT assert state-equivalence across resume — the v0.2
/// codegen resets graft state to type defaults on schema-extension
/// resume. The contract verified here is: every poke arm runs cleanly
/// and emits, regardless of whether the snapshot's noun shape matches
/// the resumed kernel's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_3_to_6_grafts_emits_for_old_and_new_grafts() -> Result<()> {
    let kernel_a = fixtures::compose_and_compile(
        "resume_3_to_6_a",
        &["settle-graft", "mint-graft", "guard-graft"],
    )?;
    let app_hoon_a = kernel_a
        .parent()
        .expect("kernel_a out.jam has a parent")
        .join("hoon/app/app.hoon");
    let kernel_b = fixtures::compose_and_compile(
        "resume_3_to_6_b",
        &[
            "settle-graft",
            "mint-graft",
            "guard-graft",
            "rbac-graft",
            "registry-graft",
            "log-graft",
        ],
    )?;

    // Boot kernel A and exercise each commitment-family graft so the
    // snapshot has non-trivial state on every A-graft slot.
    let mut harness_a = GraftTestHarness::boot(&kernel_a).await?;
    let mut mint_helper = vesl_core::Mint::new();
    let root = mint_helper.commit(&[b"resume-3-to-6-payload".as_ref()]);

    let tags = harness_a.register(1, &root).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "pre-snapshot settle-register: {tags:?}",
    );
    let tags = harness_a
        .poke_slab(build_mint_commit_poke(1, &root))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "pre-snapshot mint-commit: {tags:?}",
    );
    let tags = harness_a
        .poke_slab(build_guard_register_poke(1, &root))
        .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "pre-snapshot guard-register: {tags:?}",
    );

    // Snapshot kernel A. Drop the harness so the kernel actor frees
    // its state-jam handle before resume opens it.
    let snap_dir = tempfile::tempdir()?;
    let snap = snapshot(harness_a.app(), snap_dir.path(), &app_hoon_a).await?;
    drop(harness_a);

    // Resume into kernel B — A's snapshot has 3 graft fields, B's
    // versioned-state has 6, so `++load`'s overlay is exercised.
    let mut resumed = resume(&kernel_b, &snap, "rm4-load-defaults-3-to-6").await?;

    // Each post-resume poke must emit its effect tag. The original
    // grafts (settle/mint/guard) hit fields whose axes happen to align
    // between A and B; the new grafts (rbac/registry/log) hit fields
    // that didn't exist in A's noun and would have crashed the wrapper
    // pre-v0.2.
    let payload = vec![0x02u8];
    let new_root = mint_helper.commit(&[b"post-resume-payload".as_ref()]);

    let tags = poke_via_app(
        &mut resumed,
        vesl_core::build_settle_register_poke(2, &new_root),
    )
    .await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "POST-RESUME settle-register (priority 60): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_mint_commit_poke(2, &new_root)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "POST-RESUME mint-commit (priority 70): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_guard_register_poke(2, &new_root)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "POST-RESUME guard-register (priority 75): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_rbac_grant_poke(1, &["read"])).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "POST-RESUME rbac-grant (priority 80): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_registry_put_poke(1, &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "POST-RESUME registry-put (priority 90): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_log_append_poke("audit", &payload)).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "POST-RESUME log-append (priority 130): {tags:?}",
    );

    Ok(())
}
