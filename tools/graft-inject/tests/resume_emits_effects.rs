//! RM4 §1 — HARD-BUG-2 regression: post-resume effect emission across
//! priority bands.
//!
//! `A_to_B.md` reported that pokes against rbac-graft (priority 80)
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
    build_log_append_poke, build_rbac_grant_poke, build_registry_put_poke, effect_head_tags,
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
    let tags = harness.poke_slab(build_rbac_grant_poke(1, &["read"])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "pre-snapshot rbac-grant (priority 80): {tags:?}",
    );
    let tags = harness.poke_slab(build_registry_put_poke(1, &payload)).await?;
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "pre-snapshot registry-put (priority 90): {tags:?}",
    );
    let tags = harness.poke_slab(build_log_append_poke("audit", &payload)).await?;
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

    // RM4 HARD-BUG-2 — post-resume each priority band must STILL emit.
    let tags = poke_via_app(&mut resumed, build_rbac_grant_poke(1, &["write"])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "POST-RESUME rbac-grant (priority 80) must emit (working in RM4): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_registry_put_poke(2, &payload)).await?;
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "POST-RESUME registry-put (priority 90) must emit (DROPPED in RM4 HARD-BUG-2): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_log_append_poke("audit-post", &payload)).await?;
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "POST-RESUME log-append (priority 130) must emit (DROPPED in RM4 HARD-BUG-2): {tags:?}",
    );

    Ok(())
}

/// RM4 §1 — HARD-BUG-2 (schema-change variant): snapshot a smaller
/// kernel composition, resume into a kernel with extra grafts injected
/// at higher priorities. Mirrors the actual A→B dogfood transition
/// (snapshot post-A had settle+mint+guard; B added rbac+registry+log).
///
/// **Currently a documented v0.1 limitation, not an active regression
/// target.** The marker template's `++load` arm is identity, so when
/// the resumed kernel has more state fields than the snapshot, the
/// new fields end up at undefined nockvm axes and `~(has by ...)` /
/// other map operations on those slots silently fail inside the
/// wrapper's mule guard — effects come back empty.
///
/// The fix lives in graft-inject's codegen: the `++load` arm needs a
/// new marker (e.g., `nockup:load-defaults`) populated with each
/// graft's `++new-state` default for the schema-extension migration
/// case. That's v0.2 scope (deferred per resolution.md §1.2 risk
/// note). When that lands, remove the `#[ignore]` and this test gates
/// the migration.
///
/// The same-kernel test above is the regression guard for what does
/// work today: snapshot/resume against a single composition.
#[ignore = "RM4 §1 — schema-change resume requires graft-inject migration codegen (v0.2)"]
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

    // Kernel B: A's grafts plus rbac (80), registry (90), log (130).
    // The three new grafts straddle the priority threshold RM4 said
    // matters (rbac=80 worked, registry=90 and above did not).
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
    let tags = harness_a.register(1, &root).await?;
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
    let tags = poke_via_app(&mut resumed, build_rbac_grant_poke(1, &["read"])).await?;
    assert!(
        tags.iter().any(|t| t == "rbac-granted"),
        "POST-RESUME rbac-grant after schema change (priority 80): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_registry_put_poke(1, &payload)).await?;
    assert!(
        tags.iter().any(|t| t == "registry-stored"),
        "POST-RESUME registry-put after schema change (priority 90, RM4 fail point): {tags:?}",
    );
    let tags = poke_via_app(&mut resumed, build_log_append_poke("audit", &payload)).await?;
    assert!(
        tags.iter().any(|t| t == "log-appended"),
        "POST-RESUME log-append after schema change (priority 130, RM4 fail point): {tags:?}",
    );

    Ok(())
}

async fn poke_via_app(app: &mut NockApp, slab: NounSlab) -> Result<Vec<String>> {
    let effects = app
        .poke(SystemWire.to_wire(), slab)
        .await
        .map_err(|e| anyhow::anyhow!("poke failed: {e}"))?;
    Ok(effect_head_tags(&effects))
}
