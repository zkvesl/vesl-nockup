//! State-equivalence test for `vesl-checkpoint` snapshot/resume.
//!
//! Closes the validation gap upstream tests left open: the
//! `vesl-core/crates/vesl-checkpoint/tests/end_to_end.rs` test boots
//! `templates/counter/out.jam`, snapshots, drops, resumes — proving
//! the bytes survive a round-trip and the API contract holds. But
//! `counter` doesn't compose any v0.1 graft, so peek-after-resume
//! state assertions are unavailable upstream.
//!
//! This test runs the full lifecycle:
//!   1. Compose a kernel with `settle-graft` via the existing
//!      `compose_and_compile` machinery.
//!   2. Boot, register hull 1 with a known root.
//!   3. Snapshot to a tempdir.
//!   4. Drop the live harness (and its NockApp).
//!   5. Resume from the snapshot.
//!   6. Peek `[%settle-registered hull=1 ~]` on the resumed app and
//!      assert the stored root equals the pre-snapshot root.
//!
//! If this test passes, RM2's "does state from earlier profiles
//! survive through composition changes?" question can finally be
//! exercised.

mod fixtures;

use anyhow::Result;
use nockapp::noun::slab::NounSlab;
use vesl_checkpoint::{resume, snapshot};
use vesl_core::{build_hull_peek_path, unwrap_triple_unit_atom, Mint};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_register_state_survives_snapshot_resume() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "checkpoint_lifecycle",
        &["settle-graft"],
    )?;
    let app_hoon = jam_path
        .parent()
        .expect("compose_and_compile out.jam has a parent")
        .join("hoon/app/app.hoon");

    // 1) Boot + register hull 1 with a known root.
    let mut harness = GraftTestHarness::boot(&jam_path).await?;
    let mut mint = Mint::new();
    let root = mint.commit(&[b"checkpoint-test-payload".as_ref()]);
    let tags = harness.register(1, &root).await?;
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "register hull 1 must succeed, got effects {tags:?}",
    );
    let pre_snapshot_root = peek_settle_root(&mut harness, 1).await?;
    assert_eq!(
        pre_snapshot_root, root_bytes(&root),
        "sanity: peek before snapshot returns the registered root",
    );

    // 2) Snapshot.
    let snap_dir = tempfile::tempdir()?;
    let snap = snapshot(harness.app(), snap_dir.path(), &app_hoon).await?;
    assert!(snap.state_jam().exists(), "snapshot wrote state.jam");

    // 3) Drop harness (and its NockApp) before resuming.
    drop(harness);

    // 4) Resume.
    let mut resumed_app = resume(&jam_path, &snap, "checkpoint-resume-test").await?;

    // 5) Peek on the resumed app — the state should still hold the
    //    registered hull's root.
    let peek_path: NounSlab = build_hull_peek_path("settle-root", 1);
    let peek_result = resumed_app
        .peek(peek_path)
        .await
        .map_err(|e| anyhow::anyhow!("peek on resumed app failed: {e}"))?;
    let post_resume_root = unwrap_triple_unit_atom(&peek_result)
        .expect("settle-registered hull=1 must yield a value post-resume");
    assert_eq!(
        post_resume_root, root_bytes(&root),
        "post-resume root must match pre-snapshot root",
    );

    Ok(())
}

async fn peek_settle_root(
    harness: &mut GraftTestHarness,
    hull: u64,
) -> Result<Vec<u8>> {
    let result = harness.peek_raw(build_hull_peek_path("settle-root", hull)).await?;
    unwrap_triple_unit_atom(&result)
        .ok_or_else(|| anyhow::anyhow!("settle-root hull={hull} returned absent"))
}

fn root_bytes(root: &vesl_core::Tip5Hash) -> Vec<u8> {
    let bytes = vesl_core::tip5_to_atom_le_bytes(root);
    let last = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    bytes[..last].to_vec()
}
