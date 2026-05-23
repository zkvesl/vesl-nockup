//! `%settle-note` typed gate-clean-deny via `%settle-denied`.
//!
//! Covers the kernel→hull boundary case that previously surfaced as
//! `Ok(vec![])`: the verify-gate runs to completion and returns `%.n`
//! (input fails the gate's check, no panic). Pre–typed-denial,
//! settle-graft `?>`d on the loobean, the NockApp driver flattened
//! the crash into an empty effect list, and the only signal was a
//! stderr mule-trace. The hull could not distinguish that from an
//! rbac-deny without scraping the kernel's slog.
//!
//! The fixture composes a kernel with `settle-graft` (default-hash
//! gate), registers a hull with the Merkle root of one payload, then
//! pokes `%settle-note` with a payload whose `expected-root` matches
//! the registered root (so the pre-gate replay/root-match checks pass)
//! but whose `data` field hashes to a different leaf. The default-hash
//! gate computes `(hash-leaf data) == expected-root`, sees `%.n`, and
//! the typed-denial settle-graft now emits
//! `[%settle-denied 'settle-graft: verify gate returned false']`.
//!
//! The test asserts (a) the harness reports
//! `PokeOutcome::Rejected { reason: RejectionReason::GateDenied { reason, .. } }`,
//! (b) `reason` carries the kernel cord, and (c) `effect_head_tags()`
//! surfaces `%settle-denied` (not `%settle-error` and not empty).

mod fixtures;

use anyhow::Result;
use vesl_core::{
    build_graft_single_leaf_payload_jammed, Mint, PokeOutcome, RejectionReason,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_note_gate_clean_deny_yields_typed_settle_denied() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "settle_gate_deny",
        &["settle-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Register hull 1 with the Merkle root of "real-data". The default-hash
    // gate verifies `(hash-leaf data) == expected-root`; we'll later poke
    // a note whose `data` is something else, so the gate returns %.n.
    let mut mint = Mint::new();
    let real_root = mint.commit(&[b"real-data".as_ref()]);
    let tags = harness.register(1, &real_root).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "settle-registered"),
        "register must succeed before gate-deny test; got {tags:?}",
    );

    // Build a payload whose note.root + expected-root both match the
    // registered root (so the pre-gate root/replay checks pass) but
    // whose `data` is "wrong-data" (so the default-hash gate computes
    // `(hash-leaf "wrong-data") != real_root` → %.n).
    let bad_payload = build_graft_single_leaf_payload_jammed(
        1,
        1,
        &real_root,
        b"wrong-data",
    );
    let outcome = harness.note(&bad_payload).await?;

    match &outcome {
        PokeOutcome::Rejected {
            reason: RejectionReason::GateDenied { reason, .. },
        } => {
            assert_eq!(
                reason, "settle-graft: verify gate returned false",
                "gate-deny reason cord must match the settle-graft.hoon emission",
            );
        }
        other => panic!(
            "expected Rejected::GateDenied from gate %.n, got {other:?}",
        ),
    }

    // Surface check via effect_head_tags: pre-typed-denial this would
    // have been an empty Vec; now it's the typed %settle-denied tag.
    let tags = outcome.effect_head_tags();
    assert_eq!(
        tags,
        vec!["settle-denied".to_string()],
        "expected single %settle-denied effect, got {tags:?}",
    );

    Ok(())
}
