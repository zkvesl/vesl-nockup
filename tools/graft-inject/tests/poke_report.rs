//! Integration coverage for `vesl_test::PokeReport` slog capture.
//!
//! Composes a kernel with a single graft (`settle-graft`), boots it
//! through `GraftTestHarness`, then sends a poke whose head-atom tag
//! is *not* present in any of the kernel's cause variants. The
//! canonical scaffold's wrapper short-circuits via
//! `((soft cause) cause.input.ovum)` -> `~`, slogs `invalid cause`
//! at priority 1, and the harness's per-thread capture layer surfaces
//! it as `SlogWarning::InvalidCause`.
//!
//! The test closes the gap that commit `4452647` (Tool 1.B) left
//! open: the unit tests for `decode_cause_tag` proved the noun-string
//! parser, but did not exercise the end-to-end path
//! kernel-slog -> tracing-event -> SlogCaptureLayer -> PokeReport.

mod fixtures;

use anyhow::Result;
use nock_noun_rs::{make_tag_in, NounSlab};
use nockvm::noun::{D, T};
use vesl_test::{decode_cause_tag, GraftTestHarness, SlogWarning};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_cause_slogs_into_poke_report() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "poke_report",
        &["settle-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Build [%g-mint ~] — `g-mint` is a tag belonging to a graft
    // (mint-graft) that is NOT composed into this kernel, so
    // `(soft cause)` must reject it.
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "g-mint");
    let bogus = T(&mut slab, &[tag, D(0)]);
    slab.set_root(bogus);

    let report = harness.poke_slab_report(slab).await?;

    assert!(
        report.rejected_cause(),
        "expected at least one InvalidCause slog, got {:?}",
        report.slog_warnings,
    );

    let invalid_noun = report
        .slog_warnings
        .iter()
        .find_map(|w| match w {
            SlogWarning::InvalidCause { noun } => Some(noun.clone()),
            _ => None,
        })
        .expect("filtered above");

    assert_eq!(
        decode_cause_tag(&invalid_noun).as_deref(),
        Some("g-mint"),
        "decode_cause_tag should recover the rejected tag from {invalid_noun:?}",
    );

    let tags = report.outcome.effect_head_tags();
    assert!(
        tags.iter().all(|t| !t.starts_with("settle-")),
        "wrapper should short-circuit before any settle-* effect; got {tags:?}",
    );

    Ok(())
}
