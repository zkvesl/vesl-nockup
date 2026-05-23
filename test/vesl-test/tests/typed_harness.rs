//! Integration test for the codegen-emitted typed `GraftTestHarness`
//! methods + per-graft outcome extension traits.
//!
//! Boots a `counter-graft` kernel, drives the lifecycle through the
//! generated `counter_set` / `counter_increment` / `counter_reset`
//! methods, and confirms both the raw `PokeOutcome` and the typed
//! `CounterOutcome` decoded via [`CounterOutcomeExt`] surface the
//! expected variants.

mod fixtures;

use anyhow::Result;
use vesl_test::{CounterOutcome, CounterOutcomeExt, GraftTestHarness};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn counter_lifecycle_through_typed_methods() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "typed_harness_counter",
        &["counter-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // counter_set seeds the counter to a known value. Generated method
    // delegates to vesl_core::build_counter_set_poke under the hood.
    let outcome = harness.counter_set("clicks", 41).await?;
    let counter = outcome.as_counter_outcome();
    assert!(
        matches!(counter, CounterOutcome::Accepted { .. }),
        "expected Accepted for counter_set, got {counter:?}",
    );

    // counter_increment ticks it +1.
    let outcome = harness.counter_increment("clicks").await?;
    assert!(
        matches!(outcome.as_counter_outcome(), CounterOutcome::Accepted { .. }),
        "expected Accepted for counter_increment",
    );

    // counter_reset to verify a third arm is wired and routes the same.
    let outcome = harness.counter_reset("clicks").await?;
    assert!(
        matches!(outcome.as_counter_outcome(), CounterOutcome::Accepted { .. }),
        "expected Accepted for counter_reset",
    );

    // Saturation path — set to u64::MAX, then increment. Counter-graft
    // emits `[%counter-error 'counter-graft: counter saturated at 2^64']`
    // which the typed outcome decodes as `CounterOutcome::Error { msg }`.
    let outcome = harness.counter_set("max", u64::MAX).await?;
    assert!(matches!(outcome.as_counter_outcome(), CounterOutcome::Accepted { .. }));

    let outcome = harness.counter_increment("max").await?;
    match outcome.as_counter_outcome() {
        CounterOutcome::Error { msg } => {
            assert!(
                msg.contains("counter-graft") && msg.contains("saturated"),
                "saturation error cord shape unexpected: `{msg}`",
            );
        }
        other => panic!("expected CounterOutcome::Error for saturation, got {other:?}"),
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_grafts_outcome_collapses_to_unknown() -> Result<()> {
    // When a counter-graft kernel emits a counter-tagged effect, the
    // SettleOutcomeExt decoder must surface `Unknown` rather than
    // misinterpret the effect. Confirms the per-graft cord-prefix
    // routing in the generated extension trait impls.
    use vesl_test::{SettleOutcome, SettleOutcomeExt};

    let jam_path = fixtures::compose_and_compile(
        "typed_harness_counter_settle_view",
        &["counter-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    let outcome = harness.counter_set("c", 1).await?;
    let settle = outcome.as_settle_outcome();
    assert!(
        matches!(settle, SettleOutcome::Accepted { .. }),
        "counter Accepted should map to settle Accepted (Accepted is graft-agnostic), got {settle:?}",
    );

    let outcome = harness.counter_set("max", u64::MAX).await?;
    assert!(matches!(outcome.as_settle_outcome(), SettleOutcome::Accepted { .. }));
    let outcome = harness.counter_increment("max").await?;
    let settle = outcome.as_settle_outcome();
    assert!(
        matches!(settle, SettleOutcome::Unknown),
        "counter-graft saturation cord must NOT decode as a settle error; got {settle:?}",
    );

    Ok(())
}
