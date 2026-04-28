//! Clock-graft lifecycle integration test (Phase 03 P3a.1).
//!
//! Composes a kernel from `[settle-graft, clock-graft]`, compiles via
//! `hoonc`, boots through `vesl-test`, and exercises the deterministic
//! event-counter clock.
//!
//! No hostile-input case: %clock-tick has no payload to cue (the cause
//! cell is just `[%clock-tick ~]`). C1 regression-guard pattern is
//! exercised by log-graft's lifecycle test (P3a.2).
//!
//! What this test pins:
//!   - peek before any tick reads back 0 (initial @da)
//!   - %clock-tick emits %clock-ticked with monotonic now
//!   - peek-after-tick reads back the new now
//!   - monotonicity holds across many ticks (no rollback, no skip)

mod fixtures;

use anyhow::Result;
use vesl_core::build_clock_tick_poke;
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clock_tick_monotonic_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "clock_lifecycle",
        &["settle-graft", "clock-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Pre-tick state: clock-now must read back 0.
    let now = peek_clock(&mut harness).await?;
    assert_eq!(now, 0, "clock-now must initialize to 0 (event-count source)");

    // First tick: now → 1.
    let tags = harness.poke_slab(build_clock_tick_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "clock-ticked"),
        "expected %clock-ticked on first tick; got {tags:?}",
    );
    let now = peek_clock(&mut harness).await?;
    assert_eq!(now, 1, "clock-now must advance to 1 after one tick");

    // Many ticks: monotonic, no skip.
    for expected in 2u64..=20 {
        let tags = harness.poke_slab(build_clock_tick_poke()).await?;
        assert!(
            tags.iter().any(|t| t == "clock-ticked"),
            "expected %clock-ticked at tick {expected}; got {tags:?}",
        );
        let got = peek_clock(&mut harness).await?;
        assert_eq!(got, expected, "clock-now must advance monotonically by 1");
    }

    Ok(())
}

/// Decode the `[%clock-now ~]` peek into a `u64` (event-count cast as @da).
async fn peek_clock(harness: &mut GraftTestHarness) -> Result<u64> {
    let bytes = fixtures::peek_keyless_atom(harness, "clock-now")
        .await?
        .unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}
