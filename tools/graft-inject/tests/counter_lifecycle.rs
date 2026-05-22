//! Counter-graft lifecycle integration test.
//!
//! Composes a kernel from `[settle-graft, kv-graft, counter-graft]`,
//! compiles via `hoonc`, boots through `vesl-test`, and exercises
//! increment/reset/set/saturation paths.
//!
//! No hostile-input case: counter-graft has no `cue payload` site.
//! The C1 mule-wrap regression-guard pattern lands with queue-graft.

mod fixtures;

use anyhow::Result;
use vesl_core::{
    build_counter_increment_poke, build_counter_reset_poke, build_counter_set_poke,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn counter_increment_reset_set_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "counter_lifecycle",
        &["settle-graft", "kv-graft", "counter-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // %counter-increment on an unset name initializes to 1.
    let tags = harness.poke_slab(build_counter_increment_poke("requests")).await?;
    assert!(
        tags.iter().any(|t| t == "counter-incremented"),
        "expected %counter-incremented on first touch; got {tags:?}",
    );
    let got = peek_counter(&mut harness, "requests").await?;
    assert_eq!(got, Some(1u64), "counter must initialize to 1 on first increment");

    // Second increment: 1 -> 2.
    let _ = harness.poke_slab(build_counter_increment_poke("requests")).await?;
    let got = peek_counter(&mut harness, "requests").await?;
    assert_eq!(got, Some(2u64), "counter must increment to 2");

    // %counter-set overwrites.
    let tags = harness.poke_slab(build_counter_set_poke("requests", 100)).await?;
    assert!(
        tags.iter().any(|t| t == "counter-set"),
        "expected %counter-set on overwrite; got {tags:?}",
    );
    let got = peek_counter(&mut harness, "requests").await?;
    assert_eq!(got, Some(100u64), "counter-set must overwrite to 100");

    // %counter-reset zeros the counter.
    let tags = harness.poke_slab(build_counter_reset_poke("requests")).await?;
    assert!(
        tags.iter().any(|t| t == "counter-reset"),
        "expected %counter-reset; got {tags:?}",
    );
    let got = peek_counter(&mut harness, "requests").await?;
    assert_eq!(got, Some(0u64), "counter-reset must zero the counter");

    // %counter-reset on an unset name initializes to 0.
    let _ = harness.poke_slab(build_counter_reset_poke("fresh")).await?;
    let got = peek_counter(&mut harness, "fresh").await?;
    assert_eq!(got, Some(0u64), "reset-of-unset must initialize to 0");

    // Saturation: set to u64::MAX, then increment must error and
    // leave the counter unchanged.
    let _ = harness.poke_slab(build_counter_set_poke("ceiling", u64::MAX)).await?;
    let tags = harness.poke_slab(build_counter_increment_poke("ceiling")).await?;
    assert!(
        tags.iter().any(|t| t == "counter-error"),
        "increment past u64::MAX must emit %counter-error; got {tags:?}",
    );
    assert!(
        !tags.iter().any(|t| t == "counter-incremented"),
        "saturated increment must NOT emit %counter-incremented; got {tags:?}",
    );
    let got = peek_counter(&mut harness, "ceiling").await?;
    assert_eq!(got, Some(u64::MAX), "saturated counter must remain at u64::MAX");

    Ok(())
}

/// Decode a `[%counter-value name=@t]` peek into a `u64`.
async fn peek_counter(
    harness: &mut GraftTestHarness,
    name: &str,
) -> Result<Option<u64>> {
    let bytes = fixtures::peek_keyed_value(harness, "counter-value", name).await?;
    Ok(bytes.map(|b| {
        let mut buf = [0u8; 8];
        for (i, byte) in b.iter().take(8).enumerate() {
            buf[i] = *byte;
        }
        u64::from_le_bytes(buf)
    }))
}
