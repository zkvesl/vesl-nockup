//! Batch-graft lifecycle integration test (Phase 03e P3e.1).
//!
//! Composes a kernel from `[settle-graft, batch-graft]`, compiles
//! via `hoonc`, boots through `vesl-test`, and exercises the
//! settlement-flush buffer.
//!
//! What this test pins:
//!   - %batch-init sets the threshold; peek confirms
//!   - %batch-add appends below threshold (no auto-flush)
//!   - %batch-add at threshold auto-flushes (emits both
//!     %batch-added and %batch-flushed in the same poke)
//!   - %batch-flush manual drain emits %batch-flushed even when
//!     pending is empty (boundary signal for downstream listeners)
//!   - C1 hostile-input regression guard on the cued intent
//!     payload — malformed jam emits %batch-error, state unchanged
//!     (per the C1 contract from queue-graft / log-graft / registry-
//!     graft tests)

mod fixtures;

use anyhow::Result;
use vesl_core::{build_batch_add_poke, build_batch_flush_poke, build_batch_init_poke};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_init_add_flush_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "batch_lifecycle",
        &["settle-graft", "batch-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // jam(0) is the smallest well-formed jam — produces an intent of `0`.
    const JAM_OF_ZERO: &[u8] = &[0x02];

    // Pre-init: pending-len reads back 0, threshold reads back 0.
    let len = peek_pending_len(&mut harness).await?;
    assert_eq!(len, 0, "pending-len must initialize to 0");
    let thr = peek_threshold(&mut harness).await?;
    assert_eq!(thr, 0, "threshold must initialize to 0");

    // Set threshold = 3.
    let tags = harness.poke_slab(build_batch_init_poke(3)).await?;
    assert!(
        tags.iter().any(|t| t == "batch-initialized"),
        "expected %batch-initialized; got {tags:?}",
    );
    let thr = peek_threshold(&mut harness).await?;
    assert_eq!(thr, 3, "threshold must reflect the init");

    // Add 2 intents — below threshold, no auto-flush.
    for _ in 0..2 {
        let tags = harness.poke_slab(build_batch_add_poke(JAM_OF_ZERO)).await?;
        assert!(
            tags.iter().any(|t| t == "batch-added"),
            "expected %batch-added; got {tags:?}",
        );
        assert!(
            !tags.iter().any(|t| t == "batch-flushed"),
            "below threshold; flush must NOT fire. got {tags:?}",
        );
    }
    let len = peek_pending_len(&mut harness).await?;
    assert_eq!(len, 2, "pending-len after 2 adds");

    // Add the 3rd intent — at threshold, must auto-flush.
    let tags = harness.poke_slab(build_batch_add_poke(JAM_OF_ZERO)).await?;
    assert!(
        tags.iter().any(|t| t == "batch-added"),
        "expected %batch-added on the trigger add; got {tags:?}",
    );
    assert!(
        tags.iter().any(|t| t == "batch-flushed"),
        "at threshold; flush MUST fire. got {tags:?}",
    );
    let len = peek_pending_len(&mut harness).await?;
    assert_eq!(len, 0, "pending-len must reset to 0 after auto-flush");

    // Manual flush on empty — must still emit %batch-flushed (the
    // boundary signal lets downstream listeners observe the empty
    // window deterministically).
    let tags = harness.poke_slab(build_batch_flush_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "batch-flushed"),
        "manual flush on empty must emit %batch-flushed; got {tags:?}",
    );

    // Add 1 intent then manual flush — bundle should carry that one.
    harness.poke_slab(build_batch_add_poke(JAM_OF_ZERO)).await?;
    let tags = harness.poke_slab(build_batch_flush_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "batch-flushed"),
        "expected %batch-flushed on manual drain; got {tags:?}",
    );
    let len = peek_pending_len(&mut harness).await?;
    assert_eq!(len, 0, "pending-len must reset to 0 after manual flush");

    // C1 hostile-input regression guard. Mirrors queue-graft and
    // log-graft. Each input is malformed jam; the kernel must emit
    // %batch-error or %batch-added (cue happens to decode), never
    // panic. State-unchanged on the error path is non-negotiable.
    let len_before = peek_pending_len(&mut harness).await?;
    let hostile: &[&[u8]] = &[
        b"\x01",                 // truncated cell tag
        b"\xff",                 // all-ones single byte
        b"\xde\xad\xbe\xef",     // random
        b"\xfe\xfe\xfe\xfe\xfe", // long-ones / unaligned
    ];
    for input in hostile {
        let tags = harness.poke_slab(build_batch_add_poke(input)).await?;
        let added = tags.iter().any(|t| t == "batch-added");
        let errored = tags.iter().any(|t| t == "batch-error");
        assert!(
            added || errored,
            "hostile input {input:?}: kernel must emit %batch-added or %batch-error, never panic; got {tags:?}",
        );
        if errored && !added {
            let len_now = peek_pending_len(&mut harness).await?;
            assert_eq!(
                len_now, len_before,
                "pending-len changed on %batch-error path; state-unchanged contract violated for input {input:?}",
            );
        }
    }

    Ok(())
}

async fn peek_pending_len(harness: &mut GraftTestHarness) -> Result<u64> {
    let bytes = fixtures::peek_keyless_atom(harness, "batch-pending-len")
        .await?
        .unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}

async fn peek_threshold(harness: &mut GraftTestHarness) -> Result<u64> {
    let bytes = fixtures::peek_keyless_atom(harness, "batch-threshold")
        .await?
        .unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}
