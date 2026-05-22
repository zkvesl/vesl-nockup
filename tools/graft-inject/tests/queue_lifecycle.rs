//! Queue-graft lifecycle integration test.
//!
//! Composes a kernel from
//! `[settle-graft, kv-graft, counter-graft, queue-graft]`, compiles
//! via `hoonc`, boots through `vesl-test`, and exercises
//! push/pop/clear plus the C1 hostile-input regression guard.
//!
//! This is the first lifecycle test with a hostile-input
//! case (queue-graft is the first state-graft to cue caller-supplied
//! bytes inside its poke body). The pattern set here — send raw
//! malformed jam, assert the kernel emits a typed error or accepts
//! it, never panics — repeats for registry-graft.

mod fixtures;

use anyhow::Result;
use vesl_core::{
    build_queue_clear_poke, build_queue_pop_poke, build_queue_push_poke,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_push_pop_clear_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "queue_lifecycle",
        &[
            "settle-graft",
            "kv-graft",
            "counter-graft",
            "queue-graft",
        ],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // jam(0) is the smallest well-formed jam — produces a body of `0`.
    // We use it as a trivially-valid push payload.
    const JAM_OF_ZERO: &[u8] = &[0x02];

    // Push three valid bodies.
    for _ in 0..3 {
        let tags = harness.poke_slab(build_queue_push_poke(JAM_OF_ZERO)).await?;
        assert!(
            tags.iter().any(|t| t == "queue-pushed"),
            "expected %queue-pushed on valid push; got {tags:?}",
        );
    }

    let len = peek_len(&mut harness).await?;
    assert_eq!(len, 3, "queue-len after 3 pushes");

    // Pop three. Each emits %queue-popped.
    for i in 0..3 {
        let tags = harness.poke_slab(build_queue_pop_poke()).await?;
        assert!(
            tags.iter().any(|t| t == "queue-popped"),
            "expected %queue-popped on pop {i}; got {tags:?}",
        );
    }

    let len = peek_len(&mut harness).await?;
    assert_eq!(len, 0, "queue-len after draining all 3");

    // Pop on empty MUST emit %queue-popped (with job=~) — not error.
    let tags = harness.poke_slab(build_queue_pop_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "queue-popped"),
        "empty-pop must emit %queue-popped (not %queue-error); got {tags:?}",
    );
    assert!(
        !tags.iter().any(|t| t == "queue-error"),
        "empty-pop must not emit %queue-error; got {tags:?}",
    );

    // Push then clear: len → 0.
    harness.poke_slab(build_queue_push_poke(JAM_OF_ZERO)).await?;
    harness.poke_slab(build_queue_push_poke(JAM_OF_ZERO)).await?;
    let tags = harness.poke_slab(build_queue_clear_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "queue-cleared"),
        "expected %queue-cleared; got {tags:?}",
    );
    let len = peek_len(&mut harness).await?;
    assert_eq!(len, 0, "queue-len after clear");

    // C1 hostile-input regression guard. Each input is either
    // truncated jam, all-ones, or random bytes. The kernel MUST
    // either accept (cue happens to decode) or emit %queue-error.
    // It MUST NOT crash — that's the C1 contract.
    let hostile: &[&[u8]] = &[
        b"\x01",                 // truncated cell tag
        b"\xff",                 // all-ones single byte
        b"\xde\xad\xbe\xef",     // random
        b"\xfe\xfe\xfe\xfe\xfe", // long-ones / unaligned
    ];
    for input in hostile {
        let tags = harness.poke_slab(build_queue_push_poke(input)).await?;
        let pushed = tags.iter().any(|t| t == "queue-pushed");
        let errored = tags.iter().any(|t| t == "queue-error");
        assert!(
            pushed || errored,
            "hostile input {input:?}: kernel must emit %queue-pushed or %queue-error, never panic; got {tags:?}",
        );
    }

    Ok(())
}

async fn peek_len(harness: &mut GraftTestHarness) -> Result<u64> {
    let bytes = fixtures::peek_keyless_atom(harness, "queue-len")
        .await?
        .unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}
