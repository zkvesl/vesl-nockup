//! Log-graft lifecycle integration test.
//!
//! Composes a kernel from `[settle-graft, log-graft]`, compiles via
//! `hoonc`, boots through `vesl-test`, and exercises the append-only
//! audit trail plus the C1 hostile-input regression guard. log-graft
//! is the first cue site here, so this test is the C1 regression
//! analog of `queue_lifecycle.rs` for the behavior-graft band.
//!
//! What this test pins:
//!   - %log-append emits %log-appended for each well-formed payload
//!   - log-len peek tracks entry count
//!   - hostile jam → %log-error or accepted-as-noise, never panics
//!     (state-unchanged on the error path is the C1 contract)

mod fixtures;

use anyhow::Result;
use vesl_core::build_log_append_poke;
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_append_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "log_lifecycle",
        &["settle-graft", "log-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // jam(0) is the smallest well-formed jam — produces a body of `0`.
    const JAM_OF_ZERO: &[u8] = &[0x02];

    // Pre-append: log-len reads back 0.
    let len = peek_log_len(&mut harness).await?;
    assert_eq!(len, 0, "log-len must initialize to 0");

    // Append three valid entries with different tags.
    for tag in &["settle", "registry-put", "kv-set"] {
        let tags = harness.poke_slab(build_log_append_poke(tag, JAM_OF_ZERO)).await?.effect_head_tags();
        assert!(
            tags.iter().any(|t| t == "log-appended"),
            "expected %log-appended on valid append (tag={tag}); got {tags:?}",
        );
    }

    let len = peek_log_len(&mut harness).await?;
    assert_eq!(len, 3, "log-len after 3 appends");

    // C1 hostile-input regression guard. log-graft is the second cue
    // site to land (queue-graft was the first). Each input is either
    // truncated jam, all-ones, or random bytes. The kernel MUST
    // either accept (cue happens to decode) or emit %log-error.
    // It MUST NOT crash — that's the C1 contract.
    let hostile: &[&[u8]] = &[
        b"\x01",                 // truncated cell tag
        b"\xff",                 // all-ones single byte
        b"\xde\xad\xbe\xef",     // random
        b"\xfe\xfe\xfe\xfe\xfe", // long-ones / unaligned
    ];
    let len_before = peek_log_len(&mut harness).await?;
    for input in hostile {
        let tags = harness
            .poke_slab(build_log_append_poke("hostile", input))
            .await?.effect_head_tags();
        let appended = tags.iter().any(|t| t == "log-appended");
        let errored = tags.iter().any(|t| t == "log-error");
        assert!(
            appended || errored,
            "hostile input {input:?}: kernel must emit %log-appended or %log-error, never panic; got {tags:?}",
        );
        // C1 state-unchanged guarantee: on the error path, log-len
        // must NOT advance. Re-peek inside the loop to catch a
        // regression that updates state before the mule wraps.
        if errored && !appended {
            let len_now = peek_log_len(&mut harness).await?;
            assert_eq!(
                len_now, len_before,
                "log-len changed on %log-error path; state-unchanged contract violated for input {input:?}",
            );
        }
    }

    Ok(())
}

/// Decode the `[%log-len ~]` peek into a `u64`.
async fn peek_log_len(harness: &mut GraftTestHarness) -> Result<u64> {
    let bytes = fixtures::peek_keyless_atom(harness, "log-len")
        .await?
        .unwrap_or_default();
    let mut buf = [0u8; 8];
    for (i, byte) in bytes.iter().take(8).enumerate() {
        buf[i] = *byte;
    }
    Ok(u64::from_le_bytes(buf))
}
