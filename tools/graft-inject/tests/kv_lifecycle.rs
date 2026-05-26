//! KV-graft lifecycle integration test.
//!
//! Composes a kernel from `[settle-graft, kv-graft]`, compiles it
//! through `hoonc`, boots it via `vesl-test`, and exercises the
//! set/overwrite/delete/peek paths for the loose key-value store.
//!
//! The bare scaffold's `versioned-state` is empty without a graft
//! providing state; `settle-graft` rides along here purely so the
//! composed kernel has a non-trivial state slot to graft `kv-state`
//! beside. The full-catalog test covers a state-only smoke composition.
//!
//! No hostile-input case: kv-graft has no `cue payload` site (keys
//! and values arrive as typed atoms in the cause cell). The C1
//! mule-wrap regression-guard pattern lands with queue-graft.

mod fixtures;

use anyhow::Result;
use vesl_core::{build_kv_delete_poke, build_kv_set_poke};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kv_set_overwrite_delete_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "kv_lifecycle",
        &["settle-graft", "kv-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // %kv-set on two distinct keys.
    let tags = harness.poke_slab(build_kv_set_poke("greeting", b"hello")).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "kv-stored"),
        "expected %kv-stored on first set; got {tags:?}",
    );
    let tags = harness.poke_slab(build_kv_set_poke("count", b"\x2a")).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "kv-stored"),
        "expected %kv-stored on second set; got {tags:?}",
    );

    let got = fixtures::peek_keyed_value(&mut harness, "kv-value", "greeting").await?;
    assert_eq!(got.as_deref(), Some(&b"hello"[..]), "peek greeting after set");
    let got = fixtures::peek_keyed_value(&mut harness, "kv-value", "count").await?;
    assert_eq!(got.as_deref(), Some(&b"\x2a"[..]), "peek count after set");

    // Overwrite of an existing key MUST succeed (loose-store semantics).
    let tags = harness.poke_slab(build_kv_set_poke("greeting", b"goodbye")).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "kv-stored"),
        "expected %kv-stored on overwrite; got {tags:?}",
    );
    let got = fixtures::peek_keyed_value(&mut harness, "kv-value", "greeting").await?;
    assert_eq!(
        got.as_deref(),
        Some(&b"goodbye"[..]),
        "peek greeting after overwrite must surface new value",
    );

    // %kv-delete on an existing key.
    let tags = harness.poke_slab(build_kv_delete_poke("greeting")).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "kv-deleted"),
        "expected %kv-deleted on existing key; got {tags:?}",
    );
    let got = fixtures::peek_keyed_value(&mut harness, "kv-value", "greeting").await?;
    assert!(got.is_none(), "peek greeting after delete should be ~; got {got:?}");

    // %kv-delete on a missing key MUST be idempotent (noop-success).
    let tags = harness.poke_slab(build_kv_delete_poke("never-set")).await?.effect_head_tags();
    assert!(
        tags.iter().any(|t| t == "kv-deleted"),
        "delete-missing must emit %kv-deleted, not %kv-error; got {tags:?}",
    );
    assert!(
        !tags.iter().any(|t| t == "kv-error"),
        "delete-missing must not emit %kv-error; got {tags:?}",
    );

    // The other key is unaffected by either delete.
    let got = fixtures::peek_keyed_value(&mut harness, "kv-value", "count").await?;
    assert_eq!(got.as_deref(), Some(&b"\x2a"[..]), "count must survive deletes");

    Ok(())
}
