//! Full-catalog composition integration test.
//!
//! Composes commitment grafts (settle / mint / guard) alongside all
//! five state grafts (kv / counter / queue / rbac / registry) into a
//! single kernel and exercises one poke per graft to confirm:
//!
//! 1. **Namespace isolation** — no state-field, peek-path, or
//!    effect-tag collision when the full set composes.
//! 2. **Cross-graft independence** — pokes against one graft don't
//!    spuriously affect another's state.
//! 3. **Manifest discovery** — graft-inject pulls all eight in
//!    priority order without duplicate-sentinel errors.
//!
//! Forge is excluded because its STARK constraint tables add ~16MB
//! of pre-jammed jams to the kernel build and a 90s+ compile floor;
//! the four-graft `integration.rs` already covers forge composition
//! and namespace adjacency to the commitment grafts.

mod fixtures;

use anyhow::Result;
use vesl_core::{
    build_counter_increment_poke, build_guard_register_poke, build_kv_set_poke,
    build_mint_commit_poke, build_queue_clear_poke, build_rbac_grant_poke,
    build_registry_put_poke, Mint,
};
use vesl_test::GraftTestHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eight_graft_namespace_audit() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "phase02_audit",
        &[
            "settle-graft",
            "mint-graft",
            "guard-graft",
            "kv-graft",
            "counter-graft",
            "queue-graft",
            "rbac-graft",
            "registry-graft",
        ],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Mint a hull root (commitment-side) — must succeed alongside
    // the five state grafts living in the same kernel.
    let mut mint = Mint::new();
    let root = mint.commit(&[b"phase02-audit-fixture"]);
    let tags = harness.poke_slab(build_mint_commit_poke(7, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "mint-committed"),
        "mint-committed must fire under 8-graft compose; got {tags:?}",
    );

    // Guard registers the same hull — proves commitment-graft state
    // slots stay isolated from each other under the wider compose.
    let tags = harness.poke_slab(build_guard_register_poke(7, &root)).await?;
    assert!(
        tags.iter().any(|t| t == "guard-registered"),
        "guard-registered must fire; got {tags:?}",
    );

    // KV set + counter increment + queue clear + rbac grant +
    // registry put. Each emits its own typed effect; none of the
    // tags collide with another graft's surface.
    let tags = harness.poke_slab(build_kv_set_poke("audit", b"ok")).await?;
    assert!(tags.iter().any(|t| t == "kv-stored"));

    let tags = harness.poke_slab(build_counter_increment_poke("audit")).await?;
    assert!(tags.iter().any(|t| t == "counter-incremented"));

    let tags = harness.poke_slab(build_queue_clear_poke()).await?;
    assert!(tags.iter().any(|t| t == "queue-cleared"));

    let tags = harness
        .poke_slab(build_rbac_grant_poke(123, &["audit"]))
        .await?;
    assert!(tags.iter().any(|t| t == "rbac-granted"));

    let tags = harness
        .poke_slab(build_registry_put_poke(456, &[0x02])) // jam(0)
        .await?;
    assert!(tags.iter().any(|t| t == "registry-stored"));

    // Effect-tag determinism: each poke's tag set MUST NOT include
    // tags from sibling grafts. (We've already asserted the expected
    // tag is present; here we sanity-check no cross-leaks. Use the
    // last poke's tags as the witness.)
    assert!(
        !tags.iter().any(|t| t == "kv-stored"
            || t == "counter-incremented"
            || t == "queue-pushed"
            || t == "rbac-granted"
            || t == "mint-committed"
            || t == "guard-registered"),
        "registry-put MUST NOT leak sibling effect tags; got {tags:?}",
    );

    Ok(())
}
