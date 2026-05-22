//! Validate-graft lifecycle integration test.
//!
//! Composes a kernel from `[settle-graft, validate-graft]`, compiles
//! via `hoonc`, boots through `vesl-test`, and exercises the
//! runtime-installable rule machinery + the prelude short-circuit
//! semantics landed in 03b.
//!
//! What this test pins:
//!   - With no rules installed, every poke runs through the normal
//!     ?- switch (prelude falls through transparently)
//!   - %validate-init installs rules; the peek surface confirms
//!   - With a rule installed, a poke whose body trips the rule
//!     emits %validate-rejected and the normal arm does NOT run
//!   - %validate-clear removes rules; subsequent pokes fall through
//!     again
//!
//! The test target is the bare `%cause` cause from the kernel
//! scaffold: `[%cause ~]`. Its body is `~`, which trips the v0.1
//! `%non-empty` rule. The kernel's existing `%cause` arm just slogs
//! and emits no effects, so observing the absence of effects is
//! "rules cleared" and the presence of `%validate-rejected` is
//! "rule fired."

mod fixtures;

use anyhow::Result;
use vesl_core::{build_validate_clear_poke, build_validate_init_poke, ValidateRule};
use vesl_test::GraftTestHarness;

fn build_bare_cause_poke() -> nock_noun_rs::NounSlab {
    use nock_noun_rs::make_tag_in;
    use nockvm::noun::{D, T};
    let mut slab = nock_noun_rs::NounSlab::new();
    let tag = make_tag_in(&mut slab, "cause");
    let poke = T(&mut slab, &[tag, D(0)]);
    slab.set_root(poke);
    slab
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_install_reject_clear_paths() -> Result<()> {
    let jam_path = fixtures::compose_and_compile(
        "validate_lifecycle",
        &["settle-graft", "validate-graft"],
    )?;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Pre-install: %cause poke runs through the normal arm. The
    // scaffold's %cause arm emits nothing visible; what matters is
    // that NO %validate-rejected effect surfaces.
    let tags = harness.poke_slab(build_bare_cause_poke()).await?;
    assert!(
        !tags.iter().any(|t| t == "validate-rejected"),
        "no rules installed; %cause must not be rejected. got {tags:?}",
    );

    // Install a non-empty rule for cause-tag = `%cause`. The %cause
    // cell is `[%cause ~]`, so `+.act = ~` and the rule will trip
    // on every subsequent %cause poke.
    let tags = harness
        .poke_slab(build_validate_init_poke("cause", &[ValidateRule::NonEmpty]))
        .await?;
    assert!(
        tags.iter().any(|t| t == "validate-rules-installed"),
        "expected %validate-rules-installed effect; got {tags:?}",
    );

    // Now %cause must short-circuit to %validate-rejected.
    let tags = harness.poke_slab(build_bare_cause_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "validate-rejected"),
        "rule installed; %cause must short-circuit. got {tags:?}",
    );

    // Clear the rules for `%cause`. Subsequent %cause pokes must
    // fall through again — no %validate-rejected.
    let tags = harness
        .poke_slab(build_validate_clear_poke("cause"))
        .await?;
    assert!(
        tags.iter().any(|t| t == "validate-rules-cleared"),
        "expected %validate-rules-cleared; got {tags:?}",
    );
    let tags = harness.poke_slab(build_bare_cause_poke()).await?;
    assert!(
        !tags.iter().any(|t| t == "validate-rejected"),
        "rules cleared; %cause must not be rejected. got {tags:?}",
    );

    Ok(())
}
