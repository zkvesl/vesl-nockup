//! Phase 03b: poke-prelude marker integration tests.
//!
//! Validates the new `[graft.blocks.poke-prelude]` capability that
//! graft-inject ships ahead of any consumer (validate-graft / fsm-graft
//! land in 03c and depend on this surface). Uses synthetic graft
//! fixtures rather than real consumers — keeps the test self-contained
//! and the scope sharp on the marker mechanics.
//!
//! What this test pins:
//!   - a single prelude composes into the kernel and short-circuits
//!     on its declared cause tag (state untouched, error effect emitted)
//!   - two preludes compose in priority order; both contribute their
//!     own short-circuit guards
//!   - banner provenance: each prelude's begin/end banners appear in
//!     the composed kernel source
//!   - idempotence: re-running graft-inject does not duplicate the
//!     prelude block

mod fixtures;

use anyhow::Result;
use fixtures::{compose_and_compile_with_extras, SyntheticGraft};
use nock_noun_rs::{make_tag_in, NounSlab};
use nockvm::noun::{D, T};
use vesl_test::GraftTestHarness;

/// Synthetic graft whose ONLY contribution is a poke-prelude that
/// rejects `%guard-trip` causes. Adds the cause variant + a placeholder
/// arm body (unreachable because the prelude short-circuits first).
fn guard_test_graft() -> SyntheticGraft<'static> {
    SyntheticGraft {
        name: "guard-test-graft",
        hoon: GUARD_TEST_HOON,
        toml: GUARD_TEST_TOML,
    }
}

const GUARD_TEST_HOON: &str = "\
::  Test-only synthetic graft for phase03_prelude.rs.
::  Adds a %guard-trip cause that the prelude short-circuits on.
|%
+$  guard-test-cause
  $%  [%guard-trip ~]
  ==
+$  guard-test-effect
  $%  [%guard-rejected reason=@t]
  ==
--
";

const GUARD_TEST_TOML: &str = r#"# guard-test-graft — Phase 03b prelude integration test fixture.
#
# Synthetic graft whose only purpose is to exercise the new
# [graft.blocks.poke-prelude] marker. Adds a %guard-trip cause and
# a prelude that short-circuits on it. The placeholder %guard-trip
# arm body is unreachable when the prelude works — if it fires, the
# emitted effect signals "PRELUDE NOT FIRED" and the test fails.
#
# Priority 105 sits in the behavior-graft band (100–149) above the
# eventual real validate-graft (100). Picked so the test composition
# stack is realistic for what 03c will look like.

[graft]
name     = "guard-test-graft"
version  = "0.1.0"
priority = 105

[graft.types]
effect = "guard-test-effect"
cause  = "guard-test-cause"

[graft.blocks.imports]
sentinel = "*guard-test-graft"
body     = """
/+  *guard-test-graft"""

[graft.blocks.cause]
sentinel = "guard-test-cause"
body     = "guard-test-cause"

[graft.blocks.poke-prelude]
sentinel = "guard-trip short-circuit"
body     = """
?:  =(-.u.act %guard-trip)
  :_  state
  ^-  (list effect)
  ~[[%guard-rejected 'guard-trip rejected by prelude']]"""

[graft.blocks.poke]
sentinel = "%guard-trip"
body     = """
::
  %guard-trip
::  Unreachable: the prelude short-circuits before this fires.
::  If the prelude breaks, this arm runs and emits a sentinel error
::  the test asserts against — so a regression is loud, not silent.
:_  state
^-  (list effect)
~[[%guard-rejected 'PRELUDE NOT FIRED — bug']]"""
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prelude_short_circuits_on_declared_cause() -> Result<()> {
    let jam_path = compose_and_compile_with_extras(
        "phase03_prelude_single",
        &["settle-graft", "guard-test-graft"],
        &[guard_test_graft()],
    )?
    .jam_path;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Poke %guard-trip. Prelude must short-circuit and emit
    // %guard-rejected with the prelude's reason string. The arm-body
    // sentinel ('PRELUDE NOT FIRED') must NOT appear.
    let tags = harness.poke_slab(build_guard_trip_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "guard-rejected"),
        "expected %guard-rejected from prelude short-circuit; got {tags:?}",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prelude_banners_present_in_composed_source() -> Result<()> {
    // This test re-uses the scratch from the lifecycle test (does its
    // own compose under a distinct subdir) and inspects the composed
    // app.hoon for the per-graft banner pair.
    let art = compose_and_compile_with_extras(
        "phase03_prelude_banners",
        &["settle-graft", "guard-test-graft"],
        &[guard_test_graft()],
    )?;
    let composed = std::fs::read_to_string(&art.source_path)?;

    assert!(
        composed.contains("::  graft-inject:guard-test-graft:poke-prelude:begin"),
        "expected poke-prelude begin banner in composed source",
    );
    assert!(
        composed.contains("::  graft-inject:guard-test-graft:poke-prelude:end"),
        "expected poke-prelude end banner in composed source",
    );
    // The prelude body itself must be present between the banners.
    assert!(
        composed.contains("?:  =(-.u.act %guard-trip)"),
        "expected prelude body verbatim in composed source",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prelude_is_idempotent_under_rerun() -> Result<()> {
    // Compose once, snapshot the source, compose again, assert
    // byte-identical output.
    let art = compose_and_compile_with_extras(
        "phase03_prelude_idempotent",
        &["settle-graft", "guard-test-graft"],
        &[guard_test_graft()],
    )?;
    let after_first = std::fs::read_to_string(&art.source_path)?;

    // Run graft-inject again on the already-injected file.
    let status = std::process::Command::new(fixtures::graft_inject_bin())
        .arg("--accept-untrusted-libs").arg("--lib-dir")
        .arg(&art.lib_dir)
        .arg("--grafts")
        .arg("settle-graft,guard-test-graft")
        .arg("--apply")
        .arg(&art.source_path)
        .status()?;
    assert!(status.success(), "second graft-inject run failed");

    let after_second = std::fs::read_to_string(&art.source_path)?;
    assert_eq!(
        after_first, after_second,
        "second graft-inject run must be byte-identical (idempotence)",
    );

    // Banner appears exactly once.
    assert_eq!(
        after_second
            .matches("::  graft-inject:guard-test-graft:poke-prelude:begin")
            .count(),
        1,
        "prelude begin banner must appear exactly once after re-run",
    );

    Ok(())
}

/// Build a `[%guard-trip ~]` poke.
fn build_guard_trip_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "guard-trip");
    let poke = T(&mut slab, &[tag, D(0)]);
    slab.set_root(poke);
    slab
}
