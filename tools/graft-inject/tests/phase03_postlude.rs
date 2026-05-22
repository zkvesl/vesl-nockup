//! Poke-postlude marker integration tests.
//!
//! Validates the new `[graft.blocks.poke-postlude]` capability that
//! graft-inject ships ahead of any consumer (index-graft lands in 03d
//! and uses prelude+postlude together for write-path reconciliation).
//! Uses synthetic graft fixtures rather than real consumers — keeps
//! the test self-contained and the scope sharp on the marker mechanics.
//!
//! What this test pins:
//!   - a single postlude composes into the kernel and rebinds `out`
//!     to add an effect the test can detect alongside the original
//!   - banner provenance: each postlude's begin/end banners appear
//!     in the composed kernel source
//!   - idempotence: re-running graft-inject does not duplicate the
//!     postlude block
//!
//! Postlude semantics: each postlude runs after the `?-` switch, with
//! the switch's `[(list effect) _state]` result bound to `out`.
//! Postludes rebind `out` to transform either component. The synthetic
//! `tap-graft` here adds a `%tap-observed` effect to the head of the
//! effect list — proving the postlude saw `out` and could mutate it.

mod fixtures;

use anyhow::Result;
use fixtures::{compose_and_compile_with_extras, SyntheticGraft};
use nock_noun_rs::{make_tag_in, NounSlab};
use nockvm::noun::{D, T};
use vesl_test::GraftTestHarness;

fn tap_graft() -> SyntheticGraft<'static> {
    SyntheticGraft {
        name: "tap-graft",
        hoon: TAP_HOON,
        toml: TAP_TOML,
    }
}

const TAP_HOON: &str = "\
::  Test-only synthetic graft for phase03_postlude.rs.
::  Adds a %tap-poke cause and a postlude that prepends a
::  %tap-observed effect to the result of every poke (whether the
::  arm body emitted anything or not).
|%
+$  tap-cause
  $%  [%tap-poke ~]
  ==
+$  tap-effect
  $%  [%tap-observed ~]
      [%tap-poked ~]
  ==
--
";

const TAP_TOML: &str = r#"# tap-graft — postlude integration test fixture.
#
# Synthetic graft for the new [graft.blocks.poke-postlude] marker.
# Adds a %tap-poke cause whose arm emits %tap-poked, and a postlude
# that runs after every poke (regardless of cause) prepending a
# %tap-observed effect to `out.efx`. The test asserts:
#   - Pre-postlude effect (%tap-poked) still emitted
#   - Postlude effect (%tap-observed) prepended on top
# Together that proves the postlude saw the switch's result and
# could augment it without disturbing what the arm produced.
#
# Priority 125 sits above the eventual real index-graft (120). Picked
# so the composition stack matches what 03d will look like.

[graft]
name     = "tap-graft"
version  = "0.1.0"
priority = 125

[graft.types]
effect = "tap-effect"
cause  = "tap-cause"

[graft.blocks.imports]
sentinel = "*tap-graft"
body     = """
/+  *tap-graft"""

[graft.blocks.cause]
sentinel = "tap-cause"
body     = "tap-cause"

[graft.blocks.poke]
sentinel = "%tap-poke"
body     = """
::
  %tap-poke
:_  state
^-  (list effect)
~[[%tap-poked ~]]"""

[graft.blocks.poke-postlude]
sentinel = "tap-observed prepend"
body     = """
=/  out  out(efx [[%tap-observed ~] efx.out])"""
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postlude_transforms_switch_result() -> Result<()> {
    let jam_path = compose_and_compile_with_extras(
        "phase03_postlude_single",
        &["settle-graft", "tap-graft"],
        &[tap_graft()],
    )?
    .jam_path;
    let mut harness = GraftTestHarness::boot(&jam_path).await?;

    // Poke %tap-poke. The arm emits %tap-poked. The postlude prepends
    // %tap-observed on top of out.efx. Both must appear; the
    // postlude's effect must be FIRST (the prepend semantics).
    let tags = harness.poke_slab(build_tap_poke()).await?;
    assert!(
        tags.iter().any(|t| t == "tap-poked"),
        "expected %tap-poked from arm body; got {tags:?}",
    );
    assert!(
        tags.iter().any(|t| t == "tap-observed"),
        "expected %tap-observed from postlude; got {tags:?}",
    );
    // Postlude prepends, so %tap-observed must appear BEFORE %tap-poked
    // in the effect list.
    let observed_idx = tags.iter().position(|t| t == "tap-observed").unwrap();
    let poked_idx = tags.iter().position(|t| t == "tap-poked").unwrap();
    assert!(
        observed_idx < poked_idx,
        "postlude prepend semantics: %tap-observed must precede %tap-poked; got {tags:?}",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postlude_banners_present_in_composed_source() -> Result<()> {
    let art = compose_and_compile_with_extras(
        "phase03_postlude_banners",
        &["settle-graft", "tap-graft"],
        &[tap_graft()],
    )?;
    let composed = std::fs::read_to_string(&art.source_path)?;

    assert!(
        composed.contains("::  graft-inject:tap-graft:poke-postlude:begin"),
        "expected poke-postlude begin banner in composed source",
    );
    assert!(
        composed.contains("::  graft-inject:tap-graft:poke-postlude:end"),
        "expected poke-postlude end banner in composed source",
    );
    assert!(
        composed.contains("=/  out  out(efx [[%tap-observed ~] efx.out])"),
        "expected postlude body verbatim in composed source",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postlude_is_idempotent_under_rerun() -> Result<()> {
    let art = compose_and_compile_with_extras(
        "phase03_postlude_idempotent",
        &["settle-graft", "tap-graft"],
        &[tap_graft()],
    )?;
    let after_first = std::fs::read_to_string(&art.source_path)?;

    let status = std::process::Command::new(fixtures::graft_inject_bin())
        .arg("--accept-untrusted-libs").arg("--lib-dir")
        .arg(&art.lib_dir)
        .arg("--grafts")
        .arg("settle-graft,tap-graft")
        .arg("--apply")
        .arg(&art.source_path)
        .status()?;
    assert!(status.success(), "second graft-inject run failed");

    let after_second = std::fs::read_to_string(&art.source_path)?;
    assert_eq!(
        after_first, after_second,
        "second graft-inject run must be byte-identical (idempotence)",
    );

    assert_eq!(
        after_second
            .matches("::  graft-inject:tap-graft:poke-postlude:begin")
            .count(),
        1,
        "postlude begin banner must appear exactly once after re-run",
    );

    Ok(())
}

/// Build a `[%tap-poke ~]` poke.
fn build_tap_poke() -> NounSlab {
    let mut slab = NounSlab::new();
    let tag = make_tag_in(&mut slab, "tap-poke");
    let poke = T(&mut slab, &[tag, D(0)]);
    slab.set_root(poke);
    slab
}
