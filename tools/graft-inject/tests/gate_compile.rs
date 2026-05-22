//! Gate-selected compose+compile regression test.
//!
//! Two correlated bugs once tripped on every gate-selected
//! composition:
//!
//! - graft-inject emitted `/+  *vesl-gates` (splat) AND a
//!   qualified `name:vesl-gates` body. Hoon's namespace semantics
//!   make those mutually exclusive — the splat drops the
//!   `vesl-gates` identifier, so hoonc fails on the qualified body
//!   with `find . vesl-gates`.
//! - a copy step pulled `vesl-gates.hoon` into `hoon/lib/` but
//!   skipped its `/=  *  /common/zose` transitive dep. Because hoonc
//!   walks the whole `hoon/` tree, any project with `vesl-gates.hoon`
//!   present failed regardless of whether a gate was selected.
//!
//! This test guards both regressions in one CI lane: a successful
//! `out.jam` proves the import + body resolve together and that
//! `zose.hoon` is reachable for the tree-walk type-check (the
//! fixture's `copy_dir_contents` of `hoon/common/` lands
//! `zose.hoon` automatically).
//!
//! No boot/poke step — the failure mode is compile-time, so a
//! produced `out.jam` is the regression guard.

mod fixtures;

use std::fs;

use anyhow::Result;

#[test]
fn gate_selected_settle_compose_compiles() -> Result<()> {
    let canonical = fs::read_to_string(
        fixtures::repo_root().join("hoon/lib/settle-graft.toml"),
    )?;
    let with_gate = format!(
        "{canonical}\n[graft.gates]\ngate = \"set-membership-verify\"\n"
    );

    let jam_path = fixtures::compose_and_compile_with_manifest_overrides(
        "gate_compile",
        &["settle-graft", "mint-graft"],
        &[fixtures::ManifestOverride {
            name: "settle-graft",
            toml: with_gate,
        }],
    )?;

    assert!(
        jam_path.exists(),
        "compose+compile produced no out.jam at {}",
        jam_path.display(),
    );
    Ok(())
}
