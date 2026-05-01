//! Gate-selected compose+compile regression test (R2/02 — F12 + F13).
//!
//! Two correlated bugs once tripped on every gate-selected dogfood
//! round:
//!
//! - F12: graft-inject emitted `/+  *vesl-gates` (splat) AND a
//!   qualified `name:vesl-gates` body. Hoon's namespace semantics
//!   make those mutually exclusive — the splat drops the
//!   `vesl-gates` identifier, so hoonc fails on the qualified body
//!   with `find . vesl-gates`.
//! - F13: the dogfood Family-2 cp block copied `vesl-gates.hoon`
//!   into `hoon/lib/` but skipped its `/=  *  /common/zose`
//!   transitive dep. Because hoonc walks the whole `hoon/` tree,
//!   any profile with `vesl-gates.hoon` present failed regardless
//!   of whether a gate was selected.
//!
//! This test guards both regressions in one CI lane: a successful
//! `out.jam` proves the import + body resolve together (F12) and
//! that `zose.hoon` is reachable for the tree-walk type-check (F13,
//! since the fixture's `copy_dir_contents` of `hoon/common/`
//! lands `zose.hoon` automatically).
//!
//! No boot/poke step — F12's failure mode is compile-time, so a
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
