//! Gate catalog + `[graft.gates]` validation and application.
//!
//! Audit §3.2 extraction: pulls the gate-specific validators and the
//! poke-body rewriter out of the pre-split monolith. The catalog itself
//! (`TIER_1A_GATES`) lives here so adding a Tier 1b gate is a single-
//! file change.

use anyhow::{Result, bail};
use std::path::Path;

use crate::manifest::{Graft, build_chain_block, is_valid_graft_name};

/// Allowlist of catalog gates currently shipped in `vesl-gates.hoon`.
/// Tier 1b additions extend this list as they land.
pub(crate) const TIER_1A_GATES: &[&str] = &[
    "sig-verify-ed25519",
    "sig-verify-schnorr",
    "manifest-verify",
    "set-membership-verify",
    "bounded-value-verify",
];

/// Validate `[graft.gates]` per OVERVIEW.md C2: `gate` and `gate-chain`
/// are mutually exclusive, names match kebab-case, names resolve against
/// the catalog allowlist. `path` is reported in errors so authors can
/// find the offending manifest without grep.
pub(crate) fn validate_gate_selection(g: &Graft, path: &Path) -> Result<()> {
    let Some(sel) = &g.gates else {
        return Ok(());
    };
    if sel.gate.is_some() && sel.gate_chain.is_some() {
        bail!(
            "[graft.gates] in {} sets both `gate` and `gate-chain`; pick one or neither",
            path.display()
        );
    }
    if let Some(name) = &sel.gate {
        validate_gate_name(name, path, "gate")?;
    }
    if let Some(chain) = &sel.gate_chain {
        if chain.is_empty() {
            bail!(
                "[graft.gates].gate-chain in {} is empty; remove it or list at least one gate",
                path.display()
            );
        }
        for name in chain {
            validate_gate_name(name, path, "gate-chain entry")?;
        }
    }
    Ok(())
}

pub(crate) fn validate_gate_name(name: &str, path: &Path, field: &str) -> Result<()> {
    if !is_valid_graft_name(name) {
        bail!(
            "[graft.gates].{field} `{name}` in {}: expected kebab-case matching ^[a-z][a-z0-9-]*$",
            path.display()
        );
    }
    if !TIER_1A_GATES.contains(&name) {
        bail!(
            "[graft.gates].{field} `{name}` in {} is not a known catalog gate. \
             Tier 1a (currently shipping): {}",
            path.display(),
            TIER_1A_GATES.join(", ")
        );
    }
    Ok(())
}

/// Default hash-gate definition that ships in `settle-graft.toml`'s poke
/// body. Each of the three `%settle-*` arms carries this exact 4-line
/// block; gate selection rewrites every occurrence.
pub(crate) const DEFAULT_HASH_GATE_BLOCK: &str = "\
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =((hash-leaf ;;(@ data)) expected-root)";

/// Rewrite a graft's poke body and imports body when `[graft.gates]` is
/// set. The poke body's default hash-gate blocks are replaced with calls
/// into `vesl-gates`; the imports body gains a `/+  vesl-gates` line if
/// it isn't already there.
///
/// The import is non-splat (no `*`) on purpose: the rewritten body uses
/// the qualified `name:vesl-gates` form, which requires `vesl-gates` to
/// be a namespace identifier. A splat-import would import the arms into
/// the current scope as bare names AND drop the `vesl-gates` identifier,
/// so the qualified body would fail to resolve (`find . vesl-gates`).
///
/// `gate = "name"` produces a single-line direct binding:
///
///     =/  hash-gate=verify-gate  name:vesl-gates
///
/// `gate-chain = ["a", "b", ...]` produces an AND-fold:
///
///     =/  hash-gate=verify-gate
///       |=  [note-id=@ data=* expected-root=@]
///       ^-  ?
///       ?&  (a:vesl-gates note-id data expected-root)
///           (b:vesl-gates note-id data expected-root)
///       ==
///
/// OVERVIEW.md §Out-of-scope keeps `gate-chain` AND-only in v1.
///
/// If the manifest declares `[graft.gates]` but the poke body doesn't
/// contain the default hash-gate block, that's a mismatch worth flagging
/// — the manifest author probably hand-wrote a custom gate and the
/// catalog selection is a no-op or contradicts it.
pub(crate) fn apply_gate_selection(g: &mut Graft, path: &Path) -> Result<()> {
    let Some(sel) = g.gates.clone() else {
        return Ok(());
    };
    let new_block = if let Some(name) = &sel.gate {
        format!("=/  hash-gate=verify-gate  {name}:vesl-gates")
    } else if let Some(chain) = &sel.gate_chain {
        build_chain_block(chain)
    } else {
        // [graft.gates] table exists but neither field set — no-op,
        // matches the documented "set one or neither" semantics.
        return Ok(());
    };

    let Some(poke) = g.blocks.poke.as_mut() else {
        bail!(
            "[graft.gates] in {} selects a gate but the manifest has no [graft.blocks.poke]",
            path.display()
        );
    };
    if !poke.body.contains(DEFAULT_HASH_GATE_BLOCK) {
        bail!(
            "[graft.gates] in {} selects a gate but the poke body does not contain the \
             default hash-gate block; gate selection only applies to manifests using the \
             stock 4-line `=/  hash-gate=verify-gate  ...` shape",
            path.display()
        );
    }
    poke.body = poke.body.replace(DEFAULT_HASH_GATE_BLOCK, &new_block);

    if let Some(imports) = g.blocks.imports.as_mut() {
        if !imports.body.lines().any(|l| l.trim() == "/+  vesl-gates") {
            // Prepend so the gate import is visible at the top of the
            // composed imports block — matches the pattern in
            // settle-graft.toml where `*settle-graft` precedes
            // `*vesl-merkle`. Non-splat: see the apply_gate_selection
            // rustdoc above for why.
            imports.body = format!("/+  vesl-gates\n{}", imports.body);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ManifestFile, sha256_hex};
    use anyhow::Result;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    fn settle_graft_manifest_path() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("hoon")
            .join("lib")
            .join("settle-graft.toml")
    }

    /// Load settle-graft.toml and inject a `[graft.gates]` selection by
    /// re-parsing the TOML with an appended `[graft.gates]` table. Avoids
    /// needing a separate fixture file per test case.
    fn settle_graft_with_gates(extra_toml: &str) -> Result<Graft> {
        let raw = fs::read_to_string(settle_graft_manifest_path())
            .expect("read settle-graft.toml");
        let merged = format!("{raw}\n{extra_toml}\n");
        let value: toml::Value =
            toml::from_str(&merged).expect("parse merged TOML");
        let mut graft: Graft = ManifestFile::deserialize(value)
            .expect("deserialize merged manifest")
            .graft;
        graft.sha256 = sha256_hex(merged.as_bytes());
        let path = settle_graft_manifest_path();
        validate_gate_selection(&graft, &path)?;
        apply_gate_selection(&mut graft, &path)?;
        Ok(graft)
    }

    #[test]
    fn gate_selection_rewrites_poke_body_and_imports() {
        let g = settle_graft_with_gates(
            "[graft.gates]\ngate = \"sig-verify-ed25519\"",
        )
        .expect("ed25519 selection valid");
        let poke = g.blocks.poke.as_ref().expect("settle has poke").body.clone();
        let imports = g
            .blocks
            .imports
            .as_ref()
            .expect("settle has imports")
            .body
            .clone();
        // Default block gone, three direct bindings present (one per arm).
        assert!(
            !poke.contains(DEFAULT_HASH_GATE_BLOCK),
            "default hash-gate block must be replaced"
        );
        let occurrences = poke
            .matches("=/  hash-gate=verify-gate  sig-verify-ed25519:vesl-gates")
            .count();
        assert_eq!(
            occurrences, 3,
            "expected 3 gate bindings (register/verify/note), got {occurrences}"
        );
        assert!(
            imports.lines().any(|l| l.trim() == "/+  vesl-gates"),
            "imports body must gain /+  vesl-gates"
        );
    }

    #[test]
    fn gate_chain_emits_and_fold() {
        let g = settle_graft_with_gates(
            "[graft.gates]\ngate-chain = [\"sig-verify-ed25519\", \"manifest-verify\"]",
        )
        .expect("gate-chain valid");
        let poke = g.blocks.poke.as_ref().unwrap().body.clone();
        let expected_chain = "?&  (sig-verify-ed25519:vesl-gates note-id data expected-root)\n      (manifest-verify:vesl-gates note-id data expected-root)\n  ==";
        assert!(
            poke.contains(expected_chain),
            "AND-fold shape missing.  expected:\n{expected_chain}\n\nactual poke body:\n{poke}"
        );
    }

    #[test]
    fn gate_and_gate_chain_mutually_exclusive() {
        let err = settle_graft_with_gates(
            "[graft.gates]\ngate = \"sig-verify-ed25519\"\ngate-chain = [\"manifest-verify\"]",
        )
        .expect_err("must reject when both fields set");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("both `gate` and `gate-chain`"),
            "error must explain mutual exclusion: {msg}"
        );
    }

    #[test]
    fn gate_name_must_be_kebab_case() {
        let err = settle_graft_with_gates(
            "[graft.gates]\ngate = \"Sig-Verify-Ed25519\"",
        )
        .expect_err("must reject capital letters");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("kebab-case"),
            "error must mention kebab-case: {msg}"
        );
    }

    #[test]
    fn gate_name_must_be_in_catalog() {
        let err = settle_graft_with_gates(
            "[graft.gates]\ngate = \"threshold-sig-verify\"",
        )
        .expect_err("Tier 1b gate not yet shipping");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a known catalog gate"),
            "error must mention catalog allowlist: {msg}"
        );
    }

    #[test]
    fn empty_gate_chain_rejected() {
        let err = settle_graft_with_gates("[graft.gates]\ngate-chain = []")
            .expect_err("empty chain must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("gate-chain") && msg.contains("empty"),
            "error must mention empty gate-chain: {msg}"
        );
    }

    #[test]
    fn empty_gates_table_is_noop() {
        // [graft.gates] table with no fields set leaves the manifest alone.
        let g = settle_graft_with_gates("[graft.gates]").expect("empty table valid");
        let poke = g.blocks.poke.as_ref().unwrap().body.clone();
        assert!(
            poke.contains(DEFAULT_HASH_GATE_BLOCK),
            "default hash-gate must remain when no gate is selected"
        );
        let imports = g.blocks.imports.as_ref().unwrap().body.clone();
        assert!(
            !imports.contains("/+  vesl-gates"),
            "vesl-gates import must NOT land for a no-op gates table"
        );
    }

    #[test]
    fn gate_selection_idempotent_imports() {
        // Running apply_gate_selection on a graft that already has
        // `/+  vesl-gates` in imports must not duplicate the line.
        let g1 = settle_graft_with_gates(
            "[graft.gates]\ngate = \"set-membership-verify\"",
        )
        .unwrap();
        let imports = g1.blocks.imports.as_ref().unwrap().body.clone();
        let count = imports
            .lines()
            .filter(|l| l.trim() == "/+  vesl-gates")
            .count();
        assert_eq!(count, 1, "vesl-gates import must appear exactly once");
    }
}
