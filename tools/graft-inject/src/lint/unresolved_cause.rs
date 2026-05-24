//! Unresolved cause-reference lint: the kernel's `+$ cause $%(...)`
//! cites a sub-cause-type (e.g. `settle-cause`) that no graft's
//! `[graft.types].cause` declares in the active set.

use std::collections::HashSet;

use serde::Serialize;

use crate::manifest::Graft;

use super::extract::{CauseUnionMember, extract_cause_union_members};
use super::{LintFinding, LintSeverity};

/// JSON projection record for `unresolved_cause_references` findings.
#[derive(Serialize)]
pub(super) struct UnresolvedCauseReferenceRecord<'a> {
    pub(super) severity: LintSeverity,
    pub(super) line: usize,
    pub(super) name: &'a str,
}

/// Pre-apply lint: the kernel's `+$ cause $%(...)` cites a
/// sub-cause-type (e.g. `settle-cause`) that no graft's
/// `[graft.types].cause` declares in the active set.
///
/// `run_codegen_kernel_cause_tags` falls through silently when a
/// reference doesn't resolve — its comment described this as
/// "caught earlier" by `inject`, but `inject` operates on banner
/// markers, not on the `+$ cause` body. Without this lint, the
/// orphan reference reaches hoonc, which surfaces it as
/// `find . <name>-cause` — a message that doesn't name the kernel
/// source line or the graft set that should have declared the type.
///
/// The lint scans `extract_cause_union_members(lines)` for
/// `CauseUnionMember::Reference` entries and cross-checks each
/// against the set of declared `[graft.types].cause` names. The
/// placeholder `[%cause ~]` literal (which the template ships) is
/// already filtered out by the Reference / Literal split.
pub(crate) fn lint_unresolved_cause_references(
    grafts: &[Graft],
    lines: &[String],
) -> Vec<LintFinding> {
    let declared: HashSet<&str> = grafts
        .iter()
        .filter_map(|g| g.types.as_ref().and_then(|t| t.cause.as_deref()))
        .collect();
    // Banner-bounded reference entries are part of a graft's own
    // cause block — they're either declared (active graft, no lint
    // needed) or about to be orphan-pruned by `inject` (inactive
    // graft, false-positive flag if the lint fired). Skip those line
    // ranges so the lint only flags references the developer added
    // outside any graft-inject banner.
    let banner_lines = banner_line_set(lines);
    let mut findings: Vec<LintFinding> = Vec::new();
    for member in extract_cause_union_members(lines) {
        let CauseUnionMember::Reference { name, line } = member else {
            continue;
        };
        if banner_lines.contains(&line) {
            continue;
        }
        if !declared.contains(name.as_str()) {
            findings.push(LintFinding::UnresolvedCauseReference { line, name });
        }
    }
    findings
}

/// Build the set of 1-indexed line numbers that fall inside a
/// `::  graft-inject:<...>:begin / :end` banner pair. The `begin` and
/// `end` lines themselves are included so a reference that
/// accidentally lands on a banner line is also skipped.
fn banner_line_set(lines: &[String]) -> HashSet<usize> {
    let mut out: HashSet<usize> = HashSet::new();
    let mut in_banner = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_marker = trimmed.starts_with("::") && trimmed.contains("graft-inject:");
        if is_marker {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                out.insert(i + 1);
                continue;
            }
            if trimmed.ends_with(":end") {
                out.insert(i + 1);
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            out.insert(i + 1);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GraftBlocks, GraftTypes};

    /// Helper: build a graft with `[graft.types].cause = <name>` so the
    /// lint can resolve a reference against it. The blocks are kept
    /// minimal — only the type declaration matters for this lint.
    fn synthetic_graft_with_cause_type(name: &str, cause_type: &str) -> Graft {
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority: 50,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: None,
                cause: None,
                poke_prelude: None,
                poke: None,
                poke_postlude: None,
                peek: None,
            },
            types: Some(GraftTypes {
                effect: None,
                cause: Some(cause_type.to_string()),
            }),
            gates: None,
            schema_version: None,
            sha256: "0".repeat(64),
        }
    }

    /// `+$ cause` cites `settle-cause` and no discovered graft declares
    /// `[graft.types].cause = "settle-cause"` — fire one finding naming
    /// the unresolved type.
    #[test]
    fn unresolved_cause_reference_flags_missing_type() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      settle-cause\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        match &findings[0] {
            LintFinding::UnresolvedCauseReference { name, .. } => {
                assert_eq!(name, "settle-cause");
            }
            other => panic!("expected UnresolvedCauseReference, got {other:?}"),
        }
    }

    /// When the active set declares the referenced type, no finding
    /// fires. Sanity check that the lint isn't over-flagging.
    #[test]
    fn unresolved_cause_reference_clears_when_declared() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      settle-cause\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let settle = synthetic_graft_with_cause_type("settle-graft", "settle-cause");
        let findings = lint_unresolved_cause_references(&[settle], &domain);
        assert!(
            findings.is_empty(),
            "declared cause-type must not trigger the lint, got {findings:#?}"
        );
    }

    /// Inline `[%<tag> ...]` literals are not references — the lint
    /// only flags bare type-name members of the union. Pure-literal
    /// unions must produce zero findings.
    #[test]
    fn unresolved_cause_reference_ignores_literal_members() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      [%submit-artifact id=@]\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert!(findings.is_empty());
    }

    /// References inside a `graft-inject:<X>:cause:begin/:end` banner
    /// belong to a graft's own block. They're either declared by an
    /// active graft (resolved) or about to be orphan-pruned by the
    /// next inject pass (transient state). Either way, flagging a
    /// banner-bounded reference is a false positive — the lint must
    /// only fire on developer-added references outside any banner.
    #[test]
    fn unresolved_cause_reference_skips_banner_bounded() {
        let domain: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      ::  graft-inject:validate-graft:cause:begin sha256:deadbeef\n      validate-cause\n      ::  graft-inject:validate-graft:cause:end\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let findings = lint_unresolved_cause_references(&[], &domain);
        assert!(
            findings.is_empty(),
            "banner-bounded references must be skipped, got {findings:#?}"
        );
    }
}
