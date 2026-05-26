//! Auto-migration pre-pass: rewrite a kernel's bare `+$  effect  *`
//! line to the post-migration marker shape so codegen has a surface
//! to take over.
//!
//! Owned by `run_inject` and exposed for direct callers via
//! `pub(crate)`. Lives outside `inject.rs` because the rewrite mutates
//! the kernel source before the composer's main loop runs — it's a
//! pre-pass, not a sub-step of composition.

use crate::marker::{Marker, find_marker, leading_whitespace};

/// Outcome of `migrate_legacy_effect`. Surfaced to stderr so reviewers
/// can see whether the auto-migration touched the file before codegen
/// runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationReport {
    /// Did we rewrite a bare `+$  effect  *` into the marker shape?
    pub(crate) migrated: bool,
    /// Did we spot a custom `+$ effect <type>` that we left alone?
    /// Stderr-warned so the developer knows their custom shape will
    /// collide with codegen if the marker is added later.
    pub(crate) skipped_custom: bool,
}

impl MigrationReport {
    pub(crate) fn skipped() -> Self {
        Self {
            migrated: false,
            skipped_custom: false,
        }
    }
}

/// Rewrite a kernel's bare `+$  effect  *` line to the post-migration
/// marker shape — placeholder `+$ domain-effect` block,
/// `nockup:domain-effect` marker, `nockup:effect-union` marker, and a
/// temporary `+$ effect *` that the codegen pass replaces on the same
/// `--apply` run.
///
/// No-op (returns the input unchanged) when:
///   * the kernel already has a `nockup:effect-union` marker — codegen
///     owns that surface, no further migration needed,
///   * the kernel has no `+$ effect ...` line at all — fresh scaffold
///     that the developer will markup themselves,
///   * the kernel has a custom `+$ effect <type>` that isn't the bare
///     `*` shape — left alone with a stderr warning so the developer's
///     bespoke type isn't silently rewritten.
pub(crate) fn migrate_legacy_effect(source: &str) -> (String, MigrationReport) {
    let mut lines: Vec<String> = source.replace("\r\n", "\n").lines().map(String::from).collect();
    let trailing_newline = source.ends_with('\n');

    // Already migrated — codegen owns the effect surface.
    if find_marker(&lines, Marker::EffectUnion).ok().flatten().is_some() {
        return (source.to_string(), MigrationReport::skipped());
    }

    // Find a `+$ effect ...` line. Two outcomes:
    //   bare `*`   -> migrate
    //   custom     -> warn but skip (developer's choice deserves respect)
    let mut bare_idx: Option<usize> = None;
    let mut custom_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.first() == Some(&"+$") && parts.get(1) == Some(&"effect") {
            if parts.len() == 3 && parts[2] == "*" {
                bare_idx = Some(i);
                break;
            } else {
                custom_idx = Some(i);
                break;
            }
        }
    }

    let Some(idx) = bare_idx else {
        return (
            source.to_string(),
            MigrationReport {
                migrated: false,
                skipped_custom: custom_idx.is_some(),
            },
        );
    };

    let indent = leading_whitespace(&lines[idx]).to_string();
    let block = vec![
        format!(
            "{indent}::  domain-effect is your app's effect union. Add variants here as"
        ),
        format!(
            "{indent}::  your app emits them. The codegen-generated `+$ effect` below"
        ),
        format!(
            "{indent}::  splats domain-effect into a typed union with all graft effects."
        ),
        format!("{indent}::"),
        format!("{indent}::  nockup:domain-effect"),
        format!("{indent}+$  domain-effect"),
        format!("{indent}  $%  [%domain-placeholder ~]"),
        format!("{indent}  =="),
        format!("{indent}::"),
        format!(
            "{indent}::  graft-inject codegen replaces the open `+$ effect *` below with a"
        ),
        format!("{indent}::  typed union. Do not edit the codegen banner block by hand."),
        format!("{indent}::"),
        format!("{indent}::  nockup:effect-union"),
        format!("{indent}+$  effect  *"),
    ];
    lines.splice(idx..=idx, block);

    let mut output = lines.join("\n");
    if trailing_newline {
        output.push('\n');
    }
    (
        output,
        MigrationReport {
            migrated: true,
            skipped_custom: false,
        },
    )
}

/// One-line stderr surface for the auto-migration pass.
pub(crate) fn print_migration_line(report: &MigrationReport) {
    if report.migrated {
        eprintln!(
            "  auto-migration: rewrote bare `+$  effect  *` to nockup:effect-union marker shape"
        );
    } else if report.skipped_custom {
        eprintln!(
            "  auto-migration: skipped — found a custom `+$ effect <type>`. Leaving it alone; \
             add `nockup:effect-union` manually if you want codegen to take over."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::inject;
    use crate::codegen::CodegenStatus;
    use crate::test_support::{BARE_SCAFFOLD, synthetic_graft_with_effect};

    #[test]
    fn migration_rewrites_bare_effect_star() {
        let (out, report) = migrate_legacy_effect(BARE_SCAFFOLD);
        assert!(report.migrated);
        assert!(!report.skipped_custom);
        assert!(out.contains("::  nockup:domain-effect"));
        assert!(out.contains("+$  domain-effect"));
        assert!(out.contains("[%domain-placeholder ~]"));
        assert!(out.contains("::  nockup:effect-union"));
        assert!(out.contains("+$  effect  *"));
        // The original lone `+$  effect  *` is gone — replaced by the
        // marker block. Count: one `+$  effect  *` survives, but only as
        // the placeholder beneath nockup:effect-union.
        let bare_count = out.lines().filter(|l| l.trim() == "+$  effect  *").count();
        assert_eq!(bare_count, 1, "exactly one bare effect line after migration");
    }

    #[test]
    fn migration_idempotent_after_first_run() {
        let (once, _) = migrate_legacy_effect(BARE_SCAFFOLD);
        let (twice, report) = migrate_legacy_effect(&once);
        assert_eq!(once, twice, "second migration must be a no-op");
        assert!(!report.migrated);
        assert!(!report.skipped_custom);
    }

    #[test]
    fn migration_skips_custom_effect_type() {
        let custom = BARE_SCAFFOLD.replace("+$  effect  *", "+$  effect  (list @t)");
        let (out, report) = migrate_legacy_effect(&custom);
        assert!(!report.migrated);
        assert!(report.skipped_custom);
        assert_eq!(out, custom, "custom effect type must be left untouched");
    }

    #[test]
    fn migration_then_inject_then_codegen_end_to_end() {
        // The full --apply path: migration adds markers, inject wires
        // graft blocks, codegen synthesizes the typed union.
        let g = synthetic_graft_with_effect("alpha", 10);
        let (migrated, _) = migrate_legacy_effect(BARE_SCAFFOLD);
        let (out, report) = inject(&migrated, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "domain-effect"]
        );
        // Banner block is present and references the union variants.
        assert!(out.contains("::  graft-inject:effect-union:begin"));
        assert!(out.contains("$%  alpha-effect"));
        assert!(out.contains("domain-effect"));
        assert!(out.contains("[%domain-placeholder ~]"));
    }
}
