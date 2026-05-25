//! Typed effect-union, load-defaults overlay, and the two manifest-
//! driven Rust codegen passes (`kernel-cause-tags` and
//! `harness-methods`).
//!
//! These passes synthesize Hoon (or Rust, in the cause-tags + harness
//! cases) at codegen-owned banner pairs in the composed source. The
//! lint suite consumes their report variant lists and rendered output
//! by reference — there's no hidden state coupling, so the two layers
//! split cleanly.
//!
//! Module layout:
//! - this file — shared status / report types, banner-pair locator,
//!   and the two in-place Hoon passes (`emit_effect_union`,
//!   `emit_load_defaults`).
//! - [`kernel_cause_tags`] — `KERNEL_CAUSE_TAGS` slice + the
//!   `assert_kernel_cause_tag!` macro emitter.
//! - [`harness_methods`] — typed `GraftTestHarness` method emitter +
//!   per-graft outcome enum + sidecar reader.

use anyhow::{Result, bail};
use serde::Serialize;

use crate::inject::binding_stub;
use crate::manifest::Graft;
use crate::marker::{Marker, codegen_begin_banner, codegen_end_banner, find_marker, leading_whitespace};

mod harness_methods;
mod kernel_cause_tags;

pub(crate) use harness_methods::run_codegen_harness_methods;
pub(crate) use kernel_cause_tags::run_codegen_kernel_cause_tags;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CodegenStatus {
    /// `nockup:effect-union` marker not present in source.
    Skipped,
    /// First codegen run on this kernel: banner block inserted.
    Inserted,
    /// Banner block was present and got new content.
    Replaced,
    /// Banner block was present and already matched the synthesized
    /// output — second run is byte-identical (idempotent).
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CodegenReport {
    pub(crate) status: CodegenStatus,
    /// Variant list spliced into `+$ effect $%(...)`. Empty when status
    /// is Skipped.
    pub(crate) variants: Vec<String>,
}

/// Outcome of the load-defaults codegen pass. Mirrors
/// `CodegenReport` but tracks the `++load` overlay block separately so
/// the `print_report` line can call out the schema-migration scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct LoadDefaultsReport {
    pub(crate) status: CodegenStatus,
    /// Graft state-field names (e.g. `["settle", "rbac"]`) emitted into
    /// the `%=  old-state ... ==` overlay, in priority order. Empty when
    /// status is Skipped.
    pub(crate) fields: Vec<String>,
}

/// Locate the (begin, end) line indices of a codegen banner pair within
/// `lines`, starting the search at `search_start`. Bails on duplicate
/// begin banners, orphan ends, and orphan begins (begin without matching
/// end). `marker_label` is interpolated into the orphan-begin diagnostic.
fn find_banner_pair_indices(
    lines: &[String],
    begin_str: &str,
    end_str: &str,
    search_start: usize,
    marker_label: &str,
) -> Result<(Option<usize>, Option<usize>)> {
    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(search_start) {
        let trimmed = line.trim();
        if trimmed == begin_str {
            if begin_idx.is_some() {
                bail!(
                    "duplicate `{}` at line {}; codegen owns one banner pair per kernel",
                    begin_str,
                    i + 1
                );
            }
            begin_idx = Some(i);
        } else if trimmed == end_str {
            if begin_idx.is_none() {
                bail!(
                    "orphan `{}` at line {} (no matching begin banner)",
                    end_str,
                    i + 1
                );
            }
            end_idx = Some(i);
            break;
        }
    }

    if begin_idx.is_some() && end_idx.is_none() {
        bail!(
            "orphan `{}` (begin without end) under {}",
            begin_str,
            marker_label
        );
    }

    Ok((begin_idx, end_idx))
}

/// Synthesize the typed effect union beneath the `nockup:effect-union`
/// marker. REPLACE-IF-PRESENT semantics — the
/// emitted block lives between graft-inject's own banner pair, and the
/// pass owns everything between them. Removing a graft from the
/// composer's input shrinks the union on the next run.
///
/// Variant order: `[graft.types].effect` from each graft in the input
/// slice's order (which is already priority-sorted by `discover_grafts`),
/// then `domain-effect` if the `nockup:domain-effect` marker is present.
/// An empty union falls back to `[%effect-placeholder ~]` so Hoon's `$%`
/// stays non-empty.
///
/// Three states the codegen must handle:
///   1. Banner pair already present → REPLACE between them. Idempotent
///      when the new content matches the existing.
///   2. No banner pair, but a bare `+$  effect  *` line within the next
///      few lines → REPLACE that single line with the banner block.
///      This is the post-migration / pre-codegen state from commit 7.
///   3. Neither banner pair nor bare effect line → INSERT after the
///      marker. Plain greenfield kernel that already adopted the marker
///      shape.
pub(crate) fn emit_effect_union(
    lines: &mut Vec<String>,
    grafts: &[Graft],
) -> Result<CodegenReport> {
    let union_idx = match find_marker(lines, Marker::EffectUnion)? {
        Some(i) => i,
        None => {
            return Ok(CodegenReport {
                status: CodegenStatus::Skipped,
                variants: Vec::new(),
            });
        }
    };

    let mut variants: Vec<String> = grafts
        .iter()
        .filter_map(|g| {
            g.types
                .as_ref()
                .and_then(|t| t.effect.as_ref())
                .map(String::from)
        })
        .collect();

    if find_marker(lines, Marker::DomainEffect)?.is_some() {
        variants.push("domain-effect".to_string());
    }

    if variants.is_empty() {
        // Hoon's `$%` requires at least one variant. Use a recognizable
        // placeholder that surfaces as a clear hoonc error if the
        // kernel is left in this state.
        variants.push("[%effect-placeholder ~]".to_string());
    }

    let indent = leading_whitespace(&lines[union_idx]).to_string();
    let new_block = render_effect_union_block(&indent, &variants);

    let begin_str = codegen_begin_banner(Marker::EffectUnion);
    let end_str = codegen_end_banner(Marker::EffectUnion);

    let (begin_idx, end_idx) = find_banner_pair_indices(
        lines,
        &begin_str,
        &end_str,
        union_idx + 1,
        "nockup:effect-union",
    )?;

    match (begin_idx, end_idx) {
        (Some(b), Some(e)) => {
            let existing: Vec<String> = lines[b..=e].to_vec();
            if existing == new_block {
                return Ok(CodegenReport {
                    status: CodegenStatus::Unchanged,
                    variants,
                });
            }
            lines.splice(b..=e, new_block);
            Ok(CodegenReport {
                status: CodegenStatus::Replaced,
                variants,
            })
        }
        (None, None) => {
            // No banner pair yet. Look for a bare `+$  effect  *` line
            // immediately after the marker (post-migration state).
            // Scan a small window — anything that isn't whitespace, a
            // comment, or the bare-effect line stops the search.
            let mut bare_idx: Option<usize> = None;
            let scan_end = lines.len().min(union_idx + 8);
            for (i, line) in lines.iter().enumerate().take(scan_end).skip(union_idx + 1) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("::") {
                    continue;
                }
                if is_bare_effect_open_type(trimmed) {
                    bare_idx = Some(i);
                }
                break;
            }

            match bare_idx {
                Some(i) => {
                    lines.splice(i..=i, new_block);
                }
                None => {
                    for (offset, line) in new_block.into_iter().enumerate() {
                        lines.insert(union_idx + 1 + offset, line);
                    }
                }
            }
            Ok(CodegenReport {
                status: CodegenStatus::Inserted,
                variants,
            })
        }
        _ => unreachable!("orphan banner cases bail above"),
    }
}

/// Render the effect-union block as a vector of lines, each pre-indented
/// to match the marker's leading whitespace.
pub(crate) fn render_effect_union_block(indent: &str, variants: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(variants.len() + 5);
    out.push(format!("{indent}{}", codegen_begin_banner(Marker::EffectUnion)));
    out.push(format!("{indent}+$  effect"));
    out.push(format!("{indent}  $%  {}", variants[0]));
    for v in &variants[1..] {
        out.push(format!("{indent}      {v}"));
    }
    out.push(format!("{indent}  =="));
    out.push(format!("{indent}{}", codegen_end_banner(Marker::EffectUnion)));
    out
}

/// Synthesize the load-defaults overlay beneath the
/// `nockup:load-defaults` marker. Same REPLACE-IF-PRESENT shape as
/// `emit_effect_union` — the codegen owns everything between its
/// banner pair, and re-running with the same graft set is byte-identical.
///
/// The emitted block is a `%=  old-state ... ==` overlay that maps each
/// graft's state field (binding stub of the graft name; e.g.
/// `rbac-graft` → `rbac`) to that graft's `++new-state` default. Grafts
/// without a `[graft.blocks.state]` block (e.g. `forge-graft`) don't
/// contribute a state field and are skipped.
///
/// Three states the codegen handles:
///   1. Banner pair already present → REPLACE between them. Idempotent
///      when the new content matches the existing.
///   2. No banner pair → INSERT after the marker. The marker template
///      ships with a placeholder `old-state` line below the marker; the
///      INSERT places the codegen banner block after the marker without
///      removing the placeholder, since the placeholder is the v0.1
///      identity fallback (the migration arm sits ABOVE the placeholder
///      via the version-dispatched `?:`). For the v0.2 default the
///      generated block IS the body — when present, it replaces the
///      identity load.
///   3. Marker not present → Skipped (older templates pre-load-defaults).
pub(crate) fn emit_load_defaults(
    lines: &mut Vec<String>,
    grafts: &[Graft],
) -> Result<LoadDefaultsReport> {
    let marker_idx = match find_marker(lines, Marker::LoadDefaults)? {
        Some(i) => i,
        None => {
            return Ok(LoadDefaultsReport {
                status: CodegenStatus::Skipped,
                fields: Vec::new(),
            });
        }
    };

    let fields: Vec<String> = grafts
        .iter()
        .filter(|g| g.block(Marker::State).is_some())
        .map(|g| binding_stub(&g.name).to_string())
        .collect();

    let indent = leading_whitespace(&lines[marker_idx]).to_string();
    let new_block = render_load_defaults_block(&indent, grafts, &fields);

    let begin_str = codegen_begin_banner(Marker::LoadDefaults);
    let end_str = codegen_end_banner(Marker::LoadDefaults);

    let (begin_idx, end_idx) = find_banner_pair_indices(
        lines,
        &begin_str,
        &end_str,
        marker_idx + 1,
        "nockup:load-defaults",
    )?;

    match (begin_idx, end_idx) {
        (Some(b), Some(e)) => {
            let existing: Vec<String> = lines[b..=e].to_vec();
            if existing == new_block {
                return Ok(LoadDefaultsReport {
                    status: CodegenStatus::Unchanged,
                    fields,
                });
            }
            lines.splice(b..=e, new_block);
            Ok(LoadDefaultsReport {
                status: CodegenStatus::Replaced,
                fields,
            })
        }
        (None, None) => {
            // No banner pair. Find the placeholder line that the marker
            // template ships below the marker — the `old-state` identity
            // expression — and replace it with the codegen banner block.
            // Scan a small window after the marker; only `old-state` (or
            // a previously-injected banner pair, handled above) is the
            // legal placeholder shape, anything else is left alone.
            let scan_end = lines.len().min(marker_idx + 6);
            let mut placeholder_idx: Option<usize> = None;
            for (i, line) in lines.iter().enumerate().take(scan_end).skip(marker_idx + 1) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("::") {
                    continue;
                }
                if trimmed == "old-state" {
                    placeholder_idx = Some(i);
                }
                break;
            }
            match placeholder_idx {
                Some(i) => {
                    lines.splice(i..=i, new_block);
                }
                None => {
                    for (offset, line) in new_block.into_iter().enumerate() {
                        lines.insert(marker_idx + 1 + offset, line);
                    }
                }
            }
            Ok(LoadDefaultsReport {
                status: CodegenStatus::Inserted,
                fields,
            })
        }
        _ => unreachable!("orphan banner cases bail above"),
    }
}

/// Render the load-defaults overlay block as a vector of lines, each
/// pre-indented to match the marker's leading whitespace.
///
/// The body is shaped:
///
/// ```text
/// =/  defaults  ^*(versioned-state)
/// %_  defaults
///     settle  =/  s  (mole |.(settle.old-state))  ?~(s ^*(settle-state) u.s)
///     mint    =/  m  (mole |.(mint.old-state))    ?~(m ^*(mint-state) u.m)
///     ...
/// ==
/// ```
///
/// * `^*(versioned-state)` is the wide form of `^*  versioned-state`
///   (kettar) — the bunt (type-default) of the kernel's full
///   versioned-state shape. Domain-state fields (added by the developer
///   beyond the `nockup:state` marker) get their type defaults this way
///   without graft-inject needing to introspect them.
/// * `%_` rebinds named slots in `defaults` and returns the modified
///   subject. Hoon's `%_` and `%=` runes require their subject to be a
///   wing (a name reference), not an arbitrary expression — so we bind
///   the bunt to `defaults` first via `=/`.
/// * Each graft's slot is probed via `(mole |.(<field>.old-state))`,
///   which evaluates the field-access in a trap that catches axis
///   crashes. If the resumed snapshot's noun has the field at the
///   expected axis (same-composition resume, OR a smaller-shape
///   snapshot whose surviving fields happen to align with the new
///   kernel's axes), the probe returns Some(value) and we preserve
///   the snapshot's data. If the access crashes (axis missing or at
///   the wrong subtree), the probe returns None and we fall back to
///   `^*(<field>-state)`, the bunt of the graft's state type. The
///   per-field probing is the difference between a v0.1 silent-failure
///   load (panic on first new-graft access post-resume) and the v0.2
///   defaults-overlay migration: same-composition resumes preserve
///   data, schema-extension resumes fall back to defaults at exactly
///   the fields whose axes shifted.
/// * `++new-state` arms across grafts share the same `new-state`
///   name and would collide under splat imports; using the type bunt
///   (`^*(<field>-state)`) sidesteps that. For grafts whose
///   `++new-state` differs from the type bunt (queue/log default
///   counters to 1, the type bunts to 0), v0.2 takes the type-bunt
///   value at the fallback path — operators who need the seed counter
///   re-poke after resume.
/// * The cast `^- _state` on the load arm body type-checks the result
///   against the kernel's compiled state type.
///
/// The empty-fields case (no stateful grafts in the composition; e.g.
/// forge-only) emits a bare `^*(versioned-state)` so the load arm
/// stays a valid `_state`-typed expression and isn't a `%_  X  ==`
/// zero-mutation no-op.
pub(crate) fn render_load_defaults_block(indent: &str, grafts: &[Graft], fields: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(fields.len() + 5);
    out.push(format!(
        "{indent}{}",
        codegen_begin_banner(Marker::LoadDefaults)
    ));
    if fields.is_empty() {
        out.push(format!("{indent}^*(versioned-state)"));
    } else {
        out.push(format!("{indent}=/  defaults  ^*(versioned-state)"));
        out.push(format!("{indent}%_  defaults"));
        for g in grafts.iter().filter(|g| g.block(Marker::State).is_some()) {
            let stub = binding_stub(&g.name);
            // Single-letter probe-binding name — `s` for settle, `m`
            // for mint, etc. — uses the first character of the stub so
            // probes don't collide with each other in the `%_` body.
            // Prepend `_` if the stub is empty (defensive; the
            // `is_valid_graft_name` discovery check already rejects
            // empty names, but we don't want a panic on a degenerate
            // input).
            let probe = stub
                .chars()
                .next()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "_".to_string());
            // `;;(<field>-state ...)` is a runtime nest check inside
            // the mole trap — it crashes if the field-access read
            // returned a noun that doesn't structurally match the
            // graft's state type. Without it, schema-extension reads
            // at "deeper" axes can return garbage from inside an
            // earlier graft's state instead of crashing cleanly, and
            // the per-field probe would surface that garbage as a
            // valid value.
            out.push(format!(
                "{indent}    {stub}  =/  {probe}  (mole |.(;;({stub}-state {stub}.old-state)))  ?~({probe} ^*({stub}-state) u.{probe})"
            ));
        }
        out.push(format!("{indent}=="));
    }
    out.push(format!(
        "{indent}{}",
        codegen_end_banner(Marker::LoadDefaults)
    ));
    out
}

/// Recognize the legacy `+$  effect  *` open-type line. Tolerates one or
/// more spaces between tokens (Hoon two-space-law authors usually write
/// `+$  effect  *`). Rejects custom forms like `+$ effect (list @t)` so
/// the codegen leaves user-typed effects alone (a stderr warning is the
/// right surface for those, not a silent rewrite).
pub(crate) fn is_bare_effect_open_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.len() == 3 && parts[0] == "+$" && parts[1] == "effect" && parts[2] == "*"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::inject;
    use crate::manifest::discover_grafts;
    use crate::test_support::*;
    use std::fs;

    // ---------------------------------------------------------------
    // typed effect-union codegen
    // ---------------------------------------------------------------

    /// Synthetic graft with a `[graft.types]` declaration. Reuses
    /// `synthetic_graft` (which leaves `types: None`) and overrides.
    #[test]
    fn codegen_skipped_without_marker() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Skipped);
        assert!(report.codegen.variants.is_empty());
        assert!(!out.contains("graft-inject:effect-union:begin"));
    }

    #[test]
    fn codegen_inserts_with_one_graft() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["alpha-effect"]);
        assert!(out.contains("::  graft-inject:effect-union:begin"));
        assert!(out.contains("+$  effect"));
        assert!(out.contains("$%  alpha-effect"));
        assert!(out.contains("::  graft-inject:effect-union:end"));
    }

    #[test]
    fn codegen_inserts_with_n_grafts() {
        let grafts = vec![
            synthetic_graft_with_effect("alpha", 10),
            synthetic_graft_with_effect("beta", 20),
            synthetic_graft_with_effect("gamma", 30),
        ];
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &grafts).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "beta-effect", "gamma-effect"]
        );
        // Variant order in source matches the input slice (priority order).
        let begin = out.find("graft-inject:effect-union:begin").unwrap();
        let end = out.find("graft-inject:effect-union:end").unwrap();
        let block = &out[begin..end];
        let alpha = block.find("alpha-effect").unwrap();
        let beta = block.find("beta-effect").unwrap();
        let gamma = block.find("gamma-effect").unwrap();
        assert!(alpha < beta && beta < gamma, "variants in priority order");
    }

    #[test]
    fn codegen_includes_domain_effect_when_marker_present() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_BOTH_MARKERS, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "domain-effect"]
        );
        assert!(out.contains("domain-effect"));
        // Developer's `+$ domain-effect $%([%user-thing ~] ==)` declaration
        // must survive the codegen pass untouched.
        assert!(out.contains("[%user-thing ~]"));
    }

    #[test]
    fn codegen_idempotent_unchanged_on_rerun() {
        let g = synthetic_graft_with_effect("alpha", 10);
        let (first, _) = inject(SCAFFOLD_WITH_UNION_MARKER, std::slice::from_ref(&g)).unwrap();
        let (second, report) = inject(&first, &[g]).unwrap();
        assert_eq!(first, second, "second run must be byte-identical");
        assert_eq!(report.codegen.status, CodegenStatus::Unchanged);
    }

    #[test]
    fn codegen_replace_grows_when_graft_added() {
        let alpha = synthetic_graft_with_effect("alpha", 10);
        let beta = synthetic_graft_with_effect("beta", 20);
        let (one, _) = inject(SCAFFOLD_WITH_UNION_MARKER, std::slice::from_ref(&alpha)).unwrap();
        let (two, report) = inject(&one, &[alpha, beta]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Replaced);
        assert_eq!(
            report.codegen.variants,
            vec!["alpha-effect", "beta-effect"]
        );
        assert!(two.contains("alpha-effect"));
        assert!(two.contains("beta-effect"));
    }

    #[test]
    fn codegen_replace_shrinks_when_graft_removed() {
        let alpha = synthetic_graft_with_effect("alpha", 10);
        let beta = synthetic_graft_with_effect("beta", 20);
        let (two, _) = inject(SCAFFOLD_WITH_UNION_MARKER, &[alpha.clone(), beta]).unwrap();
        assert!(two.contains("beta-effect"));
        let (one, report) = inject(&two, &[alpha]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Replaced);
        assert_eq!(report.codegen.variants, vec!["alpha-effect"]);
        // Codegen owns the union — the dropped variant must be gone.
        let begin = one.find("graft-inject:effect-union:begin").unwrap();
        let end = one.find("graft-inject:effect-union:end").unwrap();
        let block = &one[begin..end];
        assert!(!block.contains("beta-effect"), "beta-effect must be removed from union body");
    }

    #[test]
    fn codegen_empty_graft_set_emits_placeholder() {
        let (out, report) = inject(SCAFFOLD_WITH_UNION_MARKER, &[]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["[%effect-placeholder ~]"]);
        assert!(out.contains("[%effect-placeholder ~]"));
    }

    #[test]
    fn codegen_empty_graft_set_with_domain_effect() {
        let (out, report) = inject(SCAFFOLD_WITH_BOTH_MARKERS, &[]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert_eq!(report.codegen.variants, vec!["domain-effect"]);
        assert!(!out.contains("[%effect-placeholder ~]"));
    }

    #[test]
    fn codegen_orphan_end_banner_bails() {
        let src = "\
::  test
::
::  nockup:effect-union
::  graft-inject:effect-union:end
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let result = inject(src, &[g]);
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(msg.contains("orphan"), "error must mention orphan: {msg}");
    }

    #[test]
    fn codegen_orphan_begin_banner_bails() {
        let src = "\
::  test
::
::  nockup:effect-union
::  graft-inject:effect-union:begin
+$  effect
  $%  alpha-effect
  ==
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let result = inject(src, &[g]);
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(msg.contains("orphan"), "error must mention orphan: {msg}");
    }

    #[test]
    fn codegen_replaces_post_migration_bare_effect_line() {
        // Post-migration / pre-codegen state from commit 7: marker is
        // present and a bare `+$  effect  *` line sits immediately
        // beneath. Codegen must wrap-and-replace that single line.
        let src = "\
::  test
::
::  nockup:effect-union
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, report) = inject(src, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Inserted);
        assert!(out.contains("+$  effect\n  $%  alpha-effect\n  ==\n"));
        // The bare `+$  effect  *` line must be gone.
        assert!(!out.lines().any(|l| l.trim() == "+$  effect  *"));
    }
    #[test]
    fn duplicate_effect_type_bails() {
        let dir = tempdir_for_test("duplicate_effect_type");
        write_manifest_with_types(&dir, "a.toml", "alpha", "shared-effect", "alpha-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "shared-effect", "beta-cause");
        let err = discover_grafts(&dir).expect_err("duplicate type must bail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate [graft.types].effect `shared-effect`"),
            "got: {msg}"
        );
        assert!(msg.contains("a.toml"), "missing path a in: {msg}");
        assert!(msg.contains("b.toml"), "missing path b in: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_cause_type_bails() {
        let dir = tempdir_for_test("duplicate_cause_type");
        write_manifest_with_types(&dir, "a.toml", "alpha", "alpha-effect", "shared-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "beta-effect", "shared-cause");
        let err = discover_grafts(&dir).expect_err("duplicate type must bail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate [graft.types].cause `shared-cause`"),
            "got: {msg}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_effect_types_ok() {
        // Sanity: different effect names across two manifests must NOT
        // bail. Guards against an over-zealous uniqueness check.
        let dir = tempdir_for_test("distinct_effect_types");
        write_manifest_with_types(&dir, "a.toml", "alpha", "alpha-effect", "alpha-cause");
        write_manifest_with_types(&dir, "b.toml", "beta", "beta-effect", "beta-cause");
        let grafts = discover_grafts(&dir).expect("distinct types must load");
        assert_eq!(grafts.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codegen_leaves_custom_effect_type_alone() {
        // If the developer wrote `+$ effect (list @t)` (custom, not the
        // bare `*`), the codegen INSERTs after the marker without
        // touching the developer's line. The developer's definition
        // ends up colliding with the synthesized one — which is hoonc's
        // job to surface, not the codegen's. The point of this test is
        // to confirm we don't silently rewrite bespoke types.
        let src = "\
::  test
::
::  nockup:effect-union
+$  effect  (list @t)
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft_with_effect("alpha", 10);
        let (out, _report) = inject(src, &[g]).unwrap();
        assert!(
            out.contains("+$  effect  (list @t)"),
            "custom effect type must NOT be rewritten by codegen"
        );
    }

    // ---------------------------------------------------------------
    // load-defaults overlay codegen
    // ---------------------------------------------------------------

    #[test]
    fn load_defaults_skipped_without_marker() {
        // BARE_SCAFFOLD has no `nockup:load-defaults` marker — codegen
        // returns Skipped and the source is unchanged where the load
        // arm lives.
        let g = synthetic_graft("alpha", 10);
        let (out, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Skipped);
        assert!(report.load_defaults.fields.is_empty());
        assert!(!out.contains("graft-inject:load-defaults:begin"));
    }

    #[test]
    fn load_defaults_inserts_overlay_for_one_graft() {
        let g = synthetic_graft("alpha", 10);
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[g]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        assert!(out.contains("::  graft-inject:load-defaults:begin"));
        assert!(out.contains("=/  defaults  ^*(versioned-state)"));
        assert!(out.contains("%_  defaults"));
        // The per-field overlay line wraps the field-access in
        // `(mole |.(;;(<type> <field>.old-state)))` so same-composition
        // resume preserves data and schema-extension resume falls back
        // to defaults exactly where axes shifted.
        assert!(out.contains("alpha  =/  a  (mole |.(;;(alpha-state alpha.old-state)))"));
        assert!(out.contains("?~(a ^*(alpha-state) u.a)"));
        assert!(out.contains("::  graft-inject:load-defaults:end"));
        // The `old-state` placeholder line must be gone — the codegen
        // owns that slot now.
        let begin = out.find("graft-inject:load-defaults:begin").unwrap();
        let end = out.find("graft-inject:load-defaults:end").unwrap();
        let block = &out[begin..end];
        assert!(
            !block.contains("\n    old-state\n") && !block.ends_with("old-state"),
            "raw `old-state` placeholder must be replaced by overlay\nblock:\n{block}"
        );
    }

    #[test]
    fn load_defaults_emits_fields_in_priority_order() {
        let grafts = vec![
            synthetic_graft("alpha", 10),
            synthetic_graft("beta", 20),
            synthetic_graft("gamma", 30),
        ];
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &grafts).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert_eq!(report.load_defaults.fields, vec!["alpha", "beta", "gamma"]);
        let begin = out.find("graft-inject:load-defaults:begin").unwrap();
        let end = out.find("graft-inject:load-defaults:end").unwrap();
        let block = &out[begin..end];
        let alpha = block.find("alpha  =/  a  (mole").unwrap();
        let beta = block.find("beta  =/  b  (mole").unwrap();
        let gamma = block.find("gamma  =/  g  (mole").unwrap();
        assert!(
            alpha < beta && beta < gamma,
            "fields out of priority order in:\n{block}"
        );
    }

    #[test]
    fn load_defaults_idempotent_unchanged_on_rerun() {
        let g = synthetic_graft("alpha", 10);
        let (first, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, std::slice::from_ref(&g)).unwrap();
        let (second, report) = inject(&first, &[g]).unwrap();
        assert_eq!(first, second, "second run must be byte-identical");
        assert_eq!(report.load_defaults.status, CodegenStatus::Unchanged);
    }

    #[test]
    fn load_defaults_replace_grows_when_graft_added() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let (one, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, std::slice::from_ref(&alpha)).unwrap();
        let (two, report) = inject(&one, &[alpha, beta]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Replaced);
        assert_eq!(report.load_defaults.fields, vec!["alpha", "beta"]);
        assert!(two.contains("alpha  =/  a  (mole"));
        assert!(two.contains("beta  =/  b  (mole"));
    }

    #[test]
    fn load_defaults_replace_shrinks_when_graft_removed() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let (two, _) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[alpha.clone(), beta]).unwrap();
        assert!(two.contains("beta  =/  b  (mole"));
        let (one, report) = inject(&two, &[alpha]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Replaced);
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        let begin = one.find("graft-inject:load-defaults:begin").unwrap();
        let end = one.find("graft-inject:load-defaults:end").unwrap();
        let block = &one[begin..end];
        assert!(
            !block.contains("beta  =/  b  (mole"),
            "removed graft's overlay line must be gone\nblock:\n{block}",
        );
    }

    #[test]
    fn load_defaults_empty_graft_set_emits_bunt() {
        // A composition with no stateful grafts (e.g. forge-only)
        // should still produce a valid `_state`-typed expression. The
        // codegen emits a bare `^*(versioned-state)` so the load arm
        // is the bunt of the kernel state shape.
        let (out, report) = inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[]).unwrap();
        assert_eq!(report.load_defaults.status, CodegenStatus::Inserted);
        assert!(report.load_defaults.fields.is_empty());
        assert!(out.contains("^*(versioned-state)"));
        assert!(!out.contains("%_  defaults"));
    }

    #[test]
    fn load_defaults_skips_graft_without_state_block() {
        // A graft that doesn't declare a `[graft.blocks.state]` block
        // (forge-graft pattern: stateless) doesn't contribute a state
        // field to versioned-state, so it must NOT appear in the
        // overlay either.
        let with_state = synthetic_graft("alpha", 10);
        let mut without_state = synthetic_graft("forge", 50);
        without_state.blocks.state = None;
        let (out, report) =
            inject(SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER, &[with_state, without_state]).unwrap();
        assert_eq!(report.load_defaults.fields, vec!["alpha"]);
        assert!(out.contains("alpha  =/  a  (mole"));
        assert!(
            !out.contains("forge  =/  f  (mole"),
            "stateless graft must not contribute a load-defaults overlay line\n{out}",
        );
    }

    #[test]
    fn load_defaults_orphan_end_banner_bails() {
        // An orphan end banner (no matching begin) is structural
        // corruption; the codegen must surface it via Result::Err
        // rather than silently emit a duplicate banner pair.
        let src = "\
::  test
::  nockup:load-defaults
::  graft-inject:load-defaults:end
old-state
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";
        let g = synthetic_graft("alpha", 10);
        let err = inject(src, &[g]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("orphan") && msg.contains("load-defaults"),
            "expected orphan-banner error, got: {msg}"
        );
    }
}
