//! Marker-driven block composer: walks the kernel source, strips and
//! re-emits banner-wrapped per-graft blocks at each `::  nockup:<X>`
//! marker, and bridges to the codegen + lint passes.
//!
//! Audit §3.2 extraction. The flow is:
//!
//!   1. Auto-prune orphan banner pairs whose graft is no longer in the
//!      active set (`orphan_graft_names`).
//!   2. For each `Marker::ALL`: classify the per-graft state
//!      (`check_injection`) and then canonicalize the marker section
//!      (`canonicalize_marker_section`).
//!   3. Run the codegen passes (`emit_effect_union`,
//!      `emit_load_defaults`) and the weld-friction lint
//!      (`lint_weld_friction`).
//!
//! The legacy-effect auto-migration (`migrate_legacy_effect`,
//! `print_migration_line`) is a pre-pass owned by `run_inject` —
//! kept in this module because it mutates the same kernel source the
//! inject loop will then process.
//!
//! `binding_stub` is exported as `pub(crate)` because codegen needs the
//! same `-graft` suffix-stripper for its load-defaults overlay.

use anyhow::Result;
use std::collections::{HashMap, HashSet};

use crate::codegen::{CodegenReport, LoadDefaultsReport, emit_effect_union, emit_load_defaults};
use crate::lint::{WeldLint, lint_weld_friction};
use crate::manifest::Graft;
use crate::marker::{
    Marker, begin_banner, begin_banner_with_sha, end_banner, find_marker, leading_whitespace,
    strip_banner_pair,
};

/// Per-graft injection summary returned by `inject()`. Drives `print_report`
/// and the `--list` machine-readable output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InjectReport {
    /// Markers found in the source file.
    pub(crate) markers_in_source: Vec<Marker>,
    /// Markers expected but not present in source.
    pub(crate) markers_missing: Vec<Marker>,
    /// Per-graft outcome, in the same order as the input slice.
    pub(crate) grafts: Vec<GraftReport>,
    /// Grafts whose banner pairs were present in source but absent from
    /// the active `--grafts` set on this run. Their orphan blocks were
    /// auto-pruned. Carrier separate from `grafts` because no manifest
    /// is loaded for these names.
    pub(crate) pruned_grafts: Vec<GraftReport>,
    /// Outcome of the typed effect-union codegen pass.
    pub(crate) codegen: CodegenReport,
    /// Weld-friction lint findings in domain code.
    pub(crate) weld_lint: WeldLint,
    /// RM4 §1 v0.2: outcome of the `++load` defaults codegen pass.
    pub(crate) load_defaults: LoadDefaultsReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GraftReport {
    pub(crate) name: String,
    /// Markers this graft contributes a block for.
    pub(crate) applicable: Vec<Marker>,
    /// Markers this graft injected on this run.
    pub(crate) injected: Vec<Marker>,
    /// Markers where the graft's sentinel was already present (idempotent skip).
    pub(crate) skipped: Vec<Marker>,
    /// Markers stripped as orphans this run — banner pairs were present
    /// in the source but the graft is no longer in the active set.
    pub(crate) pruned: Vec<Marker>,
}

pub(crate) fn inject(source: &str, grafts: &[Graft]) -> Result<(String, InjectReport)> {
    // Normalize CRLF -> LF for processing; we re-emit LF regardless.
    let mut lines: Vec<String> = source.replace("\r\n", "\n").lines().map(String::from).collect();
    let trailing_newline = source.ends_with('\n');

    let mut markers_in_source: Vec<Marker> = Vec::new();
    let mut markers_missing: Vec<Marker> = Vec::new();
    let mut per_graft: HashMap<String, GraftReport> = grafts
        .iter()
        .map(|g| {
            let applicable: Vec<Marker> = Marker::ALL
                .iter()
                .copied()
                .filter(|m| g.block(*m).is_some())
                .collect();
            (
                g.name.clone(),
                GraftReport {
                    name: g.name.clone(),
                    applicable,
                    injected: Vec::new(),
                    skipped: Vec::new(),
                    pruned: Vec::new(),
                },
            )
        })
        .collect();

    // RH1 step 1: auto-prune banner pairs whose graft is no longer in
    // `grafts`. Runs before the strip/inject loop so orphan blocks
    // referencing now-missing variants are gone before hoonc sees them
    // and before drift detection runs against a clean tree.
    let active: HashSet<&str> = grafts.iter().map(|g| g.name.as_str()).collect();
    let orphan_names = orphan_graft_names(&lines, &active);
    let mut pruned_grafts: Vec<GraftReport> = Vec::new();
    for name in &orphan_names {
        let mut pruned: Vec<Marker> = Vec::new();
        for marker in Marker::ALL {
            if strip_banner_pair(&mut lines, name, marker).is_some() {
                pruned.push(marker);
            }
        }
        if !pruned.is_empty() {
            eprintln!(
                "graft-inject: {}: orphan banner pair(s) at {} (graft not in active set). Pruning.",
                name,
                pruned
                    .iter()
                    .map(|m| m.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            pruned_grafts.push(GraftReport {
                name: name.clone(),
                applicable: pruned.clone(),
                injected: Vec::new(),
                skipped: Vec::new(),
                pruned,
            });
        }
    }

    for marker in Marker::ALL {
        let Some(initial_idx) = find_marker(&lines, marker)? else {
            markers_missing.push(marker);
            continue;
        };
        markers_in_source.push(marker);
        let indent = leading_whitespace(&lines[initial_idx]).to_string();

        // Filter to grafts that contribute a block at this marker.
        // Codegen-only markers (DomainEffect, EffectUnion) yield an
        // empty slice; canonicalize_marker_section returns immediately.
        let grafts_at_marker: Vec<&Graft> = grafts
            .iter()
            .filter(|g| g.block(marker).is_some())
            .collect();

        // Drive the per-graft report by reading the current banner state,
        // then unconditionally canonicalize. Output bytes are identical
        // whether a graft was UpToDate or drifted — the report just
        // distinguishes the two so users see a meaningful "skipped vs
        // injected" summary on rerun.
        for g in &grafts_at_marker {
            match check_injection(&lines, g, marker) {
                InjectStatus::Drift { old_sha } => {
                    eprintln!(
                        "graft-inject: {}: manifest drift at {} (banner sha256 {} → current {}). Re-injecting.",
                        g.name,
                        marker.label(),
                        old_sha,
                        g.sha256_short()
                    );
                    per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                }
                InjectStatus::Legacy => {
                    eprintln!(
                        "graft-inject: {}: legacy banner at {} (pre-A2, no sha256). Re-injecting in current format.",
                        g.name,
                        marker.label()
                    );
                    per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                }
                InjectStatus::UpToDate => {
                    per_graft.get_mut(&g.name).unwrap().skipped.push(marker);
                }
                InjectStatus::NotInjected => {
                    per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                }
            }
        }

        // RH2 step 2 (HARD-BUG-2 + HARD-BUG-3): collapse the dual
        // placement strategy (drift-preserve at orig_idx vs fresh-batch
        // at marker_idx+1) to a single canonical re-emit. The marker
        // section's graft blocks become a pure function of the active
        // set, so drop+readd is byte-identical and peek drift no longer
        // jumps to the chain tail.
        canonicalize_marker_section(&mut lines, marker, &indent, &grafts_at_marker);
    }

    // Typed effect-union codegen runs after the marker loop. REPLACE-
    // IF-PRESENT semantics keep the union in sync with the current
    // graft set on every rerun.
    let codegen = emit_effect_union(&mut lines, grafts)?;

    // RM4 §1 v0.2: load-defaults codegen runs after effect-union. Same
    // REPLACE-IF-PRESENT shape; populates the `++load` overlay so
    // resumed snapshots with a smaller noun shape get defaults at the
    // current kernel's new graft axes.
    let load_defaults = emit_load_defaults(&mut lines, grafts)?;

    // Weld-friction lint scans developer code (outside graft-inject
    // banners) for narrow effect bindings that will nest-fail at any
    // cross-graft `(weld a b)` site. Advisory only; surfaces in the
    // stderr report.
    let weld_lint = lint_weld_friction(&lines, &codegen.variants);

    // Preserve graft order in the report (per_graft is a HashMap).
    let grafts_reports: Vec<GraftReport> = grafts
        .iter()
        .map(|g| per_graft.remove(&g.name).expect("seeded above"))
        .collect();

    let mut output = lines.join("\n");
    if trailing_newline {
        output.push('\n');
    }
    Ok((
        output,
        InjectReport {
            markers_in_source,
            markers_missing,
            grafts: grafts_reports,
            pruned_grafts,
            codegen,
            weld_lint,
            load_defaults,
        },
    ))
}

/// RH2 step 2: a single placement strategy for graft blocks at one
/// marker. Strips every active-graft banner pair at `marker`, then
/// re-emits the slice in canonical (priority-then-name) order. The
/// final layout is a pure function of `grafts_for_marker`, so:
///
/// - drop+readd cycles produce byte-identical output (HARD-BUG-3),
/// - drift re-injection does not relocate the drifted block to a new
///   position relative to its peers (HARD-BUG-2 for peek; same fix
///   for all other markers).
///
/// Replaces RH1 step 2's `emit_position_preserving` dispatcher and the
/// `*_single_at` emitters. Codegen-only markers (DomainEffect,
/// EffectUnion, LoadDefaults) yield an empty slice from the caller's
/// filter, so the early return covers them — `emit_effect_union` and
/// `emit_load_defaults` run separately after the marker loop.
fn canonicalize_marker_section(
    lines: &mut Vec<String>,
    marker: Marker,
    indent: &str,
    grafts_for_marker: &[&Graft],
) {
    if grafts_for_marker.is_empty() {
        return;
    }
    for g in grafts_for_marker {
        strip_banner_pair(lines, &g.name, marker);
    }
    let marker_idx = find_marker(lines, marker)
        .expect("io-free find_marker")
        .expect("marker still present after strip — caller observed it pre-strip");
    match marker {
        Marker::Peek => emit_peek_chain(lines, marker_idx, indent, grafts_for_marker),
        Marker::Imports => emit_imports_block(lines, marker_idx, indent, grafts_for_marker),
        _ => emit_block(lines, marker_idx, indent, marker, grafts_for_marker),
    }
}

/// Insert composed body lines after the marker, each pending graft wrapped
/// in a `::  graft-inject:<name>:<marker>:begin` / `:end` banner pair. The
/// banners carry per-graft-per-marker idempotence (AUDIT 2026-04-19
/// H-11..H-14): re-runs scan for the begin banner by exact trimmed-line
/// match rather than hunting for body substrings inside an expanding
/// `?-` switch. Distinct marker labels keep a graft's banner at one
/// marker from being mistaken for its banner at another.
fn emit_block(
    lines: &mut Vec<String>,
    marker_idx: usize,
    indent: &str,
    marker: Marker,
    pending: &[&Graft],
) {
    let mut composed: Vec<String> = Vec::new();
    for g in pending.iter() {
        composed.push(begin_banner_with_sha(&g.name, marker, g.sha256_short()));
        let body = g
            .block(marker)
            .expect("emit_block called with a graft missing this marker")
            .trimmed_body();
        for line in body.lines() {
            composed.push(line.to_string());
        }
        composed.push(end_banner(&g.name, marker));
    }
    let indented: Vec<String> = composed
        .into_iter()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{}{}", indent, l)
            }
        })
        .collect();
    for (offset, line) in indented.into_iter().enumerate() {
        lines.insert(marker_idx + 1 + offset, line);
    }
}

/// Imports-specific emission that dedupes `/+  *foo` / `/-  *foo`
/// directives against what's already in the source file.
///
/// AUDIT 2026-04-19 M-22: four shipped grafts (settle/mint/guard/forge)
/// each import `*vesl-merkle`, so composing all four with a plain
/// concatenation produced four identical `/+  *vesl-merkle` lines.
/// Hoonc tolerates the duplicates but the noise lets a malicious manifest
/// hide an extra import in the dup-clutter during security review.
/// Preserves banner comments, indentation, and non-import body lines;
/// only skips `/+  *X` / `/-  *X` whose `X` was already imported by an
/// earlier line in the target file.
fn emit_imports_block(
    lines: &mut Vec<String>,
    marker_idx: usize,
    indent: &str,
    pending: &[&Graft],
) {
    let mut seen: HashSet<String> = lines
        .iter()
        .filter_map(|l| parse_glob_import(l).map(|s| s.to_string()))
        .collect();

    let mut composed: Vec<String> = Vec::new();
    for g in pending.iter() {
        composed.push(begin_banner_with_sha(&g.name, Marker::Imports, g.sha256_short()));
        let body = g
            .block(Marker::Imports)
            .expect("emit_imports_block called with a graft missing imports")
            .trimmed_body();
        for line in body.lines() {
            if let Some(name) = parse_glob_import(line) {
                if !seen.insert(name.to_string()) {
                    // Already imported — drop to keep the imports block
                    // mirror-readable. A comment trail would restore the
                    // audit-hide surface we're trying to close.
                    continue;
                }
            }
            composed.push(line.to_string());
        }
        composed.push(end_banner(&g.name, Marker::Imports));
    }
    let indented: Vec<String> = composed
        .into_iter()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{}{}", indent, l)
            }
        })
        .collect();
    for (offset, line) in indented.into_iter().enumerate() {
        lines.insert(marker_idx + 1 + offset, line);
    }
}

/// Extract the glob-import target from a line like `/+  *foo` or `/-  *bar`.
/// Returns None for any other shape (comments, plain `/+  bar`, body lines).
fn parse_glob_import(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("/+")
        .or_else(|| trimmed.strip_prefix("/-"))?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('*')?;
    // Name is everything up to the first whitespace or end-of-line.
    let name_end = rest
        .find(|c: char| c.is_whitespace())
        .unwrap_or(rest.len());
    let name = &rest[..name_end];
    if name.is_empty() { None } else { Some(name) }
}

/// Emit the peek-chain prelude(s) immediately before the terminal `~`
/// fallback. Each graft contributes a banner-wrapped pair:
///
///   ::  graft-inject:<name>:begin
///   =/  <stub>-res  <peek.body>
///   ?.  =(~ <stub>-res)  <stub>-res
///   ::  graft-inject:<name>:end
///
/// where `<stub>` is the graft name with the `-graft` suffix stripped.
/// The bare `~` already in the source remains as the chain's terminal
/// fallback. If no bare `~` is found between the marker and the block's
/// closing `==`, a synthetic one is appended so the `?+` still has
/// something to evaluate.
fn emit_peek_chain(
    lines: &mut Vec<String>,
    marker_idx: usize,
    indent: &str,
    pending: &[&Graft],
) {
    let chain_lines: Vec<String> = pending
        .iter()
        .flat_map(|g| {
            let body = g
                .block(Marker::Peek)
                .expect("peek graft missing a peek block")
                .trimmed_body();
            let stub = binding_stub(&g.name);
            vec![
                format!(
                    "{indent}{}",
                    begin_banner_with_sha(&g.name, Marker::Peek, g.sha256_short())
                ),
                format!("{indent}=/  {stub}-res  {body}"),
                format!("{indent}?.  =(~ {stub}-res)  {stub}-res"),
                format!("{indent}{}", end_banner(&g.name, Marker::Peek)),
            ]
        })
        .collect();

    if let Some(target) = find_last_bare_tilde(lines, marker_idx) {
        for (offset, line) in chain_lines.into_iter().enumerate() {
            lines.insert(target + offset, line);
        }
    } else {
        let mut to_insert = chain_lines;
        to_insert.push(format!("{indent}~"));
        for (offset, line) in to_insert.into_iter().enumerate() {
            lines.insert(marker_idx + 1 + offset, line);
        }
    }
}

/// Strip the `-graft` suffix from a graft name to get the binding stub
/// used in the peek chain (`settle-graft` -> `settle`, `mint-graft` -> `mint`).
pub(crate) fn binding_stub(name: &str) -> &str {
    name.strip_suffix("-graft").unwrap_or(name)
}

/// Per-graft-per-marker idempotence status. Distinguishes "banner
/// present and current" from "banner present but stale" (manifest drift
/// or pre-A2 legacy format) so the inject pass can strip-and-reinject
/// rather than silently leave a stale block in place.
///
/// R5/A2 surfaced this gap: pre-A2 graft-inject treated mere banner
/// presence as the skip signal, so editing `<graft>.toml` (e.g. swapping
/// `[graft.gates] gate = "sig-verify-schnorr"` to `"sig-verify-ed25519"`)
/// and re-running `graft-inject --apply` left the old gate body in place.
/// Embedding the manifest sha256 in the begin banner closes that gap.
#[derive(Debug, Clone, PartialEq)]
enum InjectStatus {
    /// Banner present, embedded sha256 matches current manifest. Skip.
    UpToDate,
    /// Banner present but embedded sha256 differs — manifest drift.
    /// The caller strips the banner pair and re-injects.
    Drift { old_sha: String },
    /// Banner present in pre-A2 legacy format (no sha256 suffix).
    /// Force-reinject once to stamp the new format.
    Legacy,
    /// No banner present. Fresh inject.
    NotInjected,
}

/// Per-graft-per-marker idempotence check.
///
/// AUDIT 2026-04-19 H-11..H-14: the pre-audit implementation walked a
/// marker window for the graft's sentinel string. That had three
/// failure modes — cross-graft false positives (A's body containing B's
/// sentinel), peek-chain overflow past the 10-line window at 6+ grafts,
/// and early termination on an inner `==` inside any poke body. A banner
/// comment emitted alongside each injected block removed those three
/// footguns. R5/A2 (2026-05-04) extended the banner with a 12-char
/// sha256 prefix so re-runs detect manifest drift as well.
fn check_injection(lines: &[String], graft: &Graft, marker: Marker) -> InjectStatus {
    let prefix = begin_banner(&graft.name, marker);
    let current_sha = graft.sha256_short();
    for line in lines {
        let trimmed = line.trim();
        if !trimmed.starts_with(&prefix) {
            continue;
        }
        let suffix = &trimmed[prefix.len()..];
        if suffix.is_empty() {
            return InjectStatus::Legacy;
        }
        if let Some(sha) = suffix.strip_prefix(" sha256:") {
            return if sha == current_sha {
                InjectStatus::UpToDate
            } else {
                InjectStatus::Drift {
                    old_sha: sha.to_string(),
                }
            };
        }
        // Unrecognized suffix: treat as legacy, force re-inject once.
        return InjectStatus::Legacy;
    }
    InjectStatus::NotInjected
}

/// Scan `lines` for `::  graft-inject:<name>:<marker>:begin` banners
/// whose `<name>` is not in `active`. Returns the set of orphan graft
/// names. Used by the prune pre-pass in `inject()` to detect grafts
/// that were previously injected but have been dropped from `--grafts`.
///
/// Discrimination: codegen banners (e.g. `::  graft-inject:effect-union:begin`)
/// have a single segment between `graft-inject:` and `:begin` that matches
/// a `Marker::label()`; per-graft banners have two segments (`<name>:<marker>`).
/// Codegen banners are owned by the tool itself and must never be pruned.
fn orphan_graft_names(
    lines: &[String],
    active: &HashSet<&str>,
) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    const PREFIX: &str = "::  graft-inject:";
    let marker_labels: HashSet<&str> = Marker::ALL.iter().map(|m| m.label()).collect();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in lines {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(PREFIX) else {
            continue;
        };
        let Some((segment, _tail)) = rest.split_once(':') else {
            continue;
        };
        // Codegen banner — single segment is a Marker label, never a graft name.
        if marker_labels.contains(segment) {
            continue;
        }
        // Per-graft banner — first segment is the graft name.
        if !active.contains(segment) {
            names.insert(segment.to_string());
        }
    }
    names
}

/// Last bare `~` between the peek marker and the block's closing `==`.
/// The pre-audit implementation capped the scan at 10 lines, which broke
/// idempotence once 6+ grafts were wired (AUDIT 2026-04-19 H-13): new
/// grafts landed ahead of the existing chain, duplicating the `~` and
/// preempting earlier grafts' peek semantics. Scanning the entire block
/// and returning the last bare `~` keeps the new pair inserted just
/// before the terminal fallback no matter how long the chain grows.
fn find_last_bare_tilde(lines: &[String], marker_idx: usize) -> Option<usize> {
    let mut last = None;
    // Index-based loop is the clearer shape here: we return `i` on match and
    // break early on `==`. An iterator adapter would need `take_while` with a
    // side effect, which reads worse than the straight range loop.
    #[allow(clippy::needless_range_loop)]
    for i in (marker_idx + 1)..lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "==" {
            break;
        }
        if trimmed == "~" {
            last = Some(i);
        }
    }
    last
}

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
