//! Marker-driven block composer: walks the kernel source, strips and
//! re-emits banner-wrapped per-graft blocks at each `::  nockup:<X>`
//! marker, and bridges to the codegen + lint passes.
//!
//! The flow is:
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

use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::codegen::{CodegenReport, LoadDefaultsReport, emit_effect_union, emit_load_defaults};
use crate::lint::{LintFinding, lint_weld_friction};
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
    /// Weld-friction lint findings in domain code. Advisory only;
    /// every element is `LintFinding::WeldFriction`.
    pub(crate) weld_lint: Vec<LintFinding>,
    /// Outcome of the `++load` defaults codegen pass.
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

    // Auto-prune banner pairs whose graft is no longer in
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
                        "graft-inject: {}: legacy banner at {} (no sha256 suffix). Re-injecting in current format.",
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

        // Collapse the dual placement strategy (drift-preserve at
        // orig_idx vs fresh-batch at marker_idx+1) to a single canonical
        // re-emit. The marker section's graft blocks become a pure
        // function of the active set, so drop+readd is byte-identical
        // and peek drift no longer jumps to the chain tail.
        canonicalize_marker_section(&mut lines, marker, &indent, &grafts_at_marker);
    }

    // Typed effect-union codegen runs after the marker loop. REPLACE-
    // IF-PRESENT semantics keep the union in sync with the current
    // graft set on every rerun.
    let codegen = emit_effect_union(&mut lines, grafts)?;

    // Load-defaults codegen runs after effect-union. Same
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

/// Refuse a compose where an active graft contributes a block for a
/// marker absent from `path`. The block has nowhere to land and is
/// silently dropped — a partial, misleading kernel — so this is a hard
/// error, not a buried warning. A marker absent because *no* active
/// graft needs it (selective composition, or a codegen-only marker) is
/// fine and not flagged.
pub(crate) fn enforce_markers_placeable(report: &InjectReport, path: &Path) -> Result<()> {
    let mut unplaceable: Vec<(&str, Marker)> = Vec::new();
    for g in &report.grafts {
        for marker in &g.applicable {
            if report.markers_missing.contains(marker) {
                unplaceable.push((g.name.as_str(), *marker));
            }
        }
    }
    if unplaceable.is_empty() {
        return Ok(());
    }
    for (name, marker) in &unplaceable {
        eprintln!(
            "graft-inject: {} contributes a `{}` block, but {} has no \
             `::  nockup:{}` marker to place it at.",
            name,
            marker.label(),
            path.display(),
            marker.label(),
        );
    }
    bail!(
        "{} graft block(s) could not be placed — add the missing marker(s) \
         to {} and re-run (the vesl template carries the canonical marker set)",
        unplaceable.len(),
        path.display(),
    )
}

/// A single placement strategy for graft blocks at one marker. Strips
/// every active-graft banner pair at `marker`, then re-emits the slice
/// in canonical (priority-then-name) order. The final layout is a pure
/// function of `grafts_for_marker`, so:
///
/// - drop+readd cycles produce byte-identical output,
/// - drift re-injection does not relocate the drifted block to a new
///   position relative to its peers (at the peek marker, and the same
///   for all other markers).
///
/// Replaces the earlier `emit_position_preserving` dispatcher and the
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

/// Prepend `indent` to a non-empty line; an empty line stays empty.
/// The whitespace rule the composer applies to every banner and body
/// line it emits.
fn indent_line(indent: &str, line: &str) -> String {
    if line.is_empty() {
        String::new()
    } else {
        format!("{indent}{line}")
    }
}

/// The lines `emit_block` writes *between* a graft's begin and end
/// banner at `marker`, indented by `indent` — the canonical "what this
/// block body should be". Read-only: `emit_block` renders with it, and
/// `doctor`'s hand-edit check compares it against the live source.
/// Empty when the graft declares no block at `marker`.
pub(crate) fn expected_block_body(graft: &Graft, marker: Marker, indent: &str) -> Vec<String> {
    graft
        .block(marker)
        .map(|b| {
            b.trimmed_body()
                .lines()
                .map(|l| indent_line(indent, l))
                .collect()
        })
        .unwrap_or_default()
}

/// Insert composed body lines after the marker, each pending graft wrapped
/// in a `::  graft-inject:<name>:<marker>:begin` / `:end` banner pair. The
/// banners carry per-graft-per-marker idempotence: re-runs scan for the
/// begin banner by exact trimmed-line
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
    // canonicalize_marker_section only routes grafts here that declare a
    // block at `marker`, so expected_block_body always returns that
    // block's body.
    let mut composed: Vec<String> = Vec::new();
    for g in pending.iter() {
        composed.push(indent_line(
            indent,
            &begin_banner_with_sha(&g.name, marker, g.sha256_short()),
        ));
        composed.extend(expected_block_body(g, marker, indent));
        composed.push(indent_line(indent, &end_banner(&g.name, marker)));
    }
    for (offset, line) in composed.into_iter().enumerate() {
        lines.insert(marker_idx + 1 + offset, line);
    }
}

/// Imports-specific emission that dedupes `/+  *foo` / `/-  *foo`
/// directives against what's already in the source file.
///
/// Four shipped grafts (settle/mint/guard/forge)
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
/// or legacy format) so the inject pass can strip-and-reinject
/// rather than silently leave a stale block in place.
///
/// An earlier graft-inject treated mere banner
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
    /// Banner present in legacy format (no sha256 suffix).
    /// Force-reinject once to stamp the new format.
    Legacy,
    /// No banner present. Fresh inject.
    NotInjected,
}

/// Per-graft-per-marker idempotence check.
///
/// An earlier implementation walked a marker window for the graft's
/// sentinel string. That had three failure modes — cross-graft false
/// positives (A's body containing B's sentinel), peek-chain overflow
/// past the 10-line window at 6+ grafts, and early termination on an
/// inner `==` inside any poke body. A banner comment emitted alongside
/// each injected block removed those three footguns; the banner was
/// later extended with a 12-char sha256 prefix so re-runs detect
/// manifest drift as well.
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
/// idempotence once 6+ grafts were wired: new
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::CodegenStatus;
    use crate::manifest::{Block, Graft, GraftBlocks, load_manifest, sha256_hex};
    use crate::marker::{Marker, leading_whitespace};
    use crate::test_support::*;

    #[test]
    fn injects_all_markers() {
        let grafts = settle_only_grafts();
        let (out, report) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        assert!(out.contains("/+  *settle-graft"));
        assert!(out.contains("/+  *vesl-merkle"));
        assert!(out.contains("settle=settle-state"));
        assert!(out.contains("settle-cause"));
        assert!(out.contains("%settle-register"));
        assert!(out.contains("%settle-verify"));
        assert!(out.contains("%settle-note"));
        // Peek emits the chain shape: the legacy expression lives
        // inside the `=/ settle-res ...` binding.
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("?.  =(~ settle-res)  settle-res"));

        // BARE_SCAFFOLD ships with the seven non-codegen markers (imports,
        // state, cause, poke-prelude, poke, poke-postlude, peek). The
        // three codegen markers (domain-effect, effect-union, load-defaults)
        // land via auto-migration and template refreshes, so they are
        // expected to be missing here.
        assert_eq!(report.markers_in_source.len(), 7);
        assert_eq!(report.markers_missing.len(), 3);
        let settle = &report.grafts[0];
        assert_eq!(settle.name, "settle-graft");
        // settle-graft contributes 5 of the 7 non-codegen markers
        // (no prelude / postlude). Codegen markers contribute no per-graft
        // blocks.
        assert_eq!(settle.injected.len(), 5);
        assert!(settle.skipped.is_empty());
    }

    #[test]
    fn is_idempotent() {
        let grafts = settle_only_grafts();
        let (first, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let (second, report) = inject(&first, &grafts).unwrap();
        assert_eq!(first, second, "second inject must produce identical output");
        let settle = &report.grafts[0];
        assert!(settle.injected.is_empty(), "no marker should re-inject");
        assert_eq!(settle.skipped.len(), 5, "all 5 markers should skip");
    }

    /// Regression: forge's poke sentinel (`%forge-prove`) landed past the
    /// old 60-line window once settle+mint+guard had injected their arms
    /// above it, so re-running graft-inject duplicated forge's poke block.
    /// Walking the `?-` switch to its `==` cap fixes it — this test guards
    /// the fix. It synthesizes four grafts with distinct, wide poke bodies
    /// so real-manifest paths aren't a prerequisite.
    #[test]
    fn poke_idempotence_four_grafts() {
        let grafts: Vec<Graft> = vec![
            synthetic_graft("settle", 10),
            synthetic_graft("mint", 20),
            synthetic_graft("guard", 30),
            synthetic_graft("forge", 40),
        ];
        let (first, first_report) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        for g in &first_report.grafts {
            assert!(
                !g.injected.is_empty(),
                "pass 1: {} should inject at least one marker",
                g.name
            );
        }
        let (second, second_report) = inject(&first, &grafts).unwrap();
        assert_eq!(
            first, second,
            "second inject must produce byte-identical output across all four grafts"
        );
        for g in &second_report.grafts {
            assert!(
                g.injected.is_empty(),
                "pass 2: {} re-injected marker(s) {:?} — idempotence broken",
                g.name,
                g.injected
            );
        }
        let forge = second_report
            .grafts
            .iter()
            .find(|g| g.name == "forge")
            .expect("forge graft present");
        assert!(
            forge.skipped.contains(&Marker::Poke),
            "forge poke must be detected as already-wired on re-run"
        );
        let first_forge_count = first.matches("%forge-do").count();
        let second_forge_count = second.matches("%forge-do").count();
        assert_eq!(
            first_forge_count, second_forge_count,
            "forge sentinel count must not grow between runs (first={}, second={})",
            first_forge_count, second_forge_count
        );
    }

    #[test]
    fn preserves_two_space_law() {
        // The two-space law applies to every Hoon rune in the manifest
        // bodies. Scan the loaded `settle-graft.toml`.
        let graft = load_manifest(&settle_graft_manifest_path())
            .unwrap()
            .unwrap();
        let bodies: Vec<&str> = Marker::ALL
            .iter()
            .filter_map(|m| graft.block(*m).map(|b| b.trimmed_body()))
            .collect();
        for body in bodies {
            for line in body.lines() {
                let trimmed = line.trim_start();
                for rune in ["=/", "|=", "/+", "/-", "/=", "^-", ":_", "?-", "?+", "?~", "?."] {
                    if let Some(rest) = trimmed.strip_prefix(rune) {
                        let next_two: Vec<char> = rest.chars().take(2).collect();
                        match next_two.as_slice() {
                            [] => {}
                            [' ', ' '] => {}
                            [' ', _] => panic!("single-space `{rune}` in body line: {line:?}"),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// `inject()` itself records missing markers in the report without
    /// erroring. The hard-error policy lives in `run_inject` / `run_update`
    /// via `enforce_markers_placeable`.
    #[test]
    fn inject_records_missing_markers_in_report() {
        let grafts = settle_only_grafts();
        let src = "::  just a comment\n";
        let result = inject(src, &grafts);
        assert!(result.is_ok());
        let (_, report) = result.unwrap();
        assert_eq!(report.markers_missing.len(), Marker::ALL.len());
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn does_not_match_nockup_pokemon() {
        let grafts = settle_only_grafts();
        let src = "::  nockup:pokemon\n";
        let (_, report) = inject(src, &grafts).unwrap();
        assert_eq!(report.markers_missing.len(), Marker::ALL.len());
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn single_graft_injection_pastes_body_verbatim() {
        // The data-driven inject() pastes the manifest body verbatim at
        // every non-peek marker, with the marker's leading whitespace
        // prepended and no other rewriting. Peek is excluded — see
        // peek_chain_n1_matches_legacy_replacement for that shape.
        let grafts = settle_only_grafts();
        let graft = &grafts[0];
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        for marker in [Marker::Imports, Marker::State, Marker::Cause, Marker::Poke] {
            let needle = format!("::  nockup:{}", marker.label());
            let marker_idx = lines
                .iter()
                .position(|l| {
                    let t = l.trim_start();
                    if !t.starts_with(&needle) {
                        return false;
                    }
                    // Word-boundary guard: `nockup:poke` must not match
                    // `nockup:poke-prelude` / `nockup:poke-postlude` —
                    // mirrors find_marker's tail check.
                    let tail = &t[needle.len()..];
                    tail.is_empty() || tail.chars().all(|c| c.is_whitespace())
                })
                .unwrap_or_else(|| panic!("marker `{}` missing from output", marker.label()));
            let marker_indent = leading_whitespace(lines[marker_idx]).to_string();
            let body = graft
                .block(marker)
                .expect("settle claims this marker")
                .trimmed_body();
            // Body lands one row after the begin banner, which carries a
            // ` sha256:<short>` suffix — assert on the prefix, not the live
            // sha256.
            let expected_prefix =
                format!("{marker_indent}::  graft-inject:settle-graft:{}:begin", marker.label());
            assert!(
                lines[marker_idx + 1].starts_with(&expected_prefix),
                "marker `{}` begin banner missing; got: {}",
                marker.label(),
                lines[marker_idx + 1]
            );
            for (i, want) in body.lines().enumerate() {
                let got = lines[marker_idx + 2 + i];
                let expected = if want.is_empty() {
                    String::new()
                } else {
                    format!("{marker_indent}{want}")
                };
                assert_eq!(
                    got,
                    expected,
                    "marker `{}` line {i} byte mismatch",
                    marker.label()
                );
            }
        }
    }

    #[test]
    fn multi_graft_injection_composes_blocks() {
        // vesl + two synthetic grafts, all three contribute to every marker.
        // Each marker region must contain all three sentinels in priority order.
        let mut grafts = settle_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();

        // imports: all three import directives present
        assert!(out.contains("/+  *settle-graft"));
        assert!(out.contains("/+  *alpha"));
        assert!(out.contains("/+  *beta"));
        // state: all three field declarations
        assert!(out.contains("settle=settle-state"));
        assert!(out.contains("alpha=alpha-state"));
        assert!(out.contains("beta=beta-state"));
        // cause: all three cause-union members
        assert!(out.contains("settle-cause"));
        assert!(out.contains("alpha-cause"));
        assert!(out.contains("beta-cause"));
        // poke: all three first-arm tags
        assert!(out.contains("%settle-register"));
        assert!(out.contains("%alpha-do"));
        assert!(out.contains("%beta-do"));
        // peek: all three chain bindings
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("=/  alpha-res  (alpha-peek state path)"));
        assert!(out.contains("=/  beta-res  (beta-peek state path)"));
    }

    #[test]
    fn peek_chain_composition() {
        // Three grafts → each contributes a 4-line banner-wrapped pair
        // (begin, =/, ?., end) for 12 lines, plus the terminal `~` = 13
        // lines total immediately after the marker, in priority order.
        let mut grafts = settle_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<String> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(13)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 13, "expected 13 lines after peek marker");
        // Begin banners carry a ` sha256:<short>` suffix.
        // Match on the prefix to avoid coupling tests to live sha256
        // values of fixture manifests.
        assert!(peek_lines[0].starts_with("::  graft-inject:settle-graft:peek:begin"));
        assert_eq!(peek_lines[1], "=/  settle-res  (settle-peek settle.state path)");
        assert_eq!(peek_lines[2], "?.  =(~ settle-res)  settle-res");
        assert_eq!(peek_lines[3], "::  graft-inject:settle-graft:peek:end");
        assert!(peek_lines[4].starts_with("::  graft-inject:alpha:peek:begin"));
        assert_eq!(peek_lines[5], "=/  alpha-res  (alpha-peek state path)");
        assert_eq!(peek_lines[6], "?.  =(~ alpha-res)  alpha-res");
        assert_eq!(peek_lines[7], "::  graft-inject:alpha:peek:end");
        assert!(peek_lines[8].starts_with("::  graft-inject:beta:peek:begin"));
        assert_eq!(peek_lines[9], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[10], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[11], "::  graft-inject:beta:peek:end");
        assert_eq!(peek_lines[12], "~");
    }

    #[test]
    fn per_graft_idempotence_inject_settle_then_alpha() {
        // First inject settle alone; then re-inject with [settle, alpha].
        // settle region must not double-up (no duplicated sentinels), and
        // alpha must appear interleaved at every marker.
        let settle = settle_only_grafts();
        let (after_settle, _) = inject(BARE_SCAFFOLD, &settle).unwrap();

        let mut both = settle.clone();
        both.push(synthetic_graft("alpha", 50));
        let (after_both, report) = inject(&after_settle, &both).unwrap();

        // Use exact-trimmed-line matching to avoid spurious substring
        // hits inside the poke body (e.g., `new-settle=settle-state` contains
        // the `settle=settle-state` substring).
        let lines: Vec<&str> = after_both.lines().collect();
        let trimmed_eq_count = |needle: &str| -> usize {
            lines.iter().filter(|l| l.trim() == needle).count()
        };

        for needle in [
            "/+  *settle-graft",
            "/+  *vesl-merkle",
            "settle=settle-state",
            "settle-cause",
            "%settle-register",
            "=/  settle-res  (settle-peek settle.state path)",
        ] {
            assert_eq!(
                trimmed_eq_count(needle),
                1,
                "settle line `{needle}` must appear exactly once"
            );
        }
        for needle in [
            "/+  *alpha",
            "alpha=alpha-state",
            "alpha-cause",
            "%alpha-do",
            "=/  alpha-res  (alpha-peek state path)",
        ] {
            assert_eq!(
                trimmed_eq_count(needle),
                1,
                "alpha line `{needle}` must appear exactly once"
            );
        }
        // settle was wired on the first run, so all 5 of its markers
        // skip on the second; alpha is fresh and injects all 5.
        let settle_report = &report.grafts[0];
        let alpha_report = &report.grafts[1];
        assert_eq!(settle_report.name, "settle-graft");
        assert_eq!(settle_report.injected.len(), 0);
        assert_eq!(settle_report.skipped.len(), 5);
        assert_eq!(alpha_report.name, "alpha");
        assert_eq!(alpha_report.injected.len(), 5);
        assert_eq!(alpha_report.skipped.len(), 0);
    }

    #[test]
    fn peek_chain_idempotence_append_third_graft() {
        // Build vesl+alpha chain, then add beta. Beta's two lines must
        // land immediately before the terminal `~`, after the existing
        // vesl and alpha chain lines.
        let vesl_alpha: Vec<Graft> = {
            let mut v = settle_only_grafts();
            v.push(synthetic_graft("alpha", 50));
            v
        };
        let (after_va, _) = inject(BARE_SCAFFOLD, &vesl_alpha).unwrap();

        let mut all = vesl_alpha.clone();
        all.push(synthetic_graft("beta", 60));
        let (after_all, _) = inject(&after_va, &all).unwrap();

        // Beta lines exist exactly once in the output.
        assert_eq!(
            after_all
                .matches("=/  beta-res  (beta-peek state path)")
                .count(),
            1
        );

        // The peek region after the marker is now: vesl banner-wrapped pair,
        // alpha banner-wrapped pair, beta banner-wrapped pair, terminal `~`.
        // Each pair is 4 lines (begin, =/, ?., end); 3 pairs + `~` = 13 lines.
        // Beta's pair lands immediately before the terminal `~`.
        let peek_lines: Vec<String> = after_all
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(13)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 13);
        assert!(peek_lines[8].starts_with("::  graft-inject:beta:peek:begin"));
        assert_eq!(peek_lines[9], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[10], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[11], "::  graft-inject:beta:peek:end");
        assert_eq!(peek_lines[12], "~");
    }

    #[test]
    fn peek_chain_n1_matches_legacy_replacement() {
        // For N=1 the chain is:
        //   ::  graft-inject:settle-graft:peek:begin
        //   =/  settle-res  (settle-peek settle.state path)
        //   ?.  =(~ settle-res)  settle-res
        //   ::  graft-inject:settle-graft:peek:end
        //   ~                                   <- terminal fallback
        //
        // The `=/` binding wraps the legacy flat replacement — same runtime
        // semantics.
        let grafts = settle_only_grafts();
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<&str> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(5)
            .collect();
        assert_eq!(peek_lines.len(), 5, "peek region has fewer than 5 lines");
        assert!(
            peek_lines[0]
                .trim_start()
                .starts_with("::  graft-inject:settle-graft:peek:begin")
        );
        assert_eq!(
            peek_lines[1].trim_start(),
            "=/  settle-res  (settle-peek settle.state path)"
        );
        assert_eq!(peek_lines[2].trim_start(), "?.  =(~ settle-res)  settle-res");
        assert_eq!(
            peek_lines[3].trim_start(),
            "::  graft-inject:settle-graft:peek:end"
        );
        assert_eq!(peek_lines[4].trim_start(), "~");
    }
    /// H-12: graft A's injected body contains graft B's sentinel as a
    /// bare substring. Banner-comment idempotence must not mistake A's
    /// body for B being wired — B's begin banner is the only signal.
    #[test]
    fn cross_graft_sentinel_no_false_positive() {
        // `poison` carries `%contaminant-do` in its poke body but never
        // emits a `contaminant:poke:begin` banner. A subsequent run that
        // adds the real `contaminant` graft must still inject it.
        let poison = Graft {
            name: "poison".to_string(),
            version: "0.1.0".to_string(),
            priority: 10,
            after: vec![],
            blocks: GraftBlocks {
                imports: Some(Block {
                    body: "/+  *poison".to_string(),
                }),
                state: None,
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    body: "  %poison-do\n::  references %contaminant-do elsewhere\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
            schema_version: None,
            sha256: String::new(),
        };
        let contaminant = synthetic_graft("contaminant", 20);

        let (after_poison, _) = inject(BARE_SCAFFOLD, std::slice::from_ref(&poison)).unwrap();
        // Pre-condition: poison's body literally contains the contaminant sentinel.
        assert!(after_poison.contains("%contaminant-do"));

        let (after_both, report) =
            inject(&after_poison, &[poison.clone(), contaminant.clone()]).unwrap();
        let contaminant_report = report
            .grafts
            .iter()
            .find(|g| g.name == "contaminant")
            .expect("contaminant present");
        assert!(
            contaminant_report.injected.contains(&Marker::Poke),
            "H-12: contaminant poke must inject despite %contaminant-do \
             appearing in poison's body"
        );
        assert!(after_both.contains("::  graft-inject:contaminant:poke:begin"));

        // Now a second re-run with both grafts: nothing should inject.
        let (after_third, report) =
            inject(&after_both, &[poison, contaminant]).unwrap();
        assert_eq!(after_third, after_both);
        for g in &report.grafts {
            assert!(g.injected.is_empty(), "re-run must not re-inject {}", g.name);
        }
    }

    /// H-13: peek-chain idempotence broke at 6+ grafts because the bare
    /// `~` lived past the 10-line scan window. Build 7 grafts, inject,
    /// re-inject, and assert byte-identical output plus exactly one bare
    /// `~` between the peek marker and its `==` closer (the pre-fix path
    /// produced two).
    #[test]
    fn peek_chain_seven_grafts_idempotent() {
        let grafts: Vec<Graft> = (0..7)
            .map(|i| synthetic_graft(&format!("g{i}"), 10 + i * 10))
            .collect();
        let (first, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let (second, report) = inject(&first, &grafts).unwrap();
        assert_eq!(first, second, "seven-graft inject must be idempotent");
        for g in &report.grafts {
            assert!(g.injected.is_empty(), "{} re-injected", g.name);
        }
        let lines: Vec<&str> = second.lines().collect();
        let peek_idx = lines
            .iter()
            .position(|l| l.contains("nockup:peek"))
            .expect("peek marker present");
        let close_idx = lines[peek_idx..]
            .iter()
            .position(|l| l.trim() == "==")
            .map(|o| peek_idx + o)
            .expect("peek block closer");
        let tilde_count = lines[peek_idx..close_idx]
            .iter()
            .filter(|l| l.trim() == "~")
            .count();
        assert_eq!(
            tilde_count, 1,
            "exactly one terminal ~ expected in peek block"
        );
        // Peek block is large enough to span all 7 banner-wrapped pairs
        // (4 lines each) plus the terminal tilde.
        assert!(
            close_idx - peek_idx >= 7 * 4,
            "peek block should fit 7 banner-wrapped pairs, got {} lines",
            close_idx - peek_idx
        );
    }

    /// H-14: poke-body with an inner bare `==` line (a shape Hoon kernels
    /// routinely produce from nested `?-`/`?+` tuple destructures) made
    /// the sentinel walk terminate before reaching the sentinel, causing
    /// every re-run to append the body again. Banner-comment idempotence
    /// is file-wide, so inner `==` is no longer a concern — this locks
    /// the fix in place.
    #[test]
    fn poke_body_inner_double_equals_idempotent() {
        let nested = Graft {
            name: "nested".to_string(),
            version: "0.1.0".to_string(),
            priority: 10,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: None,
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    body: "  %nested-do\n?-  +.state\n  [%foo ~]  [~ state]\n  [%bar ~]  [~ state]\n==\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
            schema_version: None,
            sha256: String::new(),
        };
        let (first, _) = inject(BARE_SCAFFOLD, std::slice::from_ref(&nested)).unwrap();
        assert!(first.lines().any(|l| l.trim() == "=="), "inner == present");
        let (second, report) = inject(&first, &[nested]).unwrap();
        assert_eq!(first, second, "inner == must not re-trigger inject");
        assert!(report.grafts[0].injected.is_empty());
    }

    /// Removing a graft from the injection set auto-prunes its
    /// banner-pair-bounded blocks. An additive-only tool would leave
    /// orphan blocks that reference types missing from the shrunk
    /// effect-union, and hoonc would fail silently. The contract: drop a
    /// graft from `--grafts`, re-run with `--apply`, and the orphan
    /// blocks are stripped automatically.
    ///
    /// Byte-identical round-trip across drop-then-readd is covered
    /// separately; this test isolates the prune contract.
    #[test]
    fn removed_graft_auto_prunes_orphan_banners() {
        let a = synthetic_graft("alpha", 10);
        let b = synthetic_graft("beta", 20);
        let (after_both, _) = inject(BARE_SCAFFOLD, &[a.clone(), b.clone()]).unwrap();
        assert!(after_both.contains("::  graft-inject:beta:imports:begin"));
        let (after_alpha_only, report) = inject(&after_both, &[a]).unwrap();
        assert!(
            !after_alpha_only.contains("::  graft-inject:beta:"),
            "beta banner pairs must be pruned when beta drops from --grafts"
        );
        assert!(
            !after_alpha_only.contains("/+  *beta"),
            "beta imports must be pruned with the rest of its banner pair"
        );
        assert!(
            after_alpha_only.contains("::  graft-inject:alpha:imports:begin"),
            "alpha banners must remain — only beta dropped"
        );
        let pruned: Vec<&str> = report
            .pruned_grafts
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(pruned, vec!["beta"], "report surfaces beta as pruned");
        assert!(
            !report.pruned_grafts[0].pruned.is_empty(),
            "pruned markers list is non-empty"
        );
    }

    /// Manifest drift on a non-first graft must re-inject the block at
    /// its ORIGINAL line position, not at the marker line. An earlier
    /// strip-then-reinject path placed the drifted graft's block at
    /// marker_idx+1, pushing every later graft down by one — so a
    /// non-semantic edit (e.g., a gate-selection swap in the manifest)
    /// changed `sha256(app.hoon)` even though the file was logically
    /// equivalent. Drift re-injection at emit_block-class markers now
    /// preserves position; the file is byte-identical when the drifted
    /// manifest is reverted.
    #[test]
    fn drift_reinject_preserves_block_position() {
        let alpha = synthetic_graft("alpha", 10);
        let mut beta = synthetic_graft("beta", 20);
        // Compute and store a stable sha256 so check_injection can detect
        // "drift" when we later mutate the manifest.
        beta.sha256 = sha256_hex(b"beta-v1");

        let (composed, _) = inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone()]).unwrap();

        // Confirm beta's poke block is BELOW alpha's in the original.
        let alpha_poke = composed
            .lines()
            .position(|l| l.contains("graft-inject:alpha:poke:begin"))
            .expect("alpha poke banner present");
        let beta_poke = composed
            .lines()
            .position(|l| l.contains("graft-inject:beta:poke:begin"))
            .expect("beta poke banner present");
        assert!(
            alpha_poke < beta_poke,
            "initial layout: alpha:poke must precede beta:poke"
        );

        // Simulate a beta manifest edit (sha256 changes; body unchanged).
        let mut beta_drifted = beta.clone();
        beta_drifted.sha256 = sha256_hex(b"beta-v2");

        let (after_drift, _) =
            inject(&composed, &[alpha.clone(), beta_drifted]).unwrap();
        let alpha_poke2 = after_drift
            .lines()
            .position(|l| l.contains("graft-inject:alpha:poke:begin"))
            .expect("alpha poke banner survives drift");
        let beta_poke2 = after_drift
            .lines()
            .position(|l| l.contains("graft-inject:beta:poke:begin"))
            .expect("beta poke banner re-emitted after drift");
        assert!(
            alpha_poke2 < beta_poke2,
            "drift re-injection must preserve order: alpha:poke still precedes beta:poke. \
             An earlier path jumped the drifted graft to marker_idx+1, inverting the order."
        );

        // Revert beta to its original sha. The result is byte-identical
        // to the initial composition — drift round-trips at the byte level.
        let (after_revert, _) = inject(&after_drift, &[alpha, beta]).unwrap();
        assert_eq!(
            after_revert, composed,
            "drift-then-revert is byte-identical (drift round-trip invariant)"
        );
    }

    /// Peek-marker drift re-injection must preserve relative order
    /// between graft peek blocks. An earlier implementation excluded
    /// peek from the position-preservation gate, so peek drift fell
    /// through to the batch fresh-inject path (`emit_peek_chain`) which
    /// inserts before the chain's terminal `~` — relocating the drifted
    /// block to the tail. `canonicalize_marker_section` now strips and
    /// re-emits all active grafts in canonical order regardless of
    /// marker type.
    ///
    /// Test shape: drift the FIRST graft of a 3-graft chain — the
    /// settle-graft peek-migration scenario.
    #[test]
    fn peek_drift_reinject_preserves_block_position() {
        let mut alpha = synthetic_graft("alpha", 10);
        alpha.sha256 = sha256_hex(b"alpha-v1");
        let beta = synthetic_graft("beta", 20);
        let gamma = synthetic_graft("gamma", 30);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone(), gamma.clone()]).unwrap();

        let pos = |s: &str, g: &str| -> usize {
            s.lines()
                .position(|l| l.contains(&format!("graft-inject:{g}:peek:begin")))
                .unwrap_or_else(|| panic!("{g} peek banner missing"))
        };
        assert!(
            pos(&composed, "alpha") < pos(&composed, "beta"),
            "initial layout: alpha:peek precedes beta:peek"
        );
        assert!(
            pos(&composed, "beta") < pos(&composed, "gamma"),
            "initial layout: beta:peek precedes gamma:peek"
        );

        let mut alpha_drifted = alpha.clone();
        alpha_drifted.sha256 = sha256_hex(b"alpha-v2");

        let (after_drift, _) =
            inject(&composed, &[alpha_drifted, beta.clone(), gamma.clone()]).unwrap();

        assert!(
            pos(&after_drift, "alpha") < pos(&after_drift, "beta"),
            "drift re-injection must preserve order at the peek marker: \
             alpha:peek still precedes beta:peek. An earlier path \
             relocated the drifted peek block to the chain tail."
        );
        assert!(
            pos(&after_drift, "beta") < pos(&after_drift, "gamma"),
            "non-drifted blocks (beta, gamma) keep relative order through drift"
        );

        let (after_revert, _) = inject(&after_drift, &[alpha, beta, gamma]).unwrap();
        assert_eq!(
            after_revert, composed,
            "peek drift-then-revert is byte-identical (drift round-trip invariant)"
        );
    }

    /// Dropping a graft and re-adding it must not land the re-injected
    /// block at marker_idx+1 (position 1 of each marker section),
    /// displacing other graft blocks below the marker. With the
    /// canonical-re-emit strategy, the final layout is a pure function
    /// of the active graft set and drop+readd is byte-identical.
    #[test]
    fn drop_readd_preserves_position_byte_identical() {
        let alpha = synthetic_graft("alpha", 10);
        let beta = synthetic_graft("beta", 20);
        let gamma = synthetic_graft("gamma", 30);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[alpha.clone(), beta.clone(), gamma.clone()]).unwrap();

        let (after_drop, _) = inject(&composed, &[alpha.clone(), gamma.clone()]).unwrap();
        assert!(
            !after_drop.contains("graft-inject:beta:"),
            "beta banners pruned on drop (precondition for the readd test)"
        );

        let (after_readd, _) = inject(&after_drop, &[alpha, beta, gamma]).unwrap();
        assert_eq!(
            after_readd, composed,
            "drop+readd is byte-identical. An earlier path re-added \
             beta at marker_idx+1 in each section instead of between \
             alpha and gamma."
        );
    }

    /// Cross-marker drop+readd with four grafts. The byte-identical
    /// assertion catches both the direct (re-added graft position) and
    /// the collateral (other grafts moving) symptoms in a single check.
    #[test]
    fn cross_marker_drop_readd_no_collateral_movement() {
        let a = synthetic_graft("aaa", 10);
        let b = synthetic_graft("bbb", 20);
        let c = synthetic_graft("ccc", 30);
        let d = synthetic_graft("ddd", 40);

        let (composed, _) =
            inject(BARE_SCAFFOLD, &[a.clone(), b.clone(), c.clone(), d.clone()]).unwrap();

        let (after_drop, _) =
            inject(&composed, &[a.clone(), b.clone(), c.clone()]).unwrap();

        let (after_readd, _) = inject(&after_drop, &[a, b, c, d]).unwrap();

        assert_eq!(
            after_readd, composed,
            "drop+readd cycle (4 grafts) is byte-identical. \
             Catches the collateral-movement symptom — a graft jumping \
             to position 1 even though a different graft was re-added."
        );
    }
    /// Helper: collect every `WeldFriction` finding's `narrow_type`
    /// for set-style assertions in the weld-lint tests.
    fn weld_narrow_types(findings: &[LintFinding]) -> Vec<&str> {
        findings
            .iter()
            .filter_map(|f| match f {
                LintFinding::WeldFriction { narrow_type, .. } => Some(narrow_type.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Scaffold + a domain `%set` arm that binds narrowly. Used to
    /// exercise the weld-friction lint on developer code outside any
    /// graft-inject banner region.
    #[test]
    fn weld_lint_flags_narrow_bindings_in_domain_code() {
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (_, report) = inject(SCAFFOLD_NARROW_BINDING, &[kv, counter]).unwrap();
        assert_eq!(
            report.weld_lint.len(),
            2,
            "two narrow bindings should be flagged: {:#?}",
            report.weld_lint,
        );
        let narrow_types = weld_narrow_types(&report.weld_lint);
        assert!(narrow_types.contains(&"counter-effect"));
        assert!(narrow_types.contains(&"kv-effect"));
    }

    #[test]
    fn weld_lint_skips_graft_injected_bodies() {
        // Graft poke bodies legitimately contain `(list <graft>-effect)`.
        // The lint must only fire on developer code, not on graft-injected
        // regions between :begin/:end banners. Re-injecting the same
        // kernel keeps banner regions intact and asserts the lint count
        // doesn't grow with each graft's body.
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (out, _) = inject(SCAFFOLD_NARROW_BINDING, &[kv.clone(), counter.clone()]).unwrap();
        let (_, report) = inject(&out, &[kv, counter]).unwrap();
        // Still 2 — the graft poke bodies inside :begin/:end banners are
        // ignored, only the developer's domain bindings count.
        assert_eq!(report.weld_lint.len(), 2);
    }

    #[test]
    fn weld_lint_silent_on_widened_bindings() {
        // Pattern B: bindings widen to `(list effect)`. No findings.
        let widened = SCAFFOLD_NARROW_BINDING
            .replace("(list counter-effect)", "(list effect)")
            .replace("(list kv-effect)", "(list effect)");
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (_, report) = inject(&widened, &[kv, counter]).unwrap();
        assert!(
            report.weld_lint.is_empty(),
            "Pattern B widening must not trip the lint: {:#?}",
            report.weld_lint,
        );
    }

    #[test]
    fn weld_lint_silent_when_codegen_skipped() {
        // No nockup:effect-union marker → codegen Skipped → empty
        // variant list → lint short-circuits. Domain code is left
        // alone whatever it does; we don't have a typed union to
        // recommend widening toward.
        let g = synthetic_graft_with_effect("alpha", 10);
        let (_, report) = inject(BARE_SCAFFOLD, &[g]).unwrap();
        assert_eq!(report.codegen.status, CodegenStatus::Skipped);
        assert!(report.weld_lint.is_empty());
    }
    // ---------------------------------------------------------------
    // migrate_legacy_effect
    // ---------------------------------------------------------------

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
