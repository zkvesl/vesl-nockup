//! graft-inject: auto-wire vesl-flavored grafts into a nockup app.hoon
//! kernel.
//!
//! Discovers graft manifests under `--lib-dir` (default `./hoon/lib/`),
//! composes their blocks at the `::  nockup:{imports,state,cause,poke,peek}`
//! markers, and writes the result back. Idempotent per graft per marker.
//!
//! See `--help` for full CLI surface.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MARKER_PREFIX: &str = "::  nockup:";
const DEFAULT_LIB_DIR: &str = "hoon/lib";

mod manifest;
mod marker;

use crate::manifest::{
    Graft, atomic_write, build_chain_block, discover_grafts, is_valid_graft_name, sha256_hex,
};
use crate::marker::{
    Marker, begin_banner, begin_banner_with_sha, codegen_begin_banner, codegen_end_banner,
    end_banner, find_marker, leading_whitespace, strip_banner_pair,
};

/// Allowlist of catalog gates currently shipped in `vesl-gates.hoon`.
/// Tier 1b additions extend this list as they land.
const TIER_1A_GATES: &[&str] = &[
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
fn validate_gate_selection(g: &Graft, path: &Path) -> Result<()> {
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

fn validate_gate_name(name: &str, path: &Path, field: &str) -> Result<()> {
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
const DEFAULT_HASH_GATE_BLOCK: &str = "\
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
fn apply_gate_selection(g: &mut Graft, path: &Path) -> Result<()> {
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

/// Per-graft injection summary returned by `inject()`. Drives `print_report`
/// and the `--list` machine-readable output.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InjectReport {
    /// Markers found in the source file.
    markers_in_source: Vec<Marker>,
    /// Markers expected but not present in source.
    markers_missing: Vec<Marker>,
    /// Per-graft outcome, in the same order as the input slice.
    grafts: Vec<GraftReport>,
    /// Grafts whose banner pairs were present in source but absent from
    /// the active `--grafts` set on this run. Their orphan blocks were
    /// auto-pruned. Carrier separate from `grafts` because no manifest
    /// is loaded for these names.
    pruned_grafts: Vec<GraftReport>,
    /// Outcome of the typed effect-union codegen pass.
    codegen: CodegenReport,
    /// Weld-friction lint findings in domain code.
    weld_lint: WeldLint,
    /// RM4 §1 v0.2: outcome of the `++load` defaults codegen pass.
    load_defaults: LoadDefaultsReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CodegenStatus {
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
struct CodegenReport {
    status: CodegenStatus,
    /// Variant list spliced into `+$ effect $%(...)`. Empty when status
    /// is Skipped.
    variants: Vec<String>,
}

/// RM4 §1 v0.2: outcome of the load-defaults codegen pass. Mirrors
/// `CodegenReport` but tracks the `++load` overlay block separately so
/// the `print_report` line can call out the schema-migration scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LoadDefaultsReport {
    status: CodegenStatus,
    /// Graft state-field names (e.g. `["settle", "rbac"]`) emitted into
    /// the `%=  old-state ... ==` overlay, in priority order. Empty when
    /// status is Skipped.
    fields: Vec<String>,
}

/// Weld-friction lint.
///
/// R5 dogfood (Profile G HULL_KEYED_KV) confirmed that the typed effect
/// union does NOT auto-fix the cross-graft `weld` friction when the
/// developer's domain arm binds narrowly:
///
///     =/  [efx-c=(list counter-effect) new-counter=counter-state]   :: NARROW
///       (counter-poke counter.state ...)
///     (weld efx-c efx-k)                                            :: nest-fail
///
/// The fix is Pattern B: widen each binding to `(list effect)`. The
/// lint scans developer code (outside `graft-inject:<X>:begin/:end`
/// banner regions) for narrow bindings and surfaces a stderr note
/// pointing at the zkvesl-docs §"Composing two graft arms in one
/// domain cause" so the developer has a searchable handle.
///
/// Findings are advisory — Pattern A (R4 backtick casts at the weld
/// site) still works as an escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WeldLintFinding {
    /// 1-indexed line number of the offending narrow binding.
    line: usize,
    /// Trimmed line text — short enough to copy-paste into a search.
    text: String,
    /// The narrow type referenced, e.g., `counter-effect`.
    narrow_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
struct WeldLint {
    findings: Vec<WeldLintFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GraftReport {
    name: String,
    /// Markers this graft contributes a block for.
    applicable: Vec<Marker>,
    /// Markers this graft injected on this run.
    injected: Vec<Marker>,
    /// Markers where the graft's sentinel was already present (idempotent skip).
    skipped: Vec<Marker>,
    /// Markers stripped as orphans this run — banner pairs were present
    /// in the source but the graft is no longer in the active set.
    pruned: Vec<Marker>,
}

fn inject(source: &str, grafts: &[Graft]) -> Result<(String, InjectReport)> {
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
fn emit_effect_union(
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

    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(union_idx + 1) {
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
            "orphan `{}` (begin without end) under nockup:effect-union",
            begin_str
        );
    }

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
fn render_effect_union_block(indent: &str, variants: &[String]) -> Vec<String> {
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

/// RM4 §1 v0.2: synthesize the load-defaults overlay beneath the
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
fn emit_load_defaults(
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

    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(marker_idx + 1) {
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
            "orphan `{}` (begin without end) under nockup:load-defaults",
            begin_str
        );
    }

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
///     =/  defaults  ^*(versioned-state)
///     %_  defaults
///         settle  =/  s  (mole |.(settle.old-state))  ?~(s ^*(settle-state) u.s)
///         mint    =/  m  (mole |.(mint.old-state))    ?~(m ^*(mint-state) u.m)
///         ...
///     ==
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
fn render_load_defaults_block(indent: &str, grafts: &[Graft], fields: &[String]) -> Vec<String> {
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

/// Codegen banner has no per-graft name (the codegen is global to the
/// kernel, not per-graft). Distinguishes from `begin_banner` which
/// embeds the contributing graft's name.
/// Recognize the legacy `+$  effect  *` open-type line. Tolerates one or
/// more spaces between tokens (Hoon two-space-law authors usually write
/// `+$  effect  *`). Rejects custom forms like `+$ effect (list @t)` so
/// the codegen leaves user-typed effects alone (a stderr warning is the
/// right surface for those, not a silent rewrite).
fn is_bare_effect_open_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.len() == 3 && parts[0] == "+$" && parts[1] == "effect" && parts[2] == "*"
}

/// Scan domain code for narrow `(list <X>-effect)` bindings that will
/// nest-fail at a cross-graft `weld`. Skips lines
/// inside `graft-inject:<...>:begin / :end` banner regions (those are
/// graft-injected bodies, not user code; the narrow types are correct
/// there). Skips entirely when codegen status is Skipped or the variant
/// list is empty — there's no typed union to widen toward.
fn lint_weld_friction(lines: &[String], variants: &[String]) -> WeldLint {
    let effect_variants: HashSet<&str> = variants
        .iter()
        .filter(|v| v.ends_with("-effect") && v.as_str() != "domain-effect")
        .map(String::as_str)
        .collect();

    if effect_variants.is_empty() {
        return WeldLint::default();
    }

    let mut findings = Vec::new();
    let mut in_banner = false;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Banner detection: any `graft-inject:<X>:<Y>:begin/:end` line
        // toggles the in_banner state. Codegen banner pairs
        // (`graft-inject:effect-union:...`) are also skipped — those
        // bodies are synthesized, not user-written.
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            // Begin banners may carry a ` sha256:<hex>` suffix (R5/A2);
            // match on the `:begin` token regardless of suffix. End
            // banners are still suffix-free.
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }

        for variant in &effect_variants {
            let needle = format!("(list {variant})");
            if line.contains(&needle) {
                findings.push(WeldLintFinding {
                    line: i + 1,
                    text: trimmed.to_string(),
                    narrow_type: (*variant).to_string(),
                });
                break; // one finding per line is enough
            }
        }
    }
    WeldLint { findings }
}

/// Pre-apply lint: bare-`~` ambiguity inside domain `?-` switch arms.
///
/// RM1 HARD-BUG-2 (`.dev/debug/log-meta/RM1/B_to_C.md` §HARD-BUG-2)
/// surfaced this: `find_last_bare_tilde` walks from the `nockup:peek`
/// marker until the next `==` capturing the last `~`-only line as
/// the peek-chain terminator. The next `==` is typically the
/// `?-  -.u.act` close in the poke arm, so any bare-`~` line inside a
/// domain arm body (e.g. `%ping :_ state ^- (list effect) ~`)
/// becomes the new "terminator" and graft-inject inserts the peek
/// chain into the poke body — corrupting the file.
///
/// RH2 step 2's canonical re-emit fix landed for the placement bugs
/// it targeted, but `emit_peek_chain` still anchors against
/// `find_last_bare_tilde`. Until that anchor changes, the safest
/// surface is a pre-apply lint that warns when the user's domain
/// arms create the structural ambiguity.
///
/// The lint walks lines inside the `nockup:poke` region but outside
/// any `graft-inject:*:begin/:end` banner (graft-injected arms are
/// graft-inject's own output and aren't user-editable). When a
/// domain arm body's final line is exactly `~`, the line is flagged
/// and the developer is pointed at the workaround:
/// `\`(list effect)\`~` or `^- (list effect) ~` on a single line.
fn lint_bare_tilde_ambiguity(lines: &[String]) -> BareTildeLint {
    let mut findings = Vec::new();
    // Anchor on the `?-  -.u.act` switch header. graft-inject's
    // `find_last_bare_tilde` would scan the same range from the
    // peek marker forward, so any domain arm body inside this
    // switch that ends with bare `~` is the friction shape from
    // RM1 HARD-BUG-2. The `nockup:poke` marker by itself isn't
    // enough — domain arms live BEFORE the marker (between the
    // switch open and the marker), so a forward-only scan from
    // the marker would miss them.
    let Some(switch_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("?-") && t.contains("-.u.act")
    }) else {
        return BareTildeLint::default();
    };

    let mut in_banner = false;
    // Track the most recent domain `%<tag>` arm header so each finding
    // can name its parent arm. Domain arms are leading `%<tag>` lines
    // that are NOT inside a graft-inject banner.
    let mut current_arm: Option<String> = None;
    for (i, line) in lines.iter().enumerate().skip(switch_idx + 1) {
        let trimmed = line.trim();
        if trimmed == "==" {
            break;
        }
        // Banner state machine — copies the lint_weld_friction shape so
        // graft-injected arm bodies are skipped.
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        // Skip the `nockup:poke` placeholder — it's a comment marker,
        // not a domain arm. Comments in general (`::  ...`) reset
        // nothing; they're transparent to the arm-tracking logic.
        if trimmed.starts_with("::") {
            continue;
        }
        // Track the most recent domain arm header. A domain arm header
        // is a line whose first token starts with `%` followed by a
        // tag character. We only need the tag for the finding message,
        // so a quick prefix match is enough — full Hoon parsing isn't
        // required.
        if let Some(rest) = trimmed.strip_prefix('%') {
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '-')
                .unwrap_or(false)
            {
                let tag: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if !tag.is_empty() {
                    current_arm = Some(tag);
                }
            }
        }
        if trimmed == "~" {
            if let Some(arm) = current_arm.take() {
                findings.push(BareTildeLintFinding {
                    line: i + 1,
                    arm,
                });
                // After flagging once per arm, reset so multi-line arm
                // bodies don't repeat-flag (the bug fires on the LAST
                // line; one finding per arm is enough).
            }
        }
    }
    BareTildeLint { findings }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BareTildeLintFinding {
    /// 1-indexed line number of the bare `~`.
    line: usize,
    /// Domain arm tag (e.g. "ping") whose body ends in the bare `~`.
    arm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
struct BareTildeLint {
    findings: Vec<BareTildeLintFinding>,
}

/// Pre-apply lint: cross-graft and graft-vs-domain name collisions.
///
/// RM1 META-COLLISION-1 (`.dev/debug/log-meta/RM1/E_to_F.md`),
/// META-COLLISION-2 (`G_to_H.md`), and META-COLLISION-3 (`H_to_I.md`)
/// surfaced two kinds of collision in cumulative-domain mode:
/// - Cause-tag collisions: two grafts (or a graft and the domain)
///   declare the same `%<tag>` poke arm. The composed `?-` switch
///   has duplicate `%<tag>` arms; hoonc's exhaustiveness check
///   fires `mint-lost` or accepts whichever arm wins lexically.
/// - State-field collisions: two grafts (or a graft and the domain)
///   declare the same field name in the state record. The composed
///   `+$ versioned-state` has duplicate field names; hoonc fires a
///   nest-fail.
///
/// The lint reads each graft's `[graft.blocks.poke]` body (cause
/// tags appear as leading `%<tag>` arm headers) and `[graft.blocks.state]`
/// body (field names appear before `=`). It also parses the domain's
/// `nockup:cause` and `nockup:state` regions in app.hoon. Any name
/// declared by more than one source becomes a finding.
fn lint_collision_check(
    grafts: &[Graft],
    domain_lines: &[String],
) -> CollisionLint {
    use std::collections::BTreeMap;
    let mut cause_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut state_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for g in grafts {
        for tag in extract_graft_cause_tags(g) {
            cause_owners.entry(tag).or_default().push(g.name.clone());
        }
        for field in extract_graft_state_fields(g) {
            state_owners.entry(field).or_default().push(g.name.clone());
        }
    }
    for tag in extract_domain_cause_tags(domain_lines) {
        cause_owners
            .entry(tag)
            .or_default()
            .push("(domain)".to_string());
    }
    for field in extract_domain_state_fields(domain_lines) {
        state_owners
            .entry(field)
            .or_default()
            .push("(domain)".to_string());
    }

    let mut findings = Vec::new();
    for (tag, owners) in cause_owners {
        if owners.len() > 1 {
            findings.push(CollisionFinding {
                kind: CollisionKind::CauseTag,
                name: tag,
                owners,
            });
        }
    }
    for (field, owners) in state_owners {
        if owners.len() > 1 {
            findings.push(CollisionFinding {
                kind: CollisionKind::StateField,
                name: field,
                owners,
            });
        }
    }
    CollisionLint { findings }
}

/// Extract `%<tag>` arm headers from a graft's poke block body.
/// graft poke bodies follow a uniform shape: each arm starts with
/// `%<tag>` on its own line (modulo leading whitespace), preceded by
/// `::` separators between arms. Walk the lines and collect the tags.
fn extract_graft_cause_tags(g: &Graft) -> Vec<String> {
    let mut tags = Vec::new();
    for marker in [Marker::Poke, Marker::PokePrelude, Marker::PokePostlude] {
        let Some(body) = g.block(marker) else {
            continue;
        };
        for line in body.body.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix('%') {
                let tag: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if !tag.is_empty() {
                    // Skip embedded `%foo` references inside expressions
                    // (e.g., `[%queue-push ...]` inside a `=/`). Real arm
                    // headers are bare on a line; embedded references are
                    // inside `[]` or `()` or have leading punctuation.
                    if !line.contains('[') && !line.contains('(') {
                        tags.push(tag);
                    }
                }
            }
        }
    }
    tags
}

/// Extract field names from a graft's state block body. The shape is
/// `<field>=<type>` (most grafts) or a `$:` record with multiple
/// `<field>=<type>` lines. Tokens before `=` (modulo leading
/// whitespace) are field names.
fn extract_graft_state_fields(g: &Graft) -> Vec<String> {
    let Some(body) = g.block(Marker::State) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    for line in body.body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("::")
            || trimmed.starts_with("$:")
            || trimmed == "=="
        {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                fields.push(name);
            }
        }
    }
    fields
}

/// Walk `domain_lines` (the entire app.hoon source as line vec) and
/// extract domain cause tags — `[%<tag> ...]` lines that sit between
/// the `+$ cause $%(...)` opening and the `::  nockup:cause` marker
/// (or the closing `==` if no marker is present).
fn extract_domain_cause_tags(lines: &[String]) -> Vec<String> {
    let mut tags = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && t.contains("cause")
    }) else {
        return tags;
    };
    let mut started = false;
    let mut in_banner = false;
    for line in &lines[open_idx..] {
        let trimmed = line.trim();
        if !started {
            if let Some(after) = trimmed.find("$%") {
                started = true;
                // `$%` may be followed by a variant on the same line
                // (e.g. `$%  [%cause ~]`). Probe for `[%<tag>` after
                // the `$%` token before continuing.
                let rest = &trimmed[after + 2..];
                push_bracket_tag(rest, &mut tags);
            }
            continue;
        }
        if trimmed.starts_with("::  nockup:cause") || trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        push_bracket_tag(trimmed, &mut tags);
    }
    tags
}

/// Extract a `[%<tag> ...]` leading tag from a string and append to
/// `tags`. No-op when the input doesn't start with `[%`.
fn push_bracket_tag(s: &str, tags: &mut Vec<String>) {
    let trimmed = s.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[%") {
        let tag: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !tag.is_empty() {
            tags.push(tag);
        }
    }
}

/// Walk `lines` and extract domain state field names — `<name>=<type>`
/// lines between `+$ versioned-state $:(...)` (or similar) and the
/// `::  nockup:state` marker.
fn extract_domain_state_fields(lines: &[String]) -> Vec<String> {
    let mut fields = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && (t.contains("state") || t.contains("versioned-state"))
    }) else {
        return fields;
    };
    let mut started = false;
    let mut in_banner = false;
    for line in &lines[open_idx..] {
        let trimmed = line.trim();
        if !started {
            if trimmed.contains("$:") {
                started = true;
            }
            continue;
        }
        if trimmed.starts_with("::  nockup:state") || trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") && trimmed.contains("graft-inject:") {
            if trimmed.contains(":begin ") || trimmed.ends_with(":begin") {
                in_banner = true;
                continue;
            }
            if trimmed.ends_with(":end") {
                in_banner = false;
                continue;
            }
        }
        if in_banner {
            continue;
        }
        if trimmed.starts_with("::") || trimmed.is_empty() {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                fields.push(name);
            }
        }
    }
    fields
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CollisionKind {
    CauseTag,
    StateField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CollisionFinding {
    kind: CollisionKind,
    /// The colliding name (`enqueue-job`, `entries`, ...).
    name: String,
    /// Owners that declared the name. `(domain)` represents the
    /// app.hoon domain code; everything else is a graft name.
    owners: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
struct CollisionLint {
    findings: Vec<CollisionFinding>,
}

/// Pre-apply lint: walk every `.hoon` file reachable from the input
/// path via `/+`, `/=`, `/-`, `/#` imports, AND eagerly scan every
/// `.hoon` under `<hoon-root>/common/`. Report unsatisfied edges as
/// HARD-LINT findings.
///
/// Reproduces the empirical seed-A friction (`hoon/common/nock-prover.hoon
/// → /# softed-constraints` after slim-cp): even though Profile A's
/// app.hoon doesn't reach nock-prover transitively, hoonc parses
/// hoon/common/ eagerly and silent-fails on the missing `/dat/` target.
/// This lint surfaces the same edge before hoonc runs so the developer
/// sees a clear "missing file at PATH" rather than hoonc's "no panic!"
/// lie. See `vesl-nockup/.dev/debug/log-meta/RM2/seed-A.md` §DOC-GAP-1.
///
/// Resolution rules:
/// - `/+ <name>`         → `<lib-dir>/<name>.hoon`
/// - `/+ *<name>`        → `<lib-dir>/<name>.hoon` (public-import form)
/// - `/= <bind> /<path>` → `<hoon-root>/<path>.hoon`
/// - `/-  <name>`        → `<hoon-root>/sur/<name>.hoon`
/// - `/# <name>`         → `<hoon-root>/dat/<name>.hoon`
fn lint_transitive_imports(root_path: &Path, lib_dir: &Path) -> TransitiveImportLint {
    use std::collections::VecDeque;

    let hoon_root = lib_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let common_dir = hoon_root.join("common");

    // Canonicalize for dedup. If canonicalize fails (e.g. the file
    // doesn't exist), fall back to the raw path — the resolver below
    // is the place that flags absence, not the dedup step.
    let canon = |p: &Path| -> PathBuf {
        p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
    };

    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, Vec<PathBuf>)> = VecDeque::new();
    queue.push_back((canon(root_path), Vec::new()));

    // Eagerly seed every .hoon under hoon/common/. Manual recursion via
    // fs::read_dir keeps us off walkdir.
    if common_dir.is_dir() {
        let mut stack = vec![common_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("hoon") {
                    queue.push_back((canon(&p), Vec::new()));
                }
            }
        }
    }

    let mut findings: Vec<TransitiveImportFinding> = Vec::new();
    while let Some((current, parents)) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let content = match fs::read_to_string(&current) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lines: Vec<String> = content.lines().map(String::from).collect();
        for spec in parse_imports(&lines) {
            let target = resolve_import(&spec, &hoon_root, lib_dir);
            if target.exists() {
                let mut next_parents = parents.clone();
                next_parents.push(current.clone());
                queue.push_back((canon(&target), next_parents));
            } else {
                let mut chain = parents.clone();
                chain.push(current.clone());
                findings.push(TransitiveImportFinding {
                    source: current.clone(),
                    rune: spec.rune.to_string(),
                    name: spec.name.clone(),
                    target,
                    reachable_from: chain,
                });
            }
        }
    }

    TransitiveImportLint { findings }
}

/// One import edge extracted from a .hoon prologue.
#[derive(Debug, Clone)]
struct ImportSpec {
    rune: &'static str,
    name: String,
    /// `/=` only: the path argument (e.g. `/common/wrapper`). Empty
    /// for the other runes.
    path_arg: String,
}

/// Parse the leading import block of a .hoon file. Stops at the first
/// non-rune non-comment non-empty line — Hoon prologues conventionally
/// run all imports before the first runic body.
fn parse_imports(lines: &[String]) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("::") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/+") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/+",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/=") {
            // `/= <bind> /<path>`. Extract the leading slash-path; bind
            // name is the first whitespace-separated token.
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if let Some(p) = fields.iter().find(|f| f.starts_with('/')) {
                out.push(ImportSpec {
                    rune: "/=",
                    name: fields.first().map(|s| s.to_string()).unwrap_or_default(),
                    path_arg: p.to_string(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/-") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/-",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/#") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/#",
                    name,
                    path_arg: String::new(),
                });
            }
        } else {
            break;
        }
    }
    out
}

/// Split a `/+` or `/-` argument into individual import names.
/// Tolerates leading `*` (public import) and comma-separated lists.
fn split_import_names(rest: &str) -> Vec<String> {
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_start_matches('*').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Resolve an import spec to a candidate file path under hoon-root.
fn resolve_import(spec: &ImportSpec, hoon_root: &Path, lib_dir: &Path) -> PathBuf {
    match spec.rune {
        "/+" => lib_dir.join(format!("{}.hoon", spec.name)),
        "/=" => {
            let p = spec.path_arg.trim_start_matches('/');
            hoon_root.join(format!("{}.hoon", p))
        }
        "/-" => hoon_root.join("sur").join(format!("{}.hoon", spec.name)),
        "/#" => hoon_root.join("dat").join(format!("{}.hoon", spec.name)),
        _ => PathBuf::new(),
    }
}

#[derive(Debug, Clone, Serialize)]
struct TransitiveImportFinding {
    /// .hoon file that owns the unsatisfied import.
    source: PathBuf,
    /// Rune ("/+", "/=", "/-", "/#").
    rune: String,
    /// Import name (or `/=` bind name).
    name: String,
    /// Expected resolution path that doesn't exist on disk.
    target: PathBuf,
    /// Chain of files traversed to reach `source`. Empty when
    /// `source` is a top-level seed (the input root or a
    /// hoon/common/ entry).
    reachable_from: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct TransitiveImportLint {
    findings: Vec<TransitiveImportFinding>,
}

/// Pre-apply lint: literal duplicate variant heads inside the
/// `+$ cause $%(...)` union, OR literal duplicate field names inside
/// the `+$ versioned-state $:(...)` record.
///
/// Distinguishes from `lint_collision_check` (which scans manifests
/// cross-referenced against domain): this pass scans the
/// already-composed app.hoon's literal unions for self-collisions.
/// Catches the case where the developer hand-writes two domain causes
/// with the same head, AND the case where two grafts each contribute
/// the same head after injection (collision_check would miss the
/// latter when the manifests declared distinct cause names but the
/// underlying `[%<tag> ...]` ended up identical).
///
/// Reports literal-match duplicates only. Near-miss disambiguation
/// (`%enqueue-job-f` vs `%enqueue-job-i`) is intentionally not
/// flagged — adds parser complexity without matching empirical demand.
fn lint_internal_dupes(lines: &[String]) -> InternalDupeLint {
    use std::collections::BTreeMap;

    let mut findings = Vec::new();

    let mut cause_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (tag, line) in extract_all_cause_variants(lines) {
        cause_lines.entry(tag).or_default().push(line);
    }
    for (tag, line_nums) in cause_lines {
        if line_nums.len() > 1 {
            findings.push(InternalDupeFinding {
                kind: InternalDupeKind::CauseTag,
                name: tag,
                lines: line_nums,
            });
        }
    }

    let mut state_lines: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (name, line) in extract_all_state_fields(lines) {
        state_lines.entry(name).or_default().push(line);
    }
    for (name, line_nums) in state_lines {
        if line_nums.len() > 1 {
            findings.push(InternalDupeFinding {
                kind: InternalDupeKind::StateField,
                name,
                lines: line_nums,
            });
        }
    }

    InternalDupeLint { findings }
}

/// Walk from `+$ cause $%(...)` open to its closing `==`, emitting
/// `(tag, 1-indexed line)` for every `[%<tag> ...]` variant. Banner
/// content IS included — internal-collision lint cares about literal
/// duplicates regardless of whether they came from domain or graft
/// injection.
fn extract_all_cause_variants(lines: &[String]) -> Vec<(String, usize)> {
    extract_cause_union_members(lines)
        .into_iter()
        .filter_map(|m| match m {
            CauseUnionMember::Literal { tag, line } => Some((tag, line)),
            CauseUnionMember::Reference { .. } => None,
        })
        .collect()
}

/// Member of a literal `+$ cause` definition. Distinguishes inline
/// `[%<tag> ...]` variants from sub-union type references like
/// `settle-cause` or `intent-cause` — the codegen pass needs both
/// (literals → tag direct; references → look up the named graft's
/// manifest), the lint pass cares only about literals.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CauseUnionMember {
    /// `[%<tag> ...]` form — an inline variant whose head is `tag`.
    Literal { tag: String, line: usize },
    /// Sub-union reference — a bare type name like `settle-cause`,
    /// `intent-cause` etc. that resolves to another `+$` definition
    /// (typically the one a graft contributes via its imports).
    Reference { name: String, line: usize },
}

/// Parse the `+$ cause` definition in `lines`. Three shapes accepted:
///   1. `+$ cause $%(...)` — explicit union; emit one member per
///      variant.
///   2. `+$ cause <type-name>` — single-line alias; emit one
///      Reference for the alias target.
///   3. `+$ cause` then `$%(...)` on a later line — same as shape 1
///      but split across lines.
fn extract_cause_union_members(lines: &[String]) -> Vec<CauseUnionMember> {
    let mut out = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && t.contains("cause")
    }) else {
        return out;
    };

    // Detect shape 2 (`+$ cause <type-name>` alias) by inspecting the
    // tokens after `cause` on the open line.
    let cause_line = lines[open_idx].trim();
    let after_cause: Vec<&str> = cause_line
        .split_whitespace()
        .skip_while(|t| *t != "cause")
        .skip(1)
        .collect();
    if let Some(first) = after_cause.first() {
        if !first.starts_with("$%") && !first.starts_with("[%") && !first.is_empty() {
            let name: String = first
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                out.push(CauseUnionMember::Reference {
                    name,
                    line: open_idx + 1,
                });
                return out;
            }
        }
    }

    // Shape 1 / 3: scan for `$%`, then collect members until `==`.
    let mut started = false;
    for (i, line) in lines.iter().enumerate().skip(open_idx) {
        let trimmed = line.trim();
        if !started {
            if let Some(after) = trimmed.find("$%") {
                started = true;
                let rest = &trimmed[after + 2..];
                push_cause_member(rest, i + 1, &mut out);
            }
            continue;
        }
        if trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") {
            continue;
        }
        push_cause_member(trimmed, i + 1, &mut out);
    }
    out
}

/// Append a `CauseUnionMember` parsed from `s`. `[%<tag>` becomes a
/// Literal; bare identifiers become a Reference. Empty strings are
/// no-ops.
fn push_cause_member(s: &str, line: usize, out: &mut Vec<CauseUnionMember>) {
    let t = s.trim();
    if t.is_empty() {
        return;
    }
    if let Some(tag) = bracket_tag(t) {
        out.push(CauseUnionMember::Literal { tag, line });
        return;
    }
    let name: String = t
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if !name.is_empty() {
        out.push(CauseUnionMember::Reference { name, line });
    }
}

/// Walk from `+$ versioned-state $:(...)` open to close, emit
/// `(field, 1-indexed line)` for every `<name>=<type>` line.
fn extract_all_state_fields(lines: &[String]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let Some(open_idx) = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("+$") && (t.contains("state") || t.contains("versioned-state"))
    }) else {
        return out;
    };
    let mut started = false;
    for (i, line) in lines.iter().enumerate().skip(open_idx) {
        let trimmed = line.trim();
        if !started {
            if trimmed.contains("$:") {
                started = true;
            }
            continue;
        }
        if trimmed == "==" {
            break;
        }
        if trimmed.starts_with("::") || trimmed.is_empty() {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name: String = trimmed[..eq]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                out.push((name, i + 1));
            }
        }
    }
    out
}

/// Read `[%<tag>` prefix and return the tag. None when the input
/// doesn't start with `[%` or the tag is empty. Sibling of
/// `push_bracket_tag` — that one mutates an output Vec, this one
/// returns by value.
fn bracket_tag(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let rest = trimmed.strip_prefix("[%")?;
    let tag: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if tag.is_empty() { None } else { Some(tag) }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InternalDupeKind {
    CauseTag,
    StateField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InternalDupeFinding {
    kind: InternalDupeKind,
    /// Duplicate name (`enqueue-job`, `entries`, ...).
    name: String,
    /// 1-indexed line numbers of every occurrence (sorted).
    lines: Vec<usize>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct InternalDupeLint {
    findings: Vec<InternalDupeFinding>,
}

/// Outcome of `migrate_legacy_effect`. Surfaced to stderr so reviewers
/// can see whether the auto-migration touched the file before codegen
/// runs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationReport {
    /// Did we rewrite a bare `+$  effect  *` into the marker shape?
    migrated: bool,
    /// Did we spot a custom `+$ effect <type>` that we left alone?
    /// Stderr-warned so the developer knows their custom shape will
    /// collide with codegen if the marker is added later.
    skipped_custom: bool,
}

impl MigrationReport {
    fn skipped() -> Self {
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
fn migrate_legacy_effect(source: &str) -> (String, MigrationReport) {
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
fn print_migration_line(report: &MigrationReport) {
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
fn binding_stub(name: &str) -> &str {
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

/// Strip a `::  graft-inject:<name>:<marker>:begin … :end` banner pair
/// (and everything between) from `lines`. Used by the drift-detection
/// path before re-injecting fresh content, and by the orphan-prune
/// pre-pass for grafts dropped from `--grafts`. Returns the line index
/// of the begin banner before stripping (so callers in the drift path
/// can re-insert at the same position), or `None` if no pair matched.
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

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// 3D VESL logomark — shown via clap `after_help` to keep the vesl identity visible behind the `nockup graft` proxy.
const ASCII_LOGO: &str = r#"
██╗   ██╗███████╗███████╗██╗
██║   ██║██╔════╝██╔════╝██║
██║   ██║█████╗  ███████╗██║
╚██╗ ██╔╝██╔══╝  ╚════██║██║
 ╚████╔╝ ███████╗███████║███████╗
  ╚═══╝  ╚══════╝╚══════╝╚══════╝
"#;

#[derive(Parser, Debug)]
#[command(
    name = "graft-inject",
    version,
    about = "Compose vesl-flavored grafts into a nockup app.hoon kernel",
    long_about = "Compose vesl-flavored grafts into a nockup app.hoon kernel.\n\
                  \n\
                  Subcommands:\n  \
                    inject     compose grafts into app.hoon (preview-by-default; --apply to write)\n  \
                    list       list discovered grafts under --lib-dir\n  \
                  \n\
                  Without a subcommand, falls back to the legacy bare invocation\n\
                  (`graft-inject <PATH> --grafts ...`). That form is deprecated; prefer\n\
                  `graft-inject inject <PATH>` so the operation is explicit. Run\n\
                  `graft-inject <subcommand> --help` for subcommand-specific options.",
    after_help = ASCII_LOGO,
)]
struct Cli {
    /// Top-level subcommand. When omitted, the legacy bare-invocation
    /// flags (`<PATH>`, `--grafts`, `--apply`, `--list`, …) are honored
    /// for back-compat — a one-line deprecation note prints to stderr.
    #[command(subcommand)]
    command: Option<Command>,

    /// Target file (omit when using --list).
    path: Option<PathBuf>,

    /// Comma-separated graft names, in injection order. When omitted,
    /// auto-discovers all *.toml manifests under --lib-dir.
    #[arg(long, value_delimiter = ',')]
    grafts: Vec<String>,

    /// Comma-separated graft names to subtract from the discovered set.
    /// Ignored when --grafts is given (use --grafts instead).
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Manifest discovery root.
    #[arg(long, default_value = DEFAULT_LIB_DIR)]
    lib_dir: PathBuf,

    /// Print discovered grafts and exit. Pair with --json for machine-readable.
    #[arg(long)]
    list: bool,

    /// JSON output mode (currently only meaningful with --list).
    #[arg(long)]
    json: bool,

    /// Deprecated alias of the default preview-only behavior. Kept for
    /// script compatibility through the AUDIT 2026-04-19 H-10 transition.
    /// Prints a one-line deprecation note to stderr and otherwise does
    /// nothing beyond the default.
    #[arg(long)]
    dry_run: bool,

    /// Write the composed output to PATH. AUDIT 2026-04-19 H-10: the
    /// default is preview-only — stdout gets the composed Hoon, stderr
    /// gets the per-manifest sha256 summary, disk is untouched. This
    /// flag is the explicit "yes, compose these manifests into kernel
    /// source" acknowledgement.
    #[arg(long)]
    apply: bool,

    /// Skip the auto-migration of legacy `+$  effect  *` to the
    /// marker-shape (`nockup:domain-effect` + `nockup:effect-union` +
    /// bare `+$ effect *`). Default behavior is to migrate
    /// transparently; `--no-migrate` is the opt-out for paranoid review.
    /// The codegen pass still skips kernels without the
    /// `nockup:effect-union` marker.
    #[arg(long = "no-migrate")]
    no_migrate: bool,
}

/// Subcommands. Each variant carries its own argument set so
/// `graft-inject <subcmd> --help` shows only the relevant flags. Bare
/// `graft-inject <PATH> [flags]` keeps working through the
/// `Cli::command == None` branch in `main`.
#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Compose grafts into app.hoon (preview-by-default; --apply to write).
    Inject {
        /// Target Hoon source file.
        path: PathBuf,

        /// Comma-separated graft names, in injection order. When omitted,
        /// auto-discovers all *.toml manifests under --lib-dir.
        #[arg(long, value_delimiter = ',')]
        grafts: Vec<String>,

        /// Comma-separated graft names to subtract from the discovered set.
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,

        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Write the composed output to PATH (default is preview-only).
        #[arg(long)]
        apply: bool,

        /// Skip the auto-migration of legacy `+$ effect *` to the marker
        /// shape. Default migrates transparently.
        #[arg(long = "no-migrate")]
        no_migrate: bool,
    },

    /// List discovered grafts under --lib-dir.
    List {
        /// Manifest discovery root.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Comma-separated graft names to subtract from the discovered set.
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,

        /// JSON output mode (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Run pre-apply structural validations on app.hoon. Exits 1 on
    /// any HARD finding so CI can gate `--apply` on the lint passing.
    Lint {
        /// Target Hoon source file.
        path: PathBuf,

        /// Manifest discovery root for collision-check across grafts.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// JSON output mode (machine-readable).
        #[arg(long)]
        json: bool,
    },

    /// Emit Rust source from app.hoon — codegen target depends on the
    /// sub-subcommand. Currently ships `kernel-cause-tags`; future
    /// targets append here.
    Codegen {
        #[command(subcommand)]
        target: CodegenTarget,
    },

    /// Rename the project kernel from `hoon/app/<from>.hoon` to
    /// `hoon/app/<new-name>.hoon`. Updates `[project].kernel_name` in
    /// `nockapp.toml` and rewrites bash code blocks in `./README.md`
    /// if present. Preview-by-default; `--apply` writes.
    RenameKernel {
        /// New kernel base name (without `.hoon` suffix). Validated
        /// against `^[a-z][a-z0-9-]*$` (Hoon module name shape).
        new_name: String,

        /// Existing kernel base name to rename FROM. Defaults to the
        /// `[project].kernel_name` value in `./nockapp.toml` if set,
        /// else `"app"` — so re-renames don't require typing the
        /// previous name.
        #[arg(long)]
        from: Option<String>,

        /// Write the planned operations to disk. Default is
        /// preview-only (matches the `inject` subcommand convention).
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum CodegenTarget {
    /// Emit `pub const KERNEL_CAUSE_TAGS: &[&str]` from app.hoon's
    /// composed cause $%. Pairs with the `assert_kernel_cause_tag!`
    /// macro the same file emits, so driver-side
    /// `b"<tag>"` literals are checked at compile time against the
    /// kernel's accepted tags. Closes RM1 HARD-BUG-3 (kernel rename
    /// invisible to driver) and HARD-FRICTION-4 (driver tag with no
    /// kernel arm).
    KernelCauseTags {
        /// Target Hoon source file (app.hoon with the grafts already
        /// composed, or the canonical scaffold for codegen-only flows).
        path: PathBuf,

        /// Manifest discovery root. Cause tags are collected from
        /// every graft's `[graft.blocks.poke]` body in addition to
        /// the domain `nockup:cause` region.
        #[arg(long, default_value = DEFAULT_LIB_DIR)]
        lib_dir: PathBuf,

        /// Output Rust file path. Without `--out` the emitted source
        /// goes to stdout — useful for `cargo run -- codegen ... |
        /// rustfmt`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// JSON output mode — emit a `{"kernel_cause_tags": [...]}`
        /// document to stdout instead of Rust source. Useful for
        /// non-Rust consumers and CI smoke checks.
        #[arg(long)]
        json: bool,
    },
}

/// Schema item for `--list --json`. Stable across the v3 plan's lifespan;
/// version bumps append fields, never reshape existing ones. Documented
/// in vesl/docs/graft-manifest.md (`--list --json schema`).
#[derive(Debug, Serialize)]
struct GraftSummary<'a> {
    name: &'a str,
    version: &'a str,
    priority: i32,
    blocks: Vec<&'static str>,
    applicable: usize,
    deferred: bool,
    /// Hex sha256 of the manifest's raw TOML bytes. AUDIT 2026-04-19
    /// H-10: lets supply-chain reviewers pin expected digests without
    /// re-reading the file.
    sha256: &'a str,
    /// Per-graft `[graft.types]` table contents, surfaced for tooling
    /// that wants to know which grafts contribute to the typed effect
    /// union. `null` when the manifest omits the table.
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<GraftTypesSummary<'a>>,
}

#[derive(Debug, Serialize)]
struct GraftTypesSummary<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    effect: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'a str>,
}

impl<'a> GraftSummary<'a> {
    fn from_graft(g: &'a Graft) -> Self {
        let blocks: Vec<&'static str> = Marker::ALL
            .iter()
            .filter(|m| g.block(**m).is_some())
            .map(|m| m.label())
            .collect();
        let applicable = blocks.len();
        let types = g.types.as_ref().map(|t| GraftTypesSummary {
            effect: t.effect.as_deref(),
            cause: t.cause.as_deref(),
        });
        Self {
            name: &g.name,
            version: &g.version,
            priority: g.priority,
            blocks,
            applicable,
            deferred: false,
            sha256: &g.sha256,
            types,
        }
    }
}

pub fn run() -> ExitCode {
    warn_if_stale();
    let cli = Cli::parse();
    let result = dispatch(cli);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Subcommand dispatch. Either runs an explicit subcommand (modern
/// surface) or falls through to the legacy bare-invocation flow
/// (`graft-inject <PATH> --apply --grafts ...`) — emitting a
/// deprecation note when the legacy path is taken so scripts know to
/// migrate.
///
/// Each subcommand variant is reified into the legacy `Cli` shape and
/// handed to `run()`. The shared dispatch keeps subcommand-specific
/// flags isolated in `Command::*` while reusing the inject pipeline
/// and the `select_grafts` / `emit_list` plumbing unchanged.
fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Inject {
            path,
            grafts,
            exclude,
            lib_dir,
            apply,
            no_migrate,
        }) => run_inject(Cli {
            command: None,
            path: Some(path),
            grafts,
            exclude,
            lib_dir,
            list: false,
            json: false,
            dry_run: false,
            apply,
            no_migrate,
        }),
        Some(Command::List {
            lib_dir,
            exclude,
            json,
        }) => run_inject(Cli {
            command: None,
            path: None,
            grafts: Vec::new(),
            exclude,
            lib_dir,
            list: true,
            json,
            dry_run: false,
            apply: false,
            no_migrate: false,
        }),
        Some(Command::Lint {
            path,
            lib_dir,
            json,
        }) => run_lint(&path, &lib_dir, json),
        Some(Command::Codegen { target }) => match target {
            CodegenTarget::KernelCauseTags {
                path,
                lib_dir,
                out,
                json,
            } => run_codegen_kernel_cause_tags(&path, &lib_dir, out.as_deref(), json),
        },
        Some(Command::RenameKernel {
            new_name,
            from,
            apply,
        }) => run_rename_kernel(&new_name, from.as_deref(), apply),
        None => {
            // Legacy bare-invocation back-compat. The user typed
            // `graft-inject <PATH> ...` or `graft-inject --list ...`
            // without naming a subcommand; emit a deprecation hint
            // unless this is a help-style invocation with nothing to do.
            if cli.list {
                eprintln!(
                    "graft-inject: --list is deprecated; use \
                     `graft-inject list` instead."
                );
            } else if cli.path.is_some() {
                eprintln!(
                    "graft-inject: bare-invocation is deprecated; use \
                     `graft-inject inject <PATH>` instead."
                );
            }
            run_inject(cli)
        }
    }
}

/// Validate a kernel base name against the Hoon module name shape:
/// lowercase letter start, then lowercase letters, digits, or hyphens.
/// Hand-rolled regex `^[a-z][a-z0-9-]*$` to avoid pulling in the
/// `regex` crate for one check.
fn validate_kernel_name(s: &str) -> Result<()> {
    let mut chars = s.chars();
    let first = chars
        .next()
        .ok_or_else(|| anyhow!("kernel name must not be empty"))?;
    if !first.is_ascii_lowercase() {
        bail!("kernel name `{s}` must start with a lowercase letter (a-z)");
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            bail!(
                "kernel name `{s}` may only contain lowercase letters, digits, \
                 and hyphens"
            );
        }
    }
    Ok(())
}

/// Locate the project root by walking up from `start` until a directory
/// containing `nockapp.toml` is found. Mirrors `has_nockapp_toml_ancestor`
/// but returns the path so callers can read/write files relative to it.
fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("nockapp.toml").is_file() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// Read `[project].kernel_name` from a project's `nockapp.toml`. Returns
/// `None` for any failure path (missing file, malformed toml, missing
/// field) so callers can fall back to defaults silently.
fn read_kernel_name_from_toml(toml_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(toml_path).ok()?;
    let value: toml::Value = toml::from_str(&raw).ok()?;
    value
        .get("project")?
        .get("kernel_name")?
        .as_str()
        .map(str::to_string)
}

/// Rewrite `[project].kernel_name = "<new>"` in `nockapp.toml`,
/// preserving comments and key ordering via `toml_edit`. Creates the
/// `[project]` table if missing.
fn rewrite_nockapp_toml(path: &Path, new_name: &str) -> Result<()> {
    use toml_edit::{value, DocumentMut, Item, Table};
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut doc: DocumentMut = raw
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    if !doc.contains_key("project") {
        doc["project"] = Item::Table(Table::new());
    }
    doc["project"]["kernel_name"] = value(new_name);
    fs::write(path, doc.to_string())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Substitute `hoon/app/<from>.hoon` → `hoon/app/<new>.hoon` inside
/// fenced ```bash code blocks in a README. Returns the substitution
/// count. No-op (returns Ok(0)) when the file is absent.
fn rewrite_readme_codeblocks(path: &Path, from: &str, new: &str) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let needle = format!("hoon/app/{from}.hoon");
    let replacement = format!("hoon/app/{new}.hoon");
    let mut out = String::with_capacity(raw.len());
    let mut in_bash = false;
    let mut count = 0usize;
    for line in raw.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if !in_bash && trimmed.starts_with("```bash") {
            in_bash = true;
            out.push_str(line);
        } else if in_bash && trimmed.starts_with("```") {
            in_bash = false;
            out.push_str(line);
        } else if in_bash {
            let occurrences = line.matches(&needle).count();
            if occurrences > 0 {
                count += occurrences;
                out.push_str(&line.replace(&needle, &replacement));
            } else {
                out.push_str(line);
            }
        } else {
            out.push_str(line);
        }
    }
    fs::write(path, out)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(count)
}

/// `nockup graft rename-kernel <new>` entry point. Renames the project
/// kernel file, updates `[project].kernel_name` in `nockapp.toml`, and
/// rewrites bash code blocks in `./README.md` if present.
///
/// `from` is the previous kernel base name. When `None`, defaults to
/// the value of `[project].kernel_name` in `nockapp.toml` if set, else
/// `"app"`. Preview-by-default — only `apply == true` writes to disk.
fn run_rename_kernel(new: &str, from: Option<&str>, apply: bool) -> Result<()> {
    validate_kernel_name(new)?;

    let cwd = std::env::current_dir().context("get current directory")?;
    let project_root = find_project_root(&cwd).ok_or_else(|| {
        anyhow!(
            "no nockapp.toml found in `{}` or its ancestors; run \
             `nockup graft rename-kernel` from inside a vesl project",
            cwd.display()
        )
    })?;

    let toml_path = project_root.join("nockapp.toml");

    let from_owned = from.map(str::to_string).unwrap_or_else(|| {
        read_kernel_name_from_toml(&toml_path).unwrap_or_else(|| "app".to_string())
    });

    let app_dir = project_root.join("hoon/app");
    let old_path = app_dir.join(format!("{from_owned}.hoon"));
    let new_path = app_dir.join(format!("{new}.hoon"));

    if !old_path.exists() {
        bail!(
            "source kernel `{}` not found (use --from to override)",
            old_path.display()
        );
    }
    if new_path.exists() {
        bail!(
            "target `{}` already exists; refusing to clobber",
            new_path.display()
        );
    }

    let readme_path = project_root.join("README.md");

    eprintln!("nockup graft rename-kernel: planned operations");
    eprintln!("  rename {} → {}", old_path.display(), new_path.display());
    eprintln!(
        "  set    [project].kernel_name = \"{new}\" in {}",
        toml_path.display()
    );
    if readme_path.exists() {
        eprintln!(
            "  edit   {} (substitute hoon/app/{from_owned}.hoon → hoon/app/{new}.hoon in bash blocks)",
            readme_path.display()
        );
    } else {
        eprintln!("  edit   README.md skipped (file absent)");
    }

    if !apply {
        eprintln!("  (preview only — pass --apply to write)");
        return Ok(());
    }

    fs::rename(&old_path, &new_path).with_context(|| {
        format!("rename {} → {}", old_path.display(), new_path.display())
    })?;
    rewrite_nockapp_toml(&toml_path, new)?;
    let readme_edits = rewrite_readme_codeblocks(&readme_path, &from_owned, new)?;
    eprintln!(
        "nockup graft rename-kernel: applied (README substitutions: {readme_edits})"
    );
    Ok(())
}

/// `graft-inject lint <PATH>` entry point. Read-only — never writes.
/// Returns Ok(()) when the file is clean and Err with a single bail
/// when any HARD finding fires (so the process exits 1 and CI gates
/// on it). The findings themselves are emitted to stderr in the
/// human-readable form, or to stdout as JSON when `--json` is set.
fn run_lint(path: &Path, lib_dir: &Path, json: bool) -> Result<()> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; lint only runs on Hoon source files",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; lint only runs on Hoon source files",
            path.display(),
        ),
    }
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<String> = source.lines().map(String::from).collect();
    let bare_tilde = lint_bare_tilde_ambiguity(&lines);

    // Collision check needs the discovered graft set so it can
    // cross-reference cause tags and state fields. When --lib-dir
    // doesn't exist we skip collision check rather than hard-error;
    // bare-tilde lint stays useful on its own (e.g. on a kernel
    // outside its project tree).
    let collision = if lib_dir.is_dir() {
        let grafts = discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?;
        lint_collision_check(&grafts, &lines)
    } else {
        CollisionLint::default()
    };

    // Transitive import walk (RM2 §1.1). Runs unconditionally — the
    // seed-A friction fires when hoonc eager-parses hoon/common/, and
    // the lint needs to mirror that scope to be useful.
    let transitive_imports = lint_transitive_imports(path, lib_dir);

    // Internal-dupe lint (RM2 §1.2): literal duplicate cause-tag heads
    // or state-field names inside the composed unions. Catches both
    // hand-written domain dupes and post-injection graft dupes that
    // collision_check (manifest-side) misses.
    let internal_dupes = lint_internal_dupes(&lines);

    let findings_total = bare_tilde.findings.len()
        + collision.findings.len()
        + transitive_imports.findings.len()
        + internal_dupes.findings.len();

    if json {
        // Stable schema: { "bare_tilde_ambiguity": [...], "collision": [...],
        // "transitive_imports": [...] }. Future lint families append
        // top-level keys without reshaping existing ones (mirrors the
        // --list --json schema policy at the GraftSummary block above).
        let report = LintReport {
            bare_tilde_ambiguity: &bare_tilde.findings,
            collision: &collision.findings,
            transitive_imports: &transitive_imports.findings,
            internal_dupes: &internal_dupes.findings,
        };
        let s = serde_json::to_string_pretty(&report)
            .expect("LintReport always serializes");
        println!("{s}");
    } else {
        eprintln!("graft-inject lint: {findings_total} finding(s)");
        if !bare_tilde.findings.is_empty() {
            eprintln!("  bare-tilde-ambiguity:");
            for f in &bare_tilde.findings {
                eprintln!(
                    "    {}:{} — domain arm `%{}` body ends with bare `~` line",
                    path.display(),
                    f.line,
                    f.arm,
                );
            }
            eprintln!(
                "    graft-inject's chain-rebuilder may mistake this for the peek-chain"
            );
            eprintln!("    terminator (RM1 HARD-BUG-2). Refactor to one of:");
            eprintln!("      `(list effect)`~");
            eprintln!("      ^- (list effect) ~");
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM1/B_to_C.md §HARD-BUG-2"
            );
        }
        if !collision.findings.is_empty() {
            eprintln!("  collision:");
            for f in &collision.findings {
                let kind = match f.kind {
                    CollisionKind::CauseTag => "cause-tag",
                    CollisionKind::StateField => "state-field",
                };
                eprintln!(
                    "    {} `{}` declared by: {}",
                    kind,
                    f.name,
                    f.owners.join(", ")
                );
            }
            eprintln!(
                "    duplicate names compose into one cause $% / state record."
            );
            eprintln!(
                "    Disambiguate via manifest rename, profile-letter suffix, or"
            );
            eprintln!("    domain shadowing.");
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM1/E_to_F.md §META-COLLISION-1"
            );
        }
        if !transitive_imports.findings.is_empty() {
            eprintln!("  transitive-imports:");
            for f in &transitive_imports.findings {
                eprintln!(
                    "    {}: {} {} → {} (NOT FOUND)",
                    f.source.display(),
                    f.rune,
                    f.name,
                    f.target.display(),
                );
                for parent in &f.reachable_from {
                    eprintln!("      reachable from: {}", parent.display());
                }
            }
            eprintln!(
                "    hoonc eager-parses hoon/common/ regardless of import-graph"
            );
            eprintln!(
                "    reachability; unsatisfied edges leave hoonc exit 0 with no"
            );
            eprintln!(
                "    out.jam (the \"no panic!\" silent-fail). Either add the missing"
            );
            eprintln!(
                "    target file or strip the offending file from hoon/common/."
            );
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM2/seed-A.md §DOC-GAP-1"
            );
        }
        if !internal_dupes.findings.is_empty() {
            eprintln!("  internal-dupes:");
            for f in &internal_dupes.findings {
                let kind = match f.kind {
                    InternalDupeKind::CauseTag => "cause-tag",
                    InternalDupeKind::StateField => "state-field",
                };
                let line_list: Vec<String> = f.lines.iter().map(|l| l.to_string()).collect();
                eprintln!(
                    "    duplicate {} `{}` at lines {}",
                    kind,
                    f.name,
                    line_list.join(", "),
                );
            }
            eprintln!(
                "    literal duplicates in the composed +$ cause $%(...) or"
            );
            eprintln!(
                "    +$ versioned-state $:(...) — hoonc accepts whichever wins"
            );
            eprintln!(
                "    lexically (mint-lost) or fires nest-fail on duplicate fields."
            );
            eprintln!(
                "    Rename, merge into a tagged sum, or distinguish by argument shape."
            );
            eprintln!(
                "    see vesl-nockup/.dev/debug/log-meta/RM2/round.md §META-COLLISION"
            );
        }
    }

    if findings_total > 0 {
        bail!("graft-inject lint: {findings_total} finding(s) above");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct LintReport<'a> {
    bare_tilde_ambiguity: &'a [BareTildeLintFinding],
    collision: &'a [CollisionFinding],
    transitive_imports: &'a [TransitiveImportFinding],
    internal_dupes: &'a [InternalDupeFinding],
}

/// `graft-inject codegen kernel-cause-tags` entry point. Reads the
/// composed cause $% from `path` plus every graft's poke arm tags
/// under `lib_dir`, deduplicates, and emits Rust source: a
/// `KERNEL_CAUSE_TAGS: &[&str]` slice plus an `assert_kernel_cause_tag!`
/// macro that compile-time checks tags against the slice.
///
/// Closes RM1 HARD-BUG-3 (kernel rename leaves driver pointing at a
/// dead tag) and HARD-FRICTION-4 (driver tag with no kernel arm) by
/// shifting the failure left from "no effects observed at runtime" to
/// `cargo build` errors.
fn run_codegen_kernel_cause_tags(
    path: &Path,
    lib_dir: &Path,
    out: Option<&Path>,
    json: bool,
) -> Result<()> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; codegen only reads Hoon source files",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; codegen only reads Hoon source files",
            path.display(),
        ),
    }
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<String> = source.lines().map(String::from).collect();

    // Collect tags by walking the literal `+$ cause` definition in
    // `path` (RM2 §2.2). Each member is either:
    //   * an inline `[%<tag> ...]` variant — emit `<tag>` directly
    //     (this captures domain causes — the previously-missed class
    //     that left `assert_kernel_cause_tag!("submit-artifact")` etc.
    //     unsupported);
    //   * a sub-union reference like `settle-cause` or `intent-cause`
    //     — look up the manifest under `lib_dir` whose
    //     `[graft.types].cause` declares that name, then inline its
    //     poke-arm tags via `extract_graft_cause_tags`.
    //
    // Inactive grafts (manifests under lib_dir whose cause type is not
    // referenced from the union) contribute nothing, closing RM2
    // NEW-FRICTION-1 (false-positive tags from placeholder grafts).
    let grafts = if lib_dir.is_dir() {
        discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?
    } else {
        Vec::new()
    };
    let mut tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for member in extract_cause_union_members(&lines) {
        match member {
            CauseUnionMember::Literal { tag, .. } => {
                // Skip the placeholder `[%cause ~]` variant the template
                // ships before any domain tag is added — syntactic anchor,
                // not a real cause-tag.
                if tag != "cause" {
                    tags.insert(tag);
                }
            }
            CauseUnionMember::Reference { name, .. } => {
                // Match against each graft's declared cause type. Falls
                // through silently when no manifest matches — that's an
                // orphan reference (graft missing from lib_dir), which
                // graft-inject's inject pass would have caught earlier.
                for g in &grafts {
                    let matches = g
                        .types
                        .as_ref()
                        .and_then(|t| t.cause.as_deref())
                        .map(|c| c == name)
                        .unwrap_or(false);
                    if matches {
                        for tag in extract_graft_cause_tags(g) {
                            tags.insert(tag);
                        }
                        break;
                    }
                }
            }
        }
    }

    let source_sha = sha256_hex(source.as_bytes());

    if json {
        let doc = CodegenTagsJson {
            source: path.display().to_string(),
            source_sha256: &source_sha,
            kernel_cause_tags: tags.iter().cloned().collect(),
        };
        let s = serde_json::to_string_pretty(&doc)
            .expect("CodegenTagsJson always serializes");
        match out {
            Some(p) => fs::write(p, format!("{s}\n"))
                .with_context(|| format!("writing {}", p.display()))?,
            None => println!("{s}"),
        }
        return Ok(());
    }

    let rust_src = emit_kernel_cause_tags_rs(path, &source_sha, &tags);
    match out {
        Some(p) => fs::write(p, &rust_src)
            .with_context(|| format!("writing {}", p.display()))?,
        None => print!("{rust_src}"),
    }
    Ok(())
}

/// Render the emitted Rust file. The slice is sorted (BTreeSet
/// iteration order); the macro uses a const block so missing tags
/// surface as compile errors rather than runtime panics.
fn emit_kernel_cause_tags_rs(
    source_path: &Path,
    source_sha256: &str,
    tags: &std::collections::BTreeSet<String>,
) -> String {
    let mut s = String::new();
    s.push_str("// AUTO-GENERATED by `graft-inject codegen kernel-cause-tags`.\n");
    s.push_str(&format!("// Source: {} sha256:{}\n", source_path.display(), source_sha256));
    s.push_str("// Re-run after every kernel change. Do not edit by hand.\n\n");
    s.push_str("/// Cause tags accepted by the composed kernel's `+$ cause $%(...)`\n");
    s.push_str("/// union. Sorted lexicographically; see the macro below for\n");
    s.push_str("/// compile-time membership checks.\n");
    s.push_str("pub const KERNEL_CAUSE_TAGS: &[&str] = &[\n");
    for tag in tags {
        s.push_str(&format!("    \"{tag}\",\n"));
    }
    s.push_str("];\n\n");
    s.push_str("/// Compile-time assertion that `$tag` (a string literal) is in\n");
    s.push_str("/// `KERNEL_CAUSE_TAGS`. Use at the call site of every poke\n");
    s.push_str("/// builder so kernel renames surface as `cargo build` errors.\n");
    s.push_str("///\n");
    s.push_str("/// ```rust,ignore\n");
    s.push_str("/// fn build_g_set_poke(name: &str, value: u64) -> NounSlab {\n");
    s.push_str("///     assert_kernel_cause_tag!(\"g-set\");\n");
    s.push_str("///     /* … */\n");
    s.push_str("/// }\n");
    s.push_str("/// ```\n");
    s.push_str("#[macro_export]\n");
    s.push_str("macro_rules! assert_kernel_cause_tag {\n");
    s.push_str("    ($tag:literal) => {\n");
    s.push_str("        const _: () = {\n");
    s.push_str("            const TAG: &str = $tag;\n");
    s.push_str("            let mut found = false;\n");
    s.push_str("            let mut i = 0;\n");
    s.push_str("            while i < $crate::KERNEL_CAUSE_TAGS.len() {\n");
    s.push_str("                let candidate = $crate::KERNEL_CAUSE_TAGS[i];\n");
    s.push_str("                if candidate.len() == TAG.len() {\n");
    s.push_str("                    let cb = candidate.as_bytes();\n");
    s.push_str("                    let tb = TAG.as_bytes();\n");
    s.push_str("                    let mut eq = true;\n");
    s.push_str("                    let mut j = 0;\n");
    s.push_str("                    while j < cb.len() {\n");
    s.push_str("                        if cb[j] != tb[j] {\n");
    s.push_str("                            eq = false;\n");
    s.push_str("                            break;\n");
    s.push_str("                        }\n");
    s.push_str("                        j += 1;\n");
    s.push_str("                    }\n");
    s.push_str("                    if eq {\n");
    s.push_str("                        found = true;\n");
    s.push_str("                        break;\n");
    s.push_str("                    }\n");
    s.push_str("                }\n");
    s.push_str("                i += 1;\n");
    s.push_str("            }\n");
    s.push_str("            assert!(found, concat!(\n");
    s.push_str("                \"cause tag `\", $tag, \"` not in KERNEL_CAUSE_TAGS — \",\n");
    s.push_str("                \"re-run `graft-inject codegen kernel-cause-tags` and \",\n");
    s.push_str("                \"check the driver's poke builder against the kernel's cause $%.\"\n");
    s.push_str("            ));\n");
    s.push_str("        };\n");
    s.push_str("    };\n");
    s.push_str("}\n");
    s
}

#[derive(Debug, Serialize)]
struct CodegenTagsJson<'a> {
    source: String,
    source_sha256: &'a str,
    kernel_cause_tags: Vec<String>,
}

/// One-line stderr warning when the binary's content-hash of `src/`
/// (captured at build time by `build.rs`) doesn't match the current
/// content-hash of `src/` in the manifest dir. Catches the dogfood
/// case where a global `cargo install --path tools/graft-inject` ran
/// weeks ago and has fallen behind source.
///
/// RH1 step 3 (HARD-FRICTION-1): pre-RH1 the metric was `git log -1
/// -- src` (latest commit touching src/), which fired in a working
/// checkout where source had advanced past the binary's git context
/// even when the binary's `src/` bytes already matched. A content-hash
/// fires only when actual bytes differ.
///
/// Silent when:
/// - The build hash is `unknown` (build.rs couldn't walk src/).
/// - The manifest dir from build time no longer exists on this machine
///   (binary was moved, or the source checkout was deleted).
/// - The runtime walk of src/ fails for any reason.
/// - The current content-hash matches the build hash (binary is current).
///
/// Suppress entirely with `GRAFT_INJECT_NO_STALENESS_WARNING=1` for
/// CI runs that don't want the noise.
fn warn_if_stale() {
    if std::env::var("GRAFT_INJECT_NO_STALENESS_WARNING").is_ok() {
        return;
    }
    let build_hash = env!("GRAFT_INJECT_BUILD_SRC_HASH");
    if build_hash == "unknown" {
        return;
    }
    let manifest_dir = env!("GRAFT_INJECT_MANIFEST_DIR");
    let src_root = Path::new(manifest_dir).join("src");
    if !src_root.exists() {
        return;
    }
    let Ok(current_hash) = hash_src_dir(&src_root) else {
        return;
    };
    if current_hash == build_hash {
        return;
    }
    let short = |s: &str| s.chars().take(12).collect::<String>();
    eprintln!(
        "graft-inject: warning — binary built from src/ hash {} but src/ \
         is now at {}. Rebuild: cargo install --path tools/graft-inject --force",
        short(build_hash),
        short(&current_hash),
    );
}

/// Mirror of `build.rs::hash_dir` for runtime staleness check. Walks
/// `dir` recursively, sorts entries by relative path for determinism,
/// and digests `(relative_path_bytes \0 file_bytes \0)` into a sha256.
/// Must stay byte-compatible with the build-time helper.
fn hash_src_dir(dir: &Path) -> std::io::Result<String> {
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_src_files(dir, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for path in &entries {
        let rel = path.strip_prefix(dir).unwrap_or(path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        hasher.update(rel_str.as_bytes());
        hasher.update(b"\0");
        let bytes = fs::read(path)?;
        hasher.update(&bytes);
        hasher.update(b"\0");
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect_src_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_src_files(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn run_inject(cli: Cli) -> Result<()> {
    let grafts = select_grafts(&cli)?;

    if cli.list {
        emit_list(&grafts, cli.json);
        return Ok(());
    }

    let path = cli.path.as_ref().ok_or_else(|| {
        anyhow!("missing target path (or use --list to enumerate discovered grafts)")
    })?;
    // AUDIT 2026-04-19 L-19: require the target to be a Hoon source
    // file. A mistyped argument (e.g. `graft-inject README.md`) would
    // otherwise inject Hoon into whatever happened to contain a marker
    // pattern — useful only for shooting feet.
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; refusing to inject Hoon into a non-.hoon file",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; refusing to inject Hoon into a non-.hoon file",
            path.display(),
        ),
    }
    let raw_source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Optional auto-migration of legacy `+$ effect *` to the marker
    // shape. Runs before the inject pass so the codegen can take over
    // the rewritten line in the same `--apply` invocation.
    let (source, migration) = if cli.no_migrate {
        (raw_source, MigrationReport::skipped())
    } else {
        migrate_legacy_effect(&raw_source)
    };
    print_migration_line(&migration);

    let (output, report) = inject(&source, &grafts)
        .with_context(|| format!("injecting into {}", path.display()))?;

    if cli.dry_run {
        eprintln!(
            "graft-inject: --dry-run is deprecated; preview is the default. \
             Pass --apply to write."
        );
    }

    // AUDIT 2026-04-19 H-10: preview by default, `--apply` to write. The
    // preview prints composed Hoon to stdout and a sha256 summary to
    // stderr so reviewers can see both the exact output and which
    // manifests produced it before any bytes hit disk.
    if cli.apply {
        if output != source {
            atomic_write(path, &output)
                .with_context(|| format!("writing {}", path.display()))?;
        }
    } else {
        print!("{output}");
    }

    print_report(path, &report, &grafts, cli.apply);
    if report.markers_in_source.is_empty() {
        bail!(
            "no nockup markers found in {}; nothing to wire",
            path.display()
        );
    }
    Ok(())
}

/// Resolve the effective graft set per CLI flags. `--grafts` is explicit
/// (must name discovered grafts; unknown names hard-error). Otherwise
/// discover all manifests under `--lib-dir` and subtract `--exclude`.
fn select_grafts(cli: &Cli) -> Result<Vec<Graft>> {
    if !cli.lib_dir.is_dir() {
        bail!(
            "lib-dir {} does not exist or is not a directory",
            cli.lib_dir.display()
        );
    }
    warn_if_lib_dir_out_of_tree(&cli.lib_dir);
    let mut discovered = discover_grafts(&cli.lib_dir)
        .with_context(|| format!("discovering grafts under {}", cli.lib_dir.display()))?;
    if discovered.is_empty() {
        bail!(
            "no grafts discovered under {}; expected at least one *.toml with a [graft] table",
            cli.lib_dir.display()
        );
    }

    if !cli.grafts.is_empty() {
        let known: HashSet<&str> = discovered.iter().map(|g| g.name.as_str()).collect();
        let mut selected: Vec<Graft> = Vec::new();
        for name in &cli.grafts {
            if !known.contains(name.as_str()) {
                bail!(
                    "unknown graft `{name}` (discovered: {})",
                    discovered
                        .iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            // Keep CLI ordering for the explicit form.
            let g = discovered
                .iter()
                .find(|g| g.name == *name)
                .expect("checked above")
                .clone();
            selected.push(g);
        }
        return Ok(selected);
    }

    if !cli.exclude.is_empty() {
        let exclude: HashSet<&str> = cli.exclude.iter().map(String::as_str).collect();
        discovered.retain(|g| !exclude.contains(g.name.as_str()));
        if discovered.is_empty() {
            eprintln!("graft-inject: warning — all discovered grafts were excluded");
        }
    }
    Ok(discovered)
}

/// Warn loudly when `--lib-dir` points outside the project tree.
///
/// AUDIT 2026-04-19 L-21: a developer running `graft-inject --lib-dir
/// /etc ...` (or any path without a `nockapp.toml` ancestor) is almost
/// certainly not doing what they meant. The loader is content to parse
/// any `*.toml` with a `[graft]` table — including ones from an
/// attacker-controlled location. Warn rather than hard-fail so tests
/// and other legitimate out-of-tree uses still run, but make the
/// trust posture explicit.
fn warn_if_lib_dir_out_of_tree(lib_dir: &Path) {
    let canonical = match lib_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return,
    };
    if !has_nockapp_toml_ancestor(&canonical) {
        eprintln!(
            "graft-inject: warning — --lib-dir {} is outside any \
             project (no `nockapp.toml` ancestor). Manifests loaded \
             from here are trusted as-is; ensure you trust their source.",
            canonical.display()
        );
    }
}

fn has_nockapp_toml_ancestor(start: &Path) -> bool {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("nockapp.toml").is_file() {
            return true;
        }
        cur = dir.parent();
    }
    false
}

fn emit_list(grafts: &[Graft], json: bool) {
    if json {
        let summaries: Vec<GraftSummary> = grafts.iter().map(GraftSummary::from_graft).collect();
        let s = serde_json::to_string_pretty(&summaries)
            .expect("GraftSummary always serializes");
        println!("{s}");
        return;
    }
    if grafts.is_empty() {
        println!("(no grafts discovered)");
        return;
    }
    for g in grafts {
        let summary = GraftSummary::from_graft(g);
        println!(
            "  {:<16} {:<8} priority={:<3} ({})",
            summary.name,
            summary.version,
            summary.priority,
            summary.blocks.join(", ")
        );
    }
}

/// Print the per-graft injection report to stderr. stderr (not stdout)
/// so preview users can pipe the rendered file out cleanly. Includes the
/// per-manifest sha256 so supply-chain reviewers can confirm what's
/// about to be composed (AUDIT 2026-04-19 H-10).
fn print_report(path: &Path, report: &InjectReport, grafts: &[Graft], applied: bool) {
    eprintln!("graft-inject: {}", path.display());
    let sha_by_name: HashMap<&str, &str> = grafts
        .iter()
        .map(|g| (g.name.as_str(), g.sha256.as_str()))
        .collect();
    let mut had_output = false;
    for g in &report.grafts {
        if g.applicable.is_empty() {
            continue;
        }
        had_output = true;
        let injected_labels: Vec<&str> =
            g.injected.iter().map(|m| m.label()).collect();
        let skipped_labels: Vec<&str> =
            g.skipped.iter().map(|m| m.label()).collect();
        let sha = sha_by_name
            .get(g.name.as_str())
            .copied()
            .unwrap_or("(sha unavailable)");
        // First 12 hex chars are enough to eyeball; full digest goes in
        // --list --json for machine-readable audits.
        let short = &sha[..sha.len().min(12)];
        let mut summary = format!(
            "  {:<16} sha256:{short} injected {}/{}",
            g.name,
            g.injected.len(),
            g.applicable.len()
        );
        if !injected_labels.is_empty() {
            summary.push_str(&format!(" ({})", injected_labels.join(", ")));
        }
        if !skipped_labels.is_empty() {
            summary.push_str(&format!("; skipped {}", skipped_labels.join(", ")));
        }
        if !g.pruned.is_empty() {
            // RH1 step 1: a graft can both be in the active set AND have
            // had stale orphan markers (from a partial prior run). Surface
            // both states on the same line.
            let pruned_labels: Vec<&str> = g.pruned.iter().map(|m| m.label()).collect();
            summary.push_str(&format!("; pruned {}", pruned_labels.join(", ")));
        }
        eprintln!("{summary}");
    }
    // RH1 step 1: orphan grafts (banner pairs present in source but graft
    // dropped from --grafts) carry no manifest, so they live on a separate
    // carrier. Surface them so the user sees the drop confirmed.
    for g in &report.pruned_grafts {
        had_output = true;
        let pruned_labels: Vec<&str> = g.pruned.iter().map(|m| m.label()).collect();
        eprintln!(
            "  {:<16} no-manifest    pruned {}/{} ({}) (orphan blocks from previous injection)",
            g.name,
            g.pruned.len(),
            g.applicable.len(),
            pruned_labels.join(", ")
        );
    }
    if !had_output {
        eprintln!("  (no grafts contributed)");
    }
    let present_labels: Vec<&str> = report
        .markers_in_source
        .iter()
        .map(|m| m.label())
        .collect();
    let missing_labels: Vec<&str> = report
        .markers_missing
        .iter()
        .map(|m| m.label())
        .collect();
    // Use `applicable` (not `injected`) so the count is stable across `--apply` reruns.
    let populated_labels: Vec<&str> = report
        .markers_in_source
        .iter()
        .filter(|m| report.grafts.iter().any(|g| g.applicable.contains(m)))
        .map(|m| m.label())
        .collect();
    eprintln!(
        "  markers in source: {} ({})",
        present_labels.len(),
        present_labels.join(", ")
    );
    eprintln!(
        "  markers populated: {} ({})",
        populated_labels.len(),
        populated_labels.join(", ")
    );
    if !missing_labels.is_empty() {
        eprintln!(
            "  warning — markers not found: {}",
            missing_labels.join(", ")
        );
    }
    print_codegen_line(&report.codegen);
    print_weld_lint(&report.weld_lint);
    if !applied {
        eprintln!("  (preview only — pass --apply to write {})", path.display());
    }
}

/// Stderr surface for the weld-friction lint. Each finding gets its
/// own line so reviewers can grep / copy. The closing pointer to the
/// zkvesl-docs anchor uses a stable heading slug so the developer can
/// search the docs site without needing to remember the URL.
fn print_weld_lint(lint: &WeldLint) {
    if lint.findings.is_empty() {
        return;
    }
    let n = lint.findings.len();
    eprintln!(
        "  weld-friction lint: {n} narrow effect binding{} found in domain code",
        if n == 1 { "" } else { "s" },
    );
    for f in &lint.findings {
        eprintln!("    line {}: {}", f.line, f.text);
    }
    eprintln!(
        "    cross-graft `(weld a b)` over these bindings will nest-fail. \
         widen each to `(list effect)` so the typed union absorbs each graft's effect."
    );
    eprintln!(
        "    see zkvesl-docs §\"Composing two graft arms in one domain cause\" \
         (/guides/grafting#composing-two-graft-arms-in-one-domain-cause)"
    );
}

/// One-line stderr surface for the typed effect-union codegen pass.
/// Skipped: silent on success-path silence (every kernel without the
/// marker would otherwise spam this line). Inserted/Replaced/Unchanged:
/// announce variant count + names so reviewers can confirm the union
/// matches the active graft set without re-reading the kernel.
fn print_codegen_line(report: &CodegenReport) {
    let label = match report.status {
        CodegenStatus::Skipped => {
            eprintln!(
                "  effect-union codegen: skipped (no nockup:effect-union marker; cast/weld friction remains)"
            );
            return;
        }
        CodegenStatus::Inserted => "inserted",
        CodegenStatus::Replaced => "replaced",
        CodegenStatus::Unchanged => "unchanged",
    };
    eprintln!(
        "  effect-union codegen: {label} ({} variant{}: {})",
        report.variants.len(),
        if report.variants.len() == 1 { "" } else { "s" },
        report.variants.join(", "),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Block, GraftBlocks, GraftTypes, ManifestFile, load_manifest};
    use serde::Deserialize;

    const BARE_SCAFFOLD: &str = "\
::  test scaffold
/+  lib
::  nockup:imports
/=  *  /common/wrapper
::
=>
|%
+$  versioned-state
  $:  %v1
      ::  nockup:state
      ~
  ==
::
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
|%
++  moat  (keep versioned-state)
::
++  inner
  |_  state=versioned-state
  ++  load
    |=  old=versioned-state
    old
  ++  peek
    |=  =path
    ^-  (unit (unit *))
    ?+  path
      ::  nockup:peek
      ~
      [%count ~]  ``0
    ==
  ++  poke
    |=  =ovum:moat
    ^-  [(list effect) _state]
    =/  act  ((soft cause) cause.input.ovum)
    ?~  act  [~ state]
    ::  nockup:poke-prelude
    =/  out=[efx=(list effect) new=_state]
      ?-  -.u.act
          %cause  [~ state]
        ::  nockup:poke
      ==
    ::  nockup:poke-postlude
    out
  --
--
((moat |) inner)
";

    fn settle_only_grafts() -> Vec<Graft> {
        let path = settle_graft_manifest_path();
        let g = load_manifest(&path)
            .expect("load settle-graft.toml")
            .expect("settle-graft.toml has [graft] table");
        vec![g]
    }

    /// Build a minimal in-memory Graft for synthetic multi-graft tests.
    /// `name` doubles as the binding stub in the peek chain (no `-graft`
    /// suffix), so assertions can match `<name>-res` directly.
    fn synthetic_graft(name: &str, priority: i32) -> Graft {
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority,
            after: vec![],
            blocks: GraftBlocks {
                imports: Some(Block {
                    sentinel: format!("*{name}"),
                    body: format!("/+  *{name}"),
                }),
                state: Some(Block {
                    sentinel: format!("{name}={name}-state"),
                    body: format!("{name}={name}-state"),
                }),
                cause: Some(Block {
                    sentinel: format!("{name}-cause"),
                    body: format!("{name}-cause"),
                }),
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: format!("%{name}-do"),
                    body: format!(
                        "  %{name}-do\n=/  lc=cause  [%{name}-do ~]\n[~ state]"
                    ),
                }),
                poke_postlude: None,
                peek: Some(Block {
                    sentinel: format!("{name}-peek"),
                    body: format!("({name}-peek state path)"),
                }),
            },
            gates: None,
            types: None,
            sha256: String::new(),
        }
    }

    fn settle_graft_manifest_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("hoon")
            .join("lib")
            .join("settle-graft.toml")
    }

    fn tempdir_for_test(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("graft-inject-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

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

    #[test]
    fn missing_marker_is_warning_not_error() {
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
            // Body lines land one row after the `begin_banner` emitted by
            // AUDIT 2026-04-19 H-11..H-14's idempotence refactor. R5/A2
            // (2026-05-04) appended a ` sha256:<short>` suffix; assert
            // on the prefix shape so the test isn't coupled to the live
            // sha256 of every fixture manifest.
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
        // R5/A2: begin banners now carry a ` sha256:<short>` suffix.
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
        // For N=1 the chain (post-AUDIT 2026-04-19 banner refactor) is:
        //   ::  graft-inject:settle-graft:peek:begin
        //   =/  settle-res  (settle-peek settle.state path)
        //   ?.  =(~ settle-res)  settle-res
        //   ::  graft-inject:settle-graft:peek:end
        //   ~                                   <- terminal fallback
        //
        // The legacy `(settle-peek settle.state path)` expression lives inside
        // the chain's `=/` binding — same runtime semantics as the
        // pre-Phase-4 flat replacement.
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

    // ---------- CLI tests ----------

    fn cli_with(lib_dir: PathBuf) -> Cli {
        Cli {
            command: None,
            path: None,
            grafts: Vec::new(),
            exclude: Vec::new(),
            lib_dir,
            list: false,
            json: false,
            dry_run: false,
            apply: false,
            no_migrate: false,
        }
    }

    /// `graft-inject inject hoon/app/app.hoon --grafts foo,bar --apply`
    /// should parse cleanly into Command::Inject with the listed args.
    #[test]
    fn cli_parses_inject_subcommand() {
        let cli = Cli::try_parse_from([
            "graft-inject",
            "inject",
            "hoon/app/app.hoon",
            "--grafts",
            "foo,bar",
            "--apply",
        ])
        .expect("inject subcommand must parse");
        match cli.command {
            Some(Command::Inject {
                path,
                grafts,
                apply,
                no_migrate,
                ..
            }) => {
                assert_eq!(path, PathBuf::from("hoon/app/app.hoon"));
                assert_eq!(grafts, vec!["foo".to_string(), "bar".to_string()]);
                assert!(apply);
                assert!(!no_migrate);
            }
            other => panic!("expected Command::Inject, got {other:?}"),
        }
    }

    /// `graft-inject list --json` parses into Command::List with json on.
    #[test]
    fn cli_parses_list_subcommand() {
        let cli = Cli::try_parse_from(["graft-inject", "list", "--json"])
            .expect("list subcommand must parse");
        match cli.command {
            Some(Command::List { json, .. }) => assert!(json),
            other => panic!("expected Command::List, got {other:?}"),
        }
    }

    /// `graft-inject hoon/app/app.hoon --grafts foo` (legacy bare form)
    /// must still parse — `command` ends up `None` and the legacy fields
    /// carry the args. This is the back-compat path that prints the
    /// deprecation note in `dispatch`.
    #[test]
    fn cli_parses_legacy_bare_invocation() {
        let cli = Cli::try_parse_from([
            "graft-inject",
            "hoon/app/app.hoon",
            "--grafts",
            "foo",
        ])
        .expect("legacy bare form must still parse");
        assert!(cli.command.is_none());
        assert_eq!(cli.path.as_deref(), Some(Path::new("hoon/app/app.hoon")));
        assert_eq!(cli.grafts, vec!["foo".to_string()]);
    }

    // ---------- bare-tilde-ambiguity lint ----------

    /// RM1 HARD-BUG-2 reproduction: a domain `%ping` arm whose body
    /// is `^- (list effect)` then a bare `~` line should trip the
    /// lint. The `find_last_bare_tilde` scan would otherwise pick
    /// this `~` up as the peek-chain terminator.
    #[test]
    fn bare_tilde_lint_flags_ping_arm() {
        let fixture = r#"?-    -.u.act
    %ping
  :_  state
  ^-  (list effect)
  ~
    %quiet
  [~ state]
    ::  nockup:poke
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert_eq!(lint.findings.len(), 1, "expected 1 finding, got {lint:#?}");
        assert_eq!(lint.findings[0].arm, "ping");
        // Line 5 is the `~` (1-indexed; line 1 is the `?-` switch).
        assert_eq!(lint.findings[0].line, 5);
    }

    /// Workaround form (`(list effect)~` on one line) is safe — no
    /// bare `~` line, no finding.
    #[test]
    fn bare_tilde_lint_clears_one_line_workaround() {
        let fixture = r#"?-    -.u.act
    %ping
  :_  state
  `(list effect)`~
    %quiet
  [~ state]
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(
            lint.findings.is_empty(),
            "workaround form should not flag, got {lint:#?}"
        );
    }

    /// Graft-injected arms use bare `~` legitimately (it's their
    /// chain terminator). The lint must skip lines inside
    /// `graft-inject:<X>:begin/:end` banner pairs.
    #[test]
    fn bare_tilde_lint_skips_graft_injected_arms() {
        let fixture = r#"?-    -.u.act
::  graft-inject:settle-graft:poke:begin sha256:deadbeef
    %settle-do
  :_  state
  ~
::  graft-inject:settle-graft:poke:end
    %ping
  :_  state
  `(list effect)`~
=="#;
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(
            lint.findings.is_empty(),
            "graft-injected bodies must be skipped, got {lint:#?}"
        );
    }

    /// Without a `?-  -.u.act` switch, the lint is a no-op.
    #[test]
    fn bare_tilde_lint_no_switch_no_findings() {
        let fixture = "++  peek\n  ~\n--";
        let lines: Vec<String> = fixture.lines().map(String::from).collect();
        let lint = lint_bare_tilde_ambiguity(&lines);
        assert!(lint.findings.is_empty());
    }

    // ---------- collision-check lint ----------

    /// Build a synthetic graft with named cause tags and state fields
    /// for collision-check tests. The block bodies follow the canonical
    /// shape: state body is `<field>=<type>`, poke body has bare
    /// `%<tag>` arm headers separated by `::`.
    fn synthetic_collision_graft(
        name: &str,
        cause_tags: &[&str],
        state_fields: &[&str],
    ) -> Graft {
        let mut poke_body = String::new();
        for tag in cause_tags {
            poke_body.push_str("::\n  %");
            poke_body.push_str(tag);
            poke_body.push_str("\n[~ state]\n");
        }
        let state_body = state_fields
            .iter()
            .map(|f| format!("{f}=@"))
            .collect::<Vec<_>>()
            .join("\n");
        Graft {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            priority: 50,
            after: vec![],
            blocks: GraftBlocks {
                imports: None,
                state: if state_fields.is_empty() {
                    None
                } else {
                    Some(Block {
                        sentinel: state_fields[0].to_string(),
                        body: state_body,
                    })
                },
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: format!("%{}", cause_tags.first().unwrap_or(&"")),
                    body: poke_body,
                }),
                poke_postlude: None,
                peek: None,
            },
            types: None,
            gates: None,
            sha256: "0".repeat(64),
        }
    }

    /// RM1 META-COLLISION-1: queue-graft and pipeline-graft both
    /// declare `%enqueue-job`. Cross-graft cause-tag collision should
    /// fire one finding naming both grafts as owners.
    #[test]
    fn collision_lint_flags_cross_graft_cause_tag() {
        let queue = synthetic_collision_graft(
            "queue-graft",
            &["enqueue-job", "drain-jobs"],
            &["queue"],
        );
        let pipeline = synthetic_collision_graft(
            "pipeline-graft",
            &["enqueue-job", "ack-job"],
            &["pipeline"],
        );
        let lint = lint_collision_check(&[queue, pipeline], &[]);
        assert_eq!(lint.findings.len(), 1);
        assert_eq!(lint.findings[0].name, "enqueue-job");
        assert_eq!(lint.findings[0].kind, CollisionKind::CauseTag);
        assert!(lint.findings[0].owners.contains(&"queue-graft".to_string()));
        assert!(
            lint.findings[0]
                .owners
                .contains(&"pipeline-graft".to_string())
        );
    }

    /// RM1 META-COLLISION-2: domain declares `entries` field and a
    /// graft also exposes `entries`. The lint should fire one finding
    /// with one owner being `(domain)`.
    #[test]
    fn collision_lint_flags_domain_vs_graft_state() {
        let audit = synthetic_collision_graft("audit-graft", &["log-entry"], &["entries"]);
        let domain = vec![
            "+$  versioned-state".to_string(),
            "  $:  %v1".to_string(),
            "      entries=(list @t)".to_string(),
            "      ::  nockup:state".to_string(),
            "  ==".to_string(),
        ];
        let lint = lint_collision_check(&[audit], &domain);
        assert_eq!(lint.findings.len(), 1);
        assert_eq!(lint.findings[0].name, "entries");
        assert_eq!(lint.findings[0].kind, CollisionKind::StateField);
        assert!(
            lint.findings[0]
                .owners
                .contains(&"(domain)".to_string())
        );
        assert!(
            lint.findings[0]
                .owners
                .contains(&"audit-graft".to_string())
        );
    }

    /// Two grafts with disjoint tag sets and disjoint field sets
    /// must produce zero findings. Sanity check that the lint isn't
    /// over-flagging.
    #[test]
    fn collision_lint_clears_disjoint_grafts() {
        let queue = synthetic_collision_graft("queue-graft", &["queue-push"], &["queue"]);
        let counter =
            synthetic_collision_graft("counter-graft", &["counter-inc"], &["counter"]);
        let lint = lint_collision_check(&[queue, counter], &[]);
        assert!(
            lint.findings.is_empty(),
            "disjoint grafts must not collide, got {lint:#?}"
        );
    }

    // ---------- codegen kernel-cause-tags ----------

    /// `emit_kernel_cause_tags_rs` produces a sorted slice + macro
    /// scaffolding. Verify the slice contains the supplied tags in
    /// sorted order and that the assert_kernel_cause_tag! macro
    /// definition appears.
    #[test]
    fn codegen_kernel_cause_tags_emits_slice_and_macro() {
        let mut tags = std::collections::BTreeSet::new();
        tags.insert("settle-register".to_string());
        tags.insert("g-set".to_string());
        tags.insert("snapshot-root".to_string());
        let path = PathBuf::from("hoon/app/app.hoon");
        let src = emit_kernel_cause_tags_rs(&path, "deadbeef", &tags);
        assert!(src.contains("pub const KERNEL_CAUSE_TAGS: &[&str] = &["));
        // BTreeSet iteration order is sorted: g-set < settle-register < snapshot-root
        let g_pos = src.find("\"g-set\"").expect("g-set should be present");
        let s_pos = src
            .find("\"settle-register\"")
            .expect("settle-register should be present");
        let sn_pos = src
            .find("\"snapshot-root\"")
            .expect("snapshot-root should be present");
        assert!(g_pos < s_pos);
        assert!(s_pos < sn_pos);
        assert!(src.contains("macro_rules! assert_kernel_cause_tag"));
        assert!(src.contains("Source: hoon/app/app.hoon sha256:deadbeef"));
    }

    /// `extract_domain_cause_tags` skips the placeholder `[%cause ~]`
    /// variant when the codegen builds its tag set — the placeholder
    /// is a syntactic anchor, not a real cause.
    #[test]
    fn codegen_skips_placeholder_cause() {
        // The codegen filter lives in run_codegen_kernel_cause_tags;
        // simulate the filtering here so the test runs without I/O.
        let domain_lines: Vec<String> = "+$  cause\n  $%  [%cause ~]\n      [%real-tag @t]\n      ::  nockup:cause\n  =="
            .lines()
            .map(String::from)
            .collect();
        let raw: Vec<String> = extract_domain_cause_tags(&domain_lines);
        assert!(raw.contains(&"cause".to_string()));
        let filtered: Vec<&String> = raw.iter().filter(|t| t.as_str() != "cause").collect();
        assert_eq!(filtered, vec![&"real-tag".to_string()]);
    }

    /// Domain cause-tag colliding with a graft cause-tag fires a
    /// CauseTag finding with `(domain)` listed alongside the graft.
    #[test]
    fn collision_lint_flags_domain_vs_graft_cause() {
        let queue = synthetic_collision_graft("queue-graft", &["queue-push"], &["queue"]);
        let domain = vec![
            "+$  cause".to_string(),
            "  $%  [%queue-push payload=@]".to_string(),
            "      ::  nockup:cause".to_string(),
            "  ==".to_string(),
        ];
        let lint = lint_collision_check(&[queue], &domain);
        assert!(
            lint.findings.iter().any(|f| f.name == "queue-push"
                && f.kind == CollisionKind::CauseTag
                && f.owners.contains(&"(domain)".to_string())
                && f.owners.contains(&"queue-graft".to_string())),
            "expected domain-vs-graft cause-tag finding, got {lint:#?}"
        );
    }

    /// Build a temp lib dir with settle-graft.toml and an alpha synthetic
    /// manifest so multi-manifest selection logic can be tested without
    /// the real hoon/lib tree.
    fn tempdir_with_two_manifests(label: &str) -> PathBuf {
        let dir = tempdir_for_test(label);
        let settle_src = fs::read_to_string(settle_graft_manifest_path()).unwrap();
        fs::write(dir.join("settle-graft.toml"), settle_src).unwrap();
        fs::write(
            dir.join("alpha.toml"),
            r#"[graft]
name     = "alpha"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*alpha"
body     = "/+  *alpha"

[graft.blocks.state]
sentinel = "alpha=alpha-state"
body     = "alpha=alpha-state"

[graft.blocks.cause]
sentinel = "alpha-cause"
body     = "alpha-cause"

[graft.blocks.poke]
sentinel = "%alpha-do"
body     = """
  %alpha-do
[~ state]"""

[graft.blocks.peek]
sentinel = "alpha-peek"
body     = "(alpha-peek state path)"
"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn unknown_graft_name_errors() {
        let dir = tempdir_with_two_manifests("unknown_graft");
        let mut cli = cli_with(dir.clone());
        cli.grafts = vec!["nosuch".to_string()];
        let err = select_grafts(&cli).expect_err("unknown name must error");
        assert!(
            err.to_string().contains("unknown graft `nosuch`"),
            "error should name the bad graft, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exclude_flag_subtracts() {
        let dir = tempdir_with_two_manifests("exclude_flag");
        let mut cli = cli_with(dir.clone());
        cli.exclude = vec!["alpha".to_string()];
        let selected = select_grafts(&cli).unwrap();
        let names: Vec<&str> = selected.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["settle-graft"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_does_not_write() {
        // AUDIT 2026-04-19 H-10: the default is preview-only. Without
        // --apply, the file on disk must be unchanged regardless of what
        // `graft-inject` composed into stdout.
        let dir = tempdir_with_two_manifests("default_preview");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();
        let original = fs::read_to_string(&target).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_eq!(after, original, "preview-only default must not modify the file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_writes() {
        // --apply is the explicit write-enabler post-AUDIT 2026-04-19 H-10.
        let dir = tempdir_with_two_manifests("apply_writes");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.grafts = vec!["settle-graft".to_string()];
        cli.apply = true;
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_ne!(after, BARE_SCAFFOLD, "--apply must modify the file");
        assert!(after.contains("::  graft-inject:settle-graft:imports:begin"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_alias_still_parses() {
        // `--dry-run` is the deprecated alias of the preview-only default.
        // It should still parse and leave the file unchanged; the
        // deprecation note to stderr is best-effort.
        let dir = tempdir_with_two_manifests("dry_run_alias");
        let target = dir.join("app.hoon");
        fs::write(&target, BARE_SCAFFOLD).unwrap();

        let mut cli = cli_with(dir.clone());
        cli.path = Some(target.clone());
        cli.dry_run = true;
        cli.grafts = vec!["settle-graft".to_string()];
        run_inject(cli).unwrap();

        let after = fs::read_to_string(&target).unwrap();
        assert_eq!(after, BARE_SCAFFOLD);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_json_is_stable() {
        // Schema (documented in vesl/docs/graft-manifest.md):
        //   [{ name, version, priority, blocks: [...], applicable, deferred, sha256 }]
        //
        // `sha256` was added per AUDIT 2026-04-19 H-10 — additive per the
        // "append never reshape" contract this schema keeps.
        let grafts = settle_only_grafts();
        let summaries: Vec<GraftSummary> =
            grafts.iter().map(GraftSummary::from_graft).collect();
        let json = serde_json::to_string(&summaries).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);
        let first = &arr[0];
        assert_eq!(first["name"], "settle-graft");
        assert_eq!(first["version"], "0.1.0");
        assert_eq!(first["priority"], 10);
        assert_eq!(first["applicable"], 5);
        assert_eq!(first["deferred"], false);
        let blocks = first["blocks"].as_array().expect("blocks is array");
        assert_eq!(blocks.len(), 5);
        let block_names: Vec<&str> = blocks
            .iter()
            .map(|v| v.as_str().expect("block label is string"))
            .collect();
        assert_eq!(
            block_names,
            vec!["imports", "state", "cause", "poke", "peek"]
        );
        let sha = first["sha256"].as_str().expect("sha256 is a string");
        assert_eq!(sha.len(), 64, "sha256 hex length");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "sha256 must be lowercase hex: {sha}"
        );
    }

    // ---------- AUDIT 2026-04-19 H-11..H-14 regressions ----------

    /// Write a synthetic manifest with the given `name` into `dir` at
    /// `file_name`, so `discover_grafts` can exercise collision + name
    /// validation paths without touching the real hoon/lib tree.
    fn write_manifest(dir: &Path, file_name: &str, name: &str) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
            ),
        )
        .unwrap();
    }

    /// Like `write_manifest` but adds a `[graft.types]` table with the
    /// caller-supplied effect/cause names. Used by the cross-graft type
    /// uniqueness tests.
    fn write_manifest_with_types(
        dir: &Path,
        file_name: &str,
        name: &str,
        effect: &str,
        cause: &str,
    ) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.types]
effect = "{effect}"
cause  = "{cause}"

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
            ),
        )
        .unwrap();
    }

    /// H-11: two manifests claiming the same `name` must hard-error at
    /// discovery time, naming both source paths. The pre-audit loader let
    /// both through and panicked downstream with `expect("seeded above")`.
    #[test]
    fn duplicate_name_bails() {
        let dir = tempdir_for_test("duplicate_name");
        write_manifest(&dir, "a.toml", "shared");
        write_manifest(&dir, "b.toml", "shared");
        let err = discover_grafts(&dir).expect_err("duplicate name must bail");
        let msg = err.to_string();
        assert!(msg.contains("duplicate graft name `shared`"), "got: {msg}");
        assert!(msg.contains("a.toml"), "missing path a in: {msg}");
        assert!(msg.contains("b.toml"), "missing path b in: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// H-11 defense-in-depth: names interpolate into banner comments and
    /// internal paths, so a hostile manifest that sneaks a `.`/`/` into
    /// the name field would break idempotence and risk path traversal on
    /// consumers that key on the name. Reject at discovery.
    #[test]
    fn invalid_name_bails() {
        let dir = tempdir_for_test("invalid_name");
        write_manifest(&dir, "evil.toml", "../evil");
        let err = discover_grafts(&dir).expect_err("bad name must bail");
        assert!(
            err.to_string().contains("invalid graft name"),
            "got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
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
                    sentinel: "*poison".to_string(),
                    body: "/+  *poison".to_string(),
                }),
                state: None,
                cause: None,
                poke_prelude: None,
                poke: Some(Block {
                    sentinel: "%poison-do".to_string(),
                    body: "  %poison-do\n::  references %contaminant-do elsewhere\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
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
                    sentinel: "%nested-do".to_string(),
                    body: "  %nested-do\n?-  +.state\n  [%foo ~]  [~ state]\n  [%bar ~]  [~ state]\n==\n[~ state]".to_string(),
                }),
                poke_postlude: None,
                peek: None,
            },
            gates: None,
            types: None,
            sha256: String::new(),
        };
        let (first, _) = inject(BARE_SCAFFOLD, std::slice::from_ref(&nested)).unwrap();
        assert!(first.lines().any(|l| l.trim() == "=="), "inner == present");
        let (second, report) = inject(&first, &[nested]).unwrap();
        assert_eq!(first, second, "inner == must not re-trigger inject");
        assert!(report.grafts[0].injected.is_empty());
    }

    /// RH1 step 1 (HARD-BUG-1): removing a graft from the injection set
    /// auto-prunes its banner-pair-bounded blocks. Pre-RH1 the tool was
    /// additive-only; orphan blocks then referenced types missing from the
    /// shrunk effect-union and hoonc failed silently. The new contract is:
    /// drop a graft from `--grafts`, re-run with `--apply`, and the orphan
    /// blocks are stripped automatically.
    ///
    /// Byte-identical round-trip across drop-then-readd is a Step 2 concern
    /// (HARD-FRICTION-2 — preserve position on fresh-inject after a partial
    /// drop). This test isolates the prune contract.
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

    /// RH1 step 2 (HARD-FRICTION-2): manifest drift on a non-first graft
    /// must re-inject the block at its ORIGINAL line position, not at the
    /// marker line. Pre-RH1 the strip-then-reinject path placed the
    /// drifted graft's block at marker_idx+1, pushing every later graft
    /// down by one — so a non-semantic edit (e.g., a gate-selection swap
    /// in the manifest) changed `sha256(app.hoon)` even though the file
    /// was logically equivalent. After Step 2, drift re-injection at
    /// emit_block-class markers preserves position; the file is byte-
    /// identical when the drifted manifest is reverted.
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
             Pre-RH1 the drifted graft jumped to marker_idx+1, inverting the order."
        );

        // Revert beta to its original sha. The result is byte-identical
        // to the initial composition — drift round-trips at the byte level.
        let (after_revert, _) = inject(&after_drift, &[alpha, beta]).unwrap();
        assert_eq!(
            after_revert, composed,
            "drift-then-revert is byte-identical (Step 2 invariant)"
        );
    }

    /// RH2 HARD-BUG-2 regression guard: peek-marker drift re-injection
    /// must preserve relative order between graft peek blocks. Pre-fix
    /// (RH1 step 2) Peek was excluded from the position-preservation
    /// gate, so peek drift fell through to the batch fresh-inject path
    /// (`emit_peek_chain`) which inserts before the chain's terminal
    /// `~` — relocating the drifted block to the tail. Post-fix (RH2
    /// step 2) `canonicalize_marker_section` strips and re-emits all
    /// active grafts in canonical order regardless of marker type.
    ///
    /// Test shape: drift the FIRST graft of a 3-graft chain.
    /// Reproduces the post-mortem's settle-graft peek migration
    /// (line 101 → 113) at HARD-REV-SWAP-GATE.
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
             alpha:peek still precedes beta:peek. HARD-BUG-2 currently \
             relocates the drifted peek block to the chain tail."
        );
        assert!(
            pos(&after_drift, "beta") < pos(&after_drift, "gamma"),
            "non-drifted blocks (beta, gamma) keep relative order through drift"
        );

        let (after_revert, _) = inject(&after_drift, &[alpha, beta, gamma]).unwrap();
        assert_eq!(
            after_revert, composed,
            "peek drift-then-revert is byte-identical (HARD-BUG-2 invariant)"
        );
    }

    /// RH2 HARD-BUG-3: dropping a graft and re-adding it currently lands
    /// the re-injected block at marker_idx+1 (position 1 of each marker
    /// section), displacing any other graft blocks below the marker.
    /// After the canonical-re-emit refactor, the final layout is a pure
    /// function of the active graft set and drop+readd is byte-identical.
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
            "drop+readd is byte-identical (HARD-BUG-3 invariant). \
             Pre-fix the re-added beta lands at marker_idx+1 in each \
             section instead of between alpha and gamma."
        );
    }

    /// RH2 HARD-BUG-3 cross-marker scenario: matches the post-mortem's
    /// HARD-REV-IDEMPOTENCE-CHAIN sequence with four grafts. The byte-
    /// identical assertion catches both the direct (re-added graft
    /// position) and the collateral (other grafts moving) symptoms in a
    /// single check.
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
             Catches the HARD-BUG-3 collateral-movement symptom — \
             the post-mortem's `log-graft jumps to position 1 even \
             though only validate was re-added` bug."
        );
    }

    // ---------------------------------------------------------------
    // [graft.gates] selection
    // ---------------------------------------------------------------

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

    // ---------------------------------------------------------------
    // typed effect-union codegen
    // ---------------------------------------------------------------

    /// Synthetic graft with a `[graft.types]` declaration. Reuses
    /// `synthetic_graft` (which leaves `types: None`) and overrides.
    fn synthetic_graft_with_effect(name: &str, priority: i32) -> Graft {
        let mut g = synthetic_graft(name, priority);
        g.types = Some(GraftTypes {
            effect: Some(format!("{name}-effect")),
            cause: Some(format!("{name}-cause")),
        });
        g
    }

    /// Bare scaffold + a `nockup:effect-union` marker. Used as the
    /// codegen test fixture so the existing BARE_SCAFFOLD tests keep
    /// running unmodified.
    const SCAFFOLD_WITH_UNION_MARKER: &str = "\
::  test scaffold with codegen marker
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

    /// Same as above plus a `nockup:domain-effect` marker and a
    /// developer-declared `+$ domain-effect` block.
    const SCAFFOLD_WITH_BOTH_MARKERS: &str = "\
::  test scaffold with both codegen markers
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%user-thing ~]
  ==
::
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

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

    // ---------------------------------------------------------------
    // weld-friction lint
    // ---------------------------------------------------------------

    /// Scaffold + a domain `%set` arm that binds narrowly. Used to
    /// exercise the weld-friction lint on developer code outside any
    /// graft-inject banner region.
    const SCAFFOLD_NARROW_BINDING: &str = "\
::  test scaffold with narrow effect bindings
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%set-done ~]
  ==
::
::  nockup:effect-union
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      [%set name=@t value=@]
      ::  nockup:cause
  ==
::
=/  [efx-c=(list counter-effect) new-counter=counter-state]
  (counter-poke counter.state [%counter-increment name.u.act])
=/  [efx-k=(list kv-effect) new-kv=kv-state]
  (kv-poke kv.state [%kv-set name.u.act value.u.act])
(weld efx-c efx-k)
--
";

    #[test]
    fn weld_lint_flags_narrow_bindings_in_domain_code() {
        let counter = synthetic_graft_with_effect("counter", 60);
        let kv = synthetic_graft_with_effect("kv", 50);
        let (_, report) = inject(SCAFFOLD_NARROW_BINDING, &[kv, counter]).unwrap();
        assert_eq!(
            report.weld_lint.findings.len(),
            2,
            "two narrow bindings should be flagged: {:#?}",
            report.weld_lint.findings,
        );
        let narrow_types: Vec<&str> = report
            .weld_lint
            .findings
            .iter()
            .map(|f| f.narrow_type.as_str())
            .collect();
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
        assert_eq!(report.weld_lint.findings.len(), 2);
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
            report.weld_lint.findings.is_empty(),
            "Pattern B widening must not trip the lint: {:#?}",
            report.weld_lint.findings,
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
        assert!(report.weld_lint.findings.is_empty());
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
    // RM4 §1 v0.2: load-defaults overlay codegen
    // ---------------------------------------------------------------

    /// Bare scaffold + a `nockup:load-defaults` marker placed inside an
    /// `++load` arm body. The placeholder `old-state` line directly
    /// after the marker mirrors the production marker template; the
    /// codegen replaces it with a `=/  defaults  ^*(versioned-state)` +
    /// `%_  defaults  ...  ==` overlay block.
    const SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER: &str = "\
::  test scaffold with load-defaults marker
::  nockup:load-defaults
old-state
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

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
