//! Typed effect-union, load-defaults overlay, and kernel-cause-tags
//! codegen passes.
//!
//! These passes synthesize Hoon (or Rust, in the cause-tags case) at
//! codegen-owned banner pairs in the composed source. The lint suite
//! consumes their report variant lists and rendered output by
//! reference — there's no hidden state coupling, so the two layers
//! split cleanly.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::harness_bindings::{
    HarnessGraftBindings, HarnessPoke, LoadedHarnessBindings, load_harness_bindings,
    validate_bindings_against_grafts,
};
use crate::inject::binding_stub;
use crate::lint::{CauseUnionMember, extract_cause_union_members, extract_graft_cause_tags};
use crate::manifest::{Graft, discover_grafts, sha256_hex};
use crate::marker::{Marker, codegen_begin_banner, codegen_end_banner, find_marker, leading_whitespace};

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

/// `graft-inject codegen kernel-cause-tags` entry point. Reads the
/// composed cause $% from `path` plus every graft's poke arm tags
/// under `lib_dir`, deduplicates, and emits Rust source: a
/// `KERNEL_CAUSE_TAGS: &[&str]` slice plus an `assert_kernel_cause_tag!`
/// macro that compile-time checks tags against the slice.
///
/// Shifts two failures left to `cargo build` errors: a kernel rename
/// that leaves the driver pointing at a dead tag, and a driver tag with
/// no matching kernel arm — both otherwise surface only as "no effects
/// observed at runtime".
pub(crate) fn run_codegen_kernel_cause_tags(
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
    // `path`. Each member is either:
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
    // referenced from the union) contribute nothing, so a placeholder
    // graft can't inject false-positive tags.
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
pub(crate) fn emit_kernel_cause_tags_rs(
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
pub(crate) struct CodegenTagsJson<'a> {
    pub(crate) source: String,
    pub(crate) source_sha256: &'a str,
    pub(crate) kernel_cause_tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// harness-methods codegen — emits typed `GraftTestHarness` methods that
// delegate to existing `vesl_core::build_*_poke` builders + per-graft
// typed outcome enums + extension traits on `vesl_core::PokeOutcome`.
//
// Source of truth: `hoon/lib/harness-bindings.toml` (the sidecar). The
// per-graft canonical manifests stay untouched in this cut — see
// `.dev/vesl-nockup-v2.0.md` for the planned promotion.
// ---------------------------------------------------------------------------

/// `graft-inject codegen harness-methods` entry point. Loads the
/// sidecar, cross-checks every `(graft, tag)` against the matching
/// `*-graft.toml` poke body, and emits Rust source for
/// `test/vesl-test/src/generated_harness.rs`.
///
/// The generated file contains, in order:
///
/// 1. A provenance header (sidecar path + sha256).
/// 2. `use` lines for the non-primitive types referenced by any bound
///    arg (`Tip5Hash`, `NounSlab`, `ValidateRule`, `ProofNode`).
/// 3. One `pub enum <Graft>Outcome { ... }` per graft with bound
///    pokes, carrying typed variants for the graft's error / rejected /
///    denied effects.
/// 4. One `pub trait <Graft>OutcomeExt` per graft with an
///    `as_<graft>_outcome(&self) -> <Graft>Outcome` method, plus an
///    `impl <Graft>OutcomeExt for vesl_core::PokeOutcome`.
/// 5. A single `impl crate::GraftTestHarness { ... }` block with one
///    async method per bound poke arm, delegating to
///    `vesl_core::<builder>(...)` and returning
///    `anyhow::Result<vesl_core::PokeOutcome>`.
pub(crate) fn run_codegen_harness_methods(
    bindings_path: &Path,
    lib_dir: &Path,
    out: Option<&Path>,
) -> Result<()> {
    let loaded = load_harness_bindings(bindings_path)?;
    let grafts = if lib_dir.is_dir() {
        discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?
    } else {
        bail!(
            "lib dir {} is not a directory; harness-methods codegen reads \
             every graft manifest to cross-check bindings against poke arms",
            lib_dir.display()
        );
    };
    validate_bindings_against_grafts(&loaded.bindings, &grafts)?;
    let src = emit_harness_methods_rs(bindings_path, &loaded);
    match out {
        Some(p) => fs::write(p, &src)
            .with_context(|| format!("writing {}", p.display()))?,
        None => print!("{src}"),
    }
    Ok(())
}

/// Render the full generated `generated_harness.rs`.
pub(crate) fn emit_harness_methods_rs(
    source_path: &Path,
    loaded: &LoadedHarnessBindings,
) -> String {
    let mut s = String::new();
    s.push_str(
        "//! AUTO-GENERATED by `nockup-graft codegen harness-methods`.\n",
    );
    s.push_str(&format!(
        "//! Source: {} sha256:{}\n",
        source_path.display(),
        &loaded.sha256
    ));
    s.push_str("//! Re-run after every harness-bindings change. Do not edit by hand.\n");
    s.push_str("//!\n");
    s.push_str("//! See `tools/graft-inject/src/harness_bindings.rs` for the sidecar\n");
    s.push_str("//! schema and `tools/graft-inject/src/codegen.rs` for the emitter.\n");
    s.push_str("\n");
    s.push_str("#![allow(unused_imports)]\n\n");

    let used = collect_used_types(loaded);
    if !used.is_empty() {
        for ident in &used {
            s.push_str(&render_use_line(ident));
        }
        s.push_str("\n");
    }

    // 3. + 4. — per-graft typed outcome enums + extension traits.
    for graft in &loaded.bindings.grafts {
        if !graft_has_typed_outcome(graft) {
            continue;
        }
        emit_outcome_enum(&mut s, graft);
        emit_outcome_ext_trait(&mut s, graft);
    }

    // 5. — single impl block holding every generated poke method.
    s.push_str("impl crate::GraftTestHarness {\n");
    let mut first = true;
    for graft in &loaded.bindings.grafts {
        if graft.pokes.is_empty() {
            continue;
        }
        if !first {
            s.push_str("\n");
        }
        first = false;
        s.push_str(&format!(
            "    // -- {}-graft -----------------------------------------------------\n\n",
            graft.name
        ));
        for poke in &graft.pokes {
            emit_poke_method(&mut s, poke);
        }
    }
    s.push_str("}\n");

    s
}

/// One generated method on `GraftTestHarness` per `[[graft.pokes]]`
/// entry. The body delegates to the existing `vesl_core::<builder>`
/// function and routes its `NounSlab` through `poke_slab`, which
/// returns the typed `PokeOutcome`.
fn emit_poke_method(s: &mut String, poke: &HarnessPoke) {
    s.push_str(&format!(
        "    /// Send `[%{tag} ...]`. Delegates to `vesl_core::{builder}`.\n",
        tag = poke.tag,
        builder = poke.builder,
    ));

    let mut params = String::new();
    let mut forwards = String::new();
    for (i, arg) in poke.args.iter().enumerate() {
        if i > 0 {
            params.push_str(", ");
            forwards.push_str(", ");
        }
        params.push_str(&format!("{}: {}", arg.name, arg.rust));
        forwards.push_str(&arg.name);
    }
    let sep = if poke.args.is_empty() { "" } else { ", " };
    s.push_str(&format!(
        "    pub async fn {method}(&mut self{sep}{params}) \
         -> anyhow::Result<vesl_core::PokeOutcome> {{\n",
        method = poke.method,
    ));
    s.push_str(&format!(
        "        let slab = vesl_core::{builder}({forwards});\n",
        builder = poke.builder,
    ));
    s.push_str("        self.poke_slab(slab).await\n");
    s.push_str("    }\n\n");
}

/// `pub enum <Graft>Outcome { Accepted, Error{msg}, <RejectedVariants>,
/// Denied{reason}, Unknown, Crashed }` — typed surface over the generic
/// `PokeOutcome`. Generated when the graft declares any error /
/// rejected / denied tag in the sidecar.
fn emit_outcome_enum(s: &mut String, graft: &HarnessGraftBindings) {
    let pascal = pascal_case(&graft.name);
    s.push_str(&format!("/// Typed outcome for `{}-graft` pokes.\n", graft.name));
    s.push_str("///\n");
    s.push_str("/// Decoded by [`PokeOutcome::");
    s.push_str(&format!("as_{}_outcome`]", graft.name));
    s.push_str(&format!(" (see [`{pascal}OutcomeExt`]).\n"));
    s.push_str("/// Use to pattern-match on the specific rejection variant the\n");
    s.push_str("/// kernel produced — `Error { msg }` for the generic cord-typed\n");
    s.push_str("/// kernel error, named struct variants for typed rejections,\n");
    s.push_str("/// `Denied { reason }` for gate-clean-deny.\n");
    s.push_str("#[derive(Debug)]\n");
    s.push_str(&format!("pub enum {pascal}Outcome {{\n"));
    s.push_str("    /// Kernel accepted the poke. `effect_tags` are the head\n");
    s.push_str("    /// tags of every emitted effect — typically a single\n");
    s.push_str("    /// `*-accepted` or graft-specific success tag.\n");
    s.push_str("    Accepted { effect_tags: Vec<String> },\n");

    // [%<graft>-error msg=@t]
    if !graft.errors.is_empty() {
        s.push_str("    /// `[%<graft>-error msg=@t]` — cord-typed kernel error.\n");
        s.push_str("    Error { msg: String },\n");
    }

    // [%<graft>-..-rejected ...]
    for rej in &graft.rejected {
        let variant = pascal_case(strip_graft_prefix(&rej.tag, &graft.name));
        s.push_str(&format!("    /// `[%{tag} ...]` — typed rejection.\n", tag = rej.tag));
        if rej.fields.is_empty() {
            s.push_str(&format!("    {variant},\n"));
        } else {
            s.push_str(&format!("    {variant} {{\n"));
            for f in &rej.fields {
                s.push_str(&format!("        {}: {},\n", f.name, f.rust));
            }
            s.push_str("    },\n");
        }
    }

    // [%<graft>-denied reason=@t]
    if !graft.denied.is_empty() {
        s.push_str("    /// `[%<graft>-denied reason=@t]` — gate-clean-deny.\n");
        s.push_str("    Denied { reason: String },\n");
    }

    s.push_str("    /// Kernel emitted no effects (collapses to\n");
    s.push_str("    /// `RejectionReason::Unknown`) or an RBAC pre-check denied\n");
    s.push_str("    /// the poke before it reached the kernel.\n");
    s.push_str("    Unknown,\n");
    s.push_str("    /// Driver-level failure (timeout, NockAppError, protocol\n");
    s.push_str("    /// violation). Mirrors `PokeOutcome::Crashed`.\n");
    s.push_str("    Crashed,\n");
    s.push_str("}\n\n");
}

/// `pub trait <Graft>OutcomeExt { fn as_<graft>_outcome(&self) ->
/// <Graft>Outcome; }` plus its `impl for vesl_core::PokeOutcome`. The
/// decoder walks the existing `PokeOutcome` shape and routes by
/// suffix-rules already enshrined in `classify_effects`:
///
/// - `Accepted { effects }` → `<Graft>Outcome::Accepted { effect_tags }`
/// - `Rejected { reason: KernelError { cord, .. } }` → `Error { msg }`
///   (only when the cord starts with `<graft>-graft:` so we don't pick
///   up another graft's error)
/// - `Rejected { reason: KernelRejected { tag, raw_effects } }` →
///   the named typed-rejection variant when the tag matches one of the
///   graft's declared `[[graft.rejected]]` entries
/// - `Rejected { reason: GateDenied { reason, .. } }` → `Denied { reason }`
///   (only when the tag matches the graft's `[[graft.denied]]`)
/// - everything else → `Unknown` / `Crashed`
fn emit_outcome_ext_trait(s: &mut String, graft: &HarnessGraftBindings) {
    let pascal = pascal_case(&graft.name);
    let trait_name = format!("{pascal}OutcomeExt");
    let method = format!("as_{}_outcome", graft.name);
    let outcome = format!("{pascal}Outcome");

    s.push_str(&format!("/// Extension trait — decodes a [`vesl_core::PokeOutcome`] into a\n"));
    s.push_str(&format!("/// typed [`{outcome}`] when the underlying effect came from\n"));
    s.push_str(&format!("/// `{}-graft`. Other grafts' effects collapse to\n", graft.name));
    s.push_str(&format!("/// [`{outcome}::Unknown`].\n"));
    s.push_str(&format!("pub trait {trait_name} {{\n"));
    s.push_str(&format!("    fn {method}(&self) -> {outcome};\n"));
    s.push_str("}\n\n");

    s.push_str(&format!("impl {trait_name} for vesl_core::PokeOutcome {{\n"));
    s.push_str(&format!("    fn {method}(&self) -> {outcome} {{\n"));
    s.push_str("        match self {\n");
    s.push_str("            vesl_core::PokeOutcome::Accepted { effects } => {\n");
    s.push_str(&format!(
        "                {outcome}::Accepted {{\n",
    ));
    s.push_str("                    effect_tags: vesl_core::effect_head_tags(effects),\n");
    s.push_str("                }\n");
    s.push_str("            }\n");

    // KernelError { cord, raw_effects } — only when cord starts with `<graft>-graft:`
    if !graft.errors.is_empty() {
        let prefix = format!("{}-graft:", graft.name);
        s.push_str("            vesl_core::PokeOutcome::Rejected {\n");
        s.push_str("                reason: vesl_core::RejectionReason::KernelError { cord, .. },\n");
        s.push_str(&format!(
            "            }} if cord.starts_with({prefix:?}) => {{\n"
        ));
        s.push_str(&format!("                {outcome}::Error {{ msg: cord.clone() }}\n"));
        s.push_str("            }\n");
    }

    // KernelRejected { tag, raw_effects } — one match arm per declared rejection
    for rej in &graft.rejected {
        let variant = pascal_case(strip_graft_prefix(&rej.tag, &graft.name));
        s.push_str("            vesl_core::PokeOutcome::Rejected {\n");
        s.push_str("                reason: vesl_core::RejectionReason::KernelRejected { tag, raw_effects },\n");
        s.push_str(&format!(
            "            }} if tag == {tag:?} => {{\n",
            tag = rej.tag,
        ));
        if rej.fields.is_empty() {
            s.push_str(&format!("                let _ = raw_effects; {outcome}::{variant}\n"));
        } else {
            // For typed-rejection field decoding, default to a heuristic
            // that consumers extend in v2.0 (the current cut surfaces
            // raw_effects so callers can decode by hand if they need the
            // typed fields). The variant is constructed with default
            // values for primitives and empty for owned types; consumers
            // pattern-match on the variant for routing and reach for
            // raw_effects when they need the bound fields.
            s.push_str("                let _ = raw_effects;\n");
            s.push_str(&format!("                {outcome}::{variant} {{\n"));
            for f in &rej.fields {
                s.push_str(&format!(
                    "                    {name}: {default},\n",
                    name = f.name,
                    default = default_value_for(&f.rust),
                ));
            }
            s.push_str("                }\n");
        }
        s.push_str("            }\n");
    }

    // GateDenied — only when graft declared a denied tag
    if !graft.denied.is_empty() {
        let prefix = format!("{}-graft:", graft.name);
        s.push_str("            vesl_core::PokeOutcome::Rejected {\n");
        s.push_str("                reason: vesl_core::RejectionReason::GateDenied { reason, .. },\n");
        s.push_str(&format!(
            "            }} if reason.starts_with({prefix:?}) => {{\n"
        ));
        s.push_str(&format!("                {outcome}::Denied {{ reason: reason.clone() }}\n"));
        s.push_str("            }\n");
    }

    s.push_str("            vesl_core::PokeOutcome::Rejected {\n");
    s.push_str("                reason: vesl_core::RejectionReason::Unknown\n");
    s.push_str("                    | vesl_core::RejectionReason::RbacDenied { .. },\n");
    s.push_str(&format!("            }} => {outcome}::Unknown,\n"));
    s.push_str(&format!(
        "            vesl_core::PokeOutcome::Crashed {{ .. }} => {outcome}::Crashed,\n",
    ));
    // Fallthrough catches: KernelError/KernelRejected/GateDenied whose
    // cord/tag didn't match this graft — they belong to a different
    // graft's namespace.
    s.push_str(&format!("            _ => {outcome}::Unknown,\n"));
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");
}

fn graft_has_typed_outcome(graft: &HarnessGraftBindings) -> bool {
    !graft.errors.is_empty() || !graft.rejected.is_empty() || !graft.denied.is_empty()
}

/// Walk every arg's rust-type string and figure out which `use` lines
/// the generated file needs. Known non-primitive idents:
/// `Tip5Hash`, `ValidateRule`, `ProofNode`, `NounSlab`.
fn collect_used_types(loaded: &LoadedHarnessBindings) -> Vec<&'static str> {
    let candidates = ["Tip5Hash", "ValidateRule", "ProofNode", "NounSlab"];
    let mut out: Vec<&'static str> = Vec::new();
    for graft in &loaded.bindings.grafts {
        for poke in &graft.pokes {
            for arg in &poke.args {
                for cand in &candidates {
                    if arg.rust.contains(cand) && !out.contains(cand) {
                        out.push(*cand);
                    }
                }
            }
        }
        for rej in &graft.rejected {
            for field in &rej.fields {
                for cand in &candidates {
                    if field.rust.contains(cand) && !out.contains(cand) {
                        out.push(*cand);
                    }
                }
            }
        }
    }
    out.sort();
    out
}

fn render_use_line(ident: &str) -> String {
    match ident {
        "Tip5Hash" | "ValidateRule" | "ProofNode" => {
            format!("use vesl_core::{ident};\n")
        }
        "NounSlab" => "use nock_noun_rs::NounSlab;\n".to_string(),
        _ => String::new(),
    }
}

/// `counter-set` → `CounterSet`, `settle-register-rejected` →
/// `SettleRegisterRejected`. Splits on `-`, capitalizes each segment.
fn pascal_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split('-') {
        let mut chars = word.chars();
        if let Some(c) = chars.next() {
            out.extend(c.to_uppercase());
        }
        for c in chars {
            out.push(c);
        }
    }
    out
}

/// Strip a leading `<graft>-` prefix from a tag. `settle-register-rejected`
/// against graft `settle` becomes `register-rejected`. Leaves unmatched
/// tags untouched so the resulting variant name is always something.
fn strip_graft_prefix<'a>(tag: &'a str, graft_name: &str) -> &'a str {
    let prefix = format!("{graft_name}-");
    tag.strip_prefix(&prefix).unwrap_or(tag)
}

/// Default value for a Rust type, used when constructing typed rejection
/// variants whose field decoding is deferred to v2.0. Conservative:
/// returns `String::new()`, `0`, `Vec::new()` for the common shapes; an
/// unrecognized type falls back to `Default::default()` which compiles
/// for any `Default`-bound type and fails loudly for one that isn't.
fn default_value_for(rust: &str) -> &'static str {
    let t = rust.trim();
    match t {
        "String" => "String::new()",
        "u64" | "u32" | "u16" | "u8" => "0",
        "Vec<u8>" => "Vec::new()",
        _ => "Default::default()",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::inject;
    use crate::manifest::discover_grafts;
    use crate::test_support::*;
    use std::fs;
    use std::path::PathBuf;

    // ---------------------------------------------------------------
    // kernel-cause-tags emission
    // ---------------------------------------------------------------

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
