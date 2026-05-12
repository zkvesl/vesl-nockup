//! Typed effect-union, load-defaults overlay, and kernel-cause-tags
//! codegen passes.
//!
//! Audit §3.2 extraction. These passes synthesize Hoon (or Rust, in the
//! cause-tags case) at codegen-owned banner pairs in the composed
//! source. The lint suite consumes their report variant lists and
//! rendered output by reference — there's no hidden state coupling, so
//! the two layers split cleanly.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fs;
use std::path::Path;

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

/// RM4 §1 v0.2: outcome of the load-defaults codegen pass. Mirrors
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
/// Closes RM1 HARD-BUG-3 (kernel rename leaves driver pointing at a
/// dead tag) and HARD-FRICTION-4 (driver tag with no kernel arm) by
/// shifting the failure left from "no effects observed at runtime" to
/// `cargo build` errors.
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
    // load-defaults overlay codegen (RM4 §1 v0.2)
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
