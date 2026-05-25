//! `graft-inject codegen kernel-cause-tags` — read the composed cause
//! `$%(...)` union plus every active graft's poke arms, emit a
//! Rust `KERNEL_CAUSE_TAGS: &[&str]` slice and the matching
//! `assert_kernel_cause_tag!` macro.
//!
//! Shifts two failures left to `cargo build` errors: a kernel rename
//! that leaves the driver pointing at a dead tag, and a driver tag
//! with no matching kernel arm — both otherwise surface only as
//! "no effects observed at runtime".

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::lint::{CauseUnionMember, extract_cause_union_members, extract_graft_cause_tags};
use crate::manifest::{discover_grafts, sha256_hex};

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
pub(super) struct CodegenTagsJson<'a> {
    pub(super) source: String,
    pub(super) source_sha256: &'a str,
    pub(super) kernel_cause_tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
