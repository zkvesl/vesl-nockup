//! `doctor` — project-health checks, surfaced both explicitly
//! (`nockup graft doctor`) and ambiently (the scaffold `build.rs` runs
//! it on every `cargo build`).
//!
//! Four checks, each a pure function returning `Vec<DoctorFinding>`:
//!
//!   1. schema-version handshake — a graft manifest authored for a
//!      newer nockup-graft (`manifest::check_schema_compat`).
//!   2. Cargo `[patch]` / nockchain-rev consistency — a `Cargo.toml`
//!      that pins more than one nockchain rev (the partial-update state
//!      that surfaces later as the `ibig` / `UBig` build failure).
//!   3. hand-edited injected blocks — a banner-bounded block whose
//!      content no longer matches what its manifest would render, while
//!      the banner sha still matches the manifest (so this is not
//!      manifest drift, which `inject` already re-injects).
//!   4. a missing `nockup:load-defaults` marker on a grafted kernel.
//!
//! Reuses the `lint.rs` shape: per-finding `Serialize` structs, a JSON
//! report, a stderr printer, and a nonzero exit when findings fire.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::inject::expected_block_body;
use crate::manifest::{Graft, check_schema_compat, discover_grafts};
use crate::marker::{Marker, banner_sha256, find_banner_pair, find_marker, leading_whitespace};

/// Markers whose injected block is a verbatim indented paste of the
/// manifest body (`emit_block`), so the live block can be compared
/// byte-for-byte against `expected_block_body`. `imports` (deduped by
/// `emit_imports_block`) and `peek` (wrapped into a chain by
/// `emit_peek_chain`) legitimately diverge from a plain render and are
/// excluded; the codegen markers carry no per-graft block at all.
const HAND_EDIT_MARKERS: [Marker; 5] = [
    Marker::State,
    Marker::Cause,
    Marker::PokePrelude,
    Marker::Poke,
    Marker::PokePostlude,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorSeverity {
    Error,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorCheck {
    SchemaVersion,
    PatchConsistency,
    HandEditedBlock,
    MissingLoadDefaults,
}

impl DoctorCheck {
    fn label(self) -> &'static str {
        match self {
            Self::SchemaVersion => "schema-version",
            Self::PatchConsistency => "patch-consistency",
            Self::HandEditedBlock => "hand-edited-block",
            Self::MissingLoadDefaults => "missing-load-defaults",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DoctorFinding {
    pub(crate) check: DoctorCheck,
    pub(crate) severity: DoctorSeverity,
    /// One-line summary — also the body of a `build-warnings` line.
    pub(crate) message: String,
    /// Optional `file` or `file:line` anchor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
    /// Longer remediation text. Human format only — dropped from the
    /// `build-warnings` surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}

/// JSON document for `doctor --json`. Stable schema — append top-level
/// keys (or `DoctorCheck` variants), never reshape, mirroring the
/// `--list --json` and `lint --json` contracts.
#[derive(Debug, Serialize)]
struct DoctorReport<'a> {
    findings: &'a [DoctorFinding],
}

/// `doctor`'s text output mode. `--json` (on `Human`) overrides to a
/// JSON report; `BuildWarnings` always wins and always exits 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum DoctorFormat {
    /// Grouped, explanatory stderr — the default for a human run.
    Human,
    /// One `doctor: <message>` line per finding to stdout, no banners,
    /// no `detail`, always exit 0. The scaffold `build.rs` captures
    /// these and forwards each as a `cargo:warning=`.
    BuildWarnings,
}

/// `doctor` CLI entry point. Runs the four checks and emits per `format`
/// (`--json` overrides the `human` text form). Exits nonzero on findings
/// for the human/json surfaces so CI can gate on it; `build-warnings`
/// always returns `Ok` so the scaffold `build.rs` never fails the build.
pub(crate) fn run_doctor(
    path: &Path,
    lib_dir: &Path,
    json: bool,
    format: DoctorFormat,
) -> Result<()> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("hoon") => {}
        Some(other) => bail!(
            "target {} has extension `.{}`; doctor only runs on Hoon source files",
            path.display(),
            other,
        ),
        None => bail!(
            "target {} has no file extension; doctor only runs on Hoon source files",
            path.display(),
        ),
    }
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Discover grafts when --lib-dir exists; skip the manifest-dependent
    // checks gracefully when it doesn't (mirrors run_lint). discover_grafts
    // stays schema-agnostic, so a future-schema manifest is reported by
    // check_schema rather than killing discovery here.
    let grafts = if lib_dir.is_dir() {
        discover_grafts(lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?
    } else {
        Vec::new()
    };

    let findings = collect_findings(path, &source, &grafts);

    match format {
        DoctorFormat::BuildWarnings => {
            emit_build_warnings(&findings);
            Ok(())
        }
        DoctorFormat::Human => {
            if json {
                emit_json(&findings);
            } else {
                emit_human(path, &findings);
            }
            if findings.is_empty() {
                Ok(())
            } else {
                bail!("graft-inject doctor: {} finding(s) above", findings.len())
            }
        }
    }
}

/// Run all four checks and return the findings — the shared substrate
/// behind both `run_doctor` and `update`'s pre-apply preview.
pub(crate) fn collect_findings(
    path: &Path,
    source: &str,
    grafts: &[Graft],
) -> Vec<DoctorFinding> {
    let project_root = resolve_project_root(path);
    let mut findings: Vec<DoctorFinding> = Vec::new();
    findings.extend(check_schema(grafts));
    findings.extend(check_patch_consistency(project_root.as_deref()));
    findings.extend(check_hand_edits(path, source, grafts));
    findings.extend(check_load_defaults_marker(path, source));
    findings
}

/// Walk up from the kernel file (canonicalized) to the project root —
/// the directory holding `nockapp.toml` — falling back to the current
/// directory. `None` when neither route finds a project, in which case
/// the `[patch]`-consistency check degrades to a no-op.
fn resolve_project_root(path: &Path) -> Option<PathBuf> {
    if let Ok(abs) = path.canonicalize() {
        if let Some(root) = abs.parent().and_then(crate::cli::find_project_root) {
            return Some(root);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    crate::cli::find_project_root(&cwd)
}

/// Check 1 — manifest-schema handshake (failure mode 3.2).
fn check_schema(grafts: &[Graft]) -> Vec<DoctorFinding> {
    check_schema_compat(grafts)
        .into_iter()
        .map(|s| DoctorFinding {
            check: DoctorCheck::SchemaVersion,
            severity: DoctorSeverity::Error,
            message: format!(
                "graft `{}` targets manifest schema_version {} but this \
                 nockup-graft supports up to {}",
                s.graft, s.manifest_version, s.binary_version,
            ),
            location: None,
            detail: Some(
                "Update the binary: cargo install --git \
                 https://github.com/zkvesl/vesl-nockup --bin nockup-graft --force"
                    .to_string(),
            ),
        })
        .collect()
}

/// Recursively collect every `rev` declared on a git-dependency whose
/// `git` URL names nockchain. Walks all tables uniformly, so
/// `[dependencies]`, `[dev-dependencies]`, `[target.*]`, and
/// `[patch."…"]` are all covered.
fn collect_nockchain_revs(value: &toml::Value, out: &mut BTreeSet<String>) {
    match value {
        toml::Value::Table(table) => {
            let git = table.get("git").and_then(toml::Value::as_str);
            let rev = table.get("rev").and_then(toml::Value::as_str);
            if let (Some(git), Some(rev)) = (git, rev) {
                if git.contains("nockchain") {
                    out.insert(rev.to_string());
                }
            }
            for v in table.values() {
                collect_nockchain_revs(v, out);
            }
        }
        toml::Value::Array(arr) => {
            for v in arr {
                collect_nockchain_revs(v, out);
            }
        }
        _ => {}
    }
}

/// Check 2 — Cargo `[patch]` / nockchain-rev consistency (failure mode
/// 3.5). Flags a project `Cargo.toml` that pins more than one distinct
/// nockchain rev — the partial-update state that surfaces later as the
/// `ibig` / `UBig` type mismatch on `cargo build`. When the project
/// root or `Cargo.toml` cannot be read or parsed, emits nothing: this
/// check false-negatives rather than false-positives.
fn check_patch_consistency(project_root: Option<&Path>) -> Vec<DoctorFinding> {
    let Some(root) = project_root else {
        return Vec::new();
    };
    let cargo_toml = root.join("Cargo.toml");
    let Ok(raw) = std::fs::read_to_string(&cargo_toml) else {
        return Vec::new();
    };
    let Ok(value) = raw.parse::<toml::Value>() else {
        return Vec::new();
    };
    let mut revs = BTreeSet::new();
    collect_nockchain_revs(&value, &mut revs);
    if revs.len() <= 1 {
        return Vec::new();
    }
    let list: Vec<&str> = revs.iter().map(String::as_str).collect();
    vec![DoctorFinding {
        check: DoctorCheck::PatchConsistency,
        severity: DoctorSeverity::Warn,
        message: format!(
            "Cargo.toml pins {} different nockchain revs ({}); cargo build \
             may fail on an ibig/UBig type mismatch",
            revs.len(),
            list.join(", "),
        ),
        location: Some("Cargo.toml".to_string()),
        detail: Some(
            "Realign every nockchain git-dep and the [patch] block to one \
             rev. See the vesl-nockup README, \"Updating an existing project\"."
                .to_string(),
        ),
    }]
}

/// Check 3 — hand-edited injected blocks (failure mode 3.1, detection
/// only). For each graft and each covered marker whose banner pair is
/// present and whose banner sha still matches the manifest, compares the
/// lines between the banners against what the manifest would render now.
/// A mismatch means the block was edited in place — the next
/// `inject --apply` that re-injects it will silently overwrite the edit.
fn check_hand_edits(path: &Path, source: &str, grafts: &[Graft]) -> Vec<DoctorFinding> {
    let lines: Vec<String> = source.lines().map(String::from).collect();
    let mut findings = Vec::new();
    for g in grafts {
        for marker in HAND_EDIT_MARKERS {
            if g.block(marker).is_none() {
                continue;
            }
            let Some((begin, end)) = find_banner_pair(&lines, &g.name, marker) else {
                continue; // graft not injected at this marker — nothing to compare
            };
            // Only flag the up-to-date case. A banner sha that differs
            // from the manifest is manifest drift, which `inject` already
            // re-injects; a legacy banner (no sha) likewise force-reinjects.
            match banner_sha256(&lines[begin]) {
                Some(sha) if sha == g.sha256_short() => {}
                _ => continue,
            }
            let indent = leading_whitespace(&lines[begin]).to_string();
            let expected = expected_block_body(g, marker, &indent);
            let actual: Vec<String> = lines[begin + 1..end].to_vec();
            if actual != expected {
                findings.push(DoctorFinding {
                    check: DoctorCheck::HandEditedBlock,
                    severity: DoctorSeverity::Warn,
                    message: format!(
                        "graft `{}` block `{}` has been hand-edited; the next \
                         `nockup graft inject --apply` that re-injects it will \
                         overwrite the edit",
                        g.name,
                        marker.label(),
                    ),
                    location: Some(format!("{}:{}", path.display(), begin + 1)),
                    detail: Some(
                        "Move the customization out of the banner pair, or \
                         drive it through the graft manifest. See the \
                         vesl-nockup README, \"Re-injection is not a merge\"."
                            .to_string(),
                    ),
                });
            }
        }
    }
    findings
}

/// Check 4 — missing `nockup:load-defaults` marker (failure mode 3.3).
/// A grafted kernel without the marker has no defaults overlay in
/// `++load`, so a schema-extension resume silently drops effects for
/// grafts past the first added priority band. Fires only when the kernel
/// actually carries injected grafts — a bare scaffold has no resume
/// concern yet.
fn check_load_defaults_marker(path: &Path, source: &str) -> Vec<DoctorFinding> {
    let lines: Vec<String> = source.lines().map(String::from).collect();
    let has_grafts = lines
        .iter()
        .any(|l| l.contains("graft-inject:") && l.contains(":begin"));
    if !has_grafts {
        return Vec::new();
    }
    if matches!(find_marker(&lines, Marker::LoadDefaults), Ok(Some(_))) {
        return Vec::new();
    }
    vec![DoctorFinding {
        check: DoctorCheck::MissingLoadDefaults,
        severity: DoctorSeverity::Warn,
        message: format!(
            "{} has no `::  nockup:load-defaults` marker; a schema-extension \
             resume will silently drop effects for grafts past the first \
             added priority band",
            path.display(),
        ),
        location: Some(path.display().to_string()),
        detail: Some(
            "Add the marker next to `++load`. The current scaffold template \
             ships it — copying the `++load` region from templates/app.hoon \
             is the simplest fix."
                .to_string(),
        ),
    }]
}

/// `build-warnings` surface: one bare line per finding to stdout, for
/// the scaffold `build.rs` to forward as `cargo:warning=`.
fn emit_build_warnings(findings: &[DoctorFinding]) {
    for f in findings {
        match &f.location {
            Some(loc) => println!("doctor: {} [{}]", f.message, loc),
            None => println!("doctor: {}", f.message),
        }
    }
}

/// `--json` surface: the stable `DoctorReport` document to stdout.
fn emit_json(findings: &[DoctorFinding]) {
    let report = DoctorReport { findings };
    let s = serde_json::to_string_pretty(&report).expect("DoctorReport always serializes");
    println!("{s}");
}

/// Default human surface: a grouped, explanatory report to stderr.
/// Also the findings block of `update`'s pre-apply preview.
pub(crate) fn emit_human(path: &Path, findings: &[DoctorFinding]) {
    eprintln!(
        "graft-inject doctor: {} ({} finding(s))",
        path.display(),
        findings.len(),
    );
    if findings.is_empty() {
        eprintln!("  no findings — project looks healthy");
        return;
    }
    for f in findings {
        let sev = match f.severity {
            DoctorSeverity::Error => "error",
            DoctorSeverity::Warn => "warn",
        };
        eprintln!("  [{sev}] {}: {}", f.check.label(), f.message);
        if let Some(loc) = &f.location {
            eprintln!("        at {loc}");
        }
        if let Some(detail) = &f.detail {
            eprintln!("        {detail}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_nockchain_revs_gathers_distinct_revs() {
        let cargo = r#"
[dependencies]
nockapp = { git = "https://github.com/nockchain/nockchain.git", rev = "aaaa" }
nockvm = { git = "https://github.com/nockchain/nockchain.git", rev = "bbbb" }
serde = "1"

[patch."https://github.com/nockchain/nockchain.git"]
ibig = { git = "https://github.com/nockchain/nockchain.git", rev = "aaaa" }
"#;
        let value: toml::Value = cargo.parse().unwrap();
        let mut revs = BTreeSet::new();
        collect_nockchain_revs(&value, &mut revs);
        assert_eq!(revs.len(), 2, "two distinct nockchain revs, got {revs:?}");
        assert!(revs.contains("aaaa") && revs.contains("bbbb"));
    }

    #[test]
    fn collect_nockchain_revs_ignores_non_nockchain_git_deps() {
        let cargo = r#"
[dependencies]
other = { git = "https://github.com/example/other.git", rev = "ffff" }
"#;
        let value: toml::Value = cargo.parse().unwrap();
        let mut revs = BTreeSet::new();
        collect_nockchain_revs(&value, &mut revs);
        assert!(revs.is_empty(), "non-nockchain git deps must be ignored");
    }

    #[test]
    fn patch_consistency_silent_without_project_root() {
        assert!(check_patch_consistency(None).is_empty());
    }
}
