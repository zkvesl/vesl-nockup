//! graft-inject: auto-wire vesl-flavored grafts into a nockup app.hoon
//! kernel.
//!
//! Discovers graft manifests under `--lib-dir` (default `./hoon/lib/`),
//! composes their blocks at the `::  nockup:{imports,state,cause,poke,peek}`
//! markers, and writes the result back. Idempotent per graft per marker.
//!
//! See `--help` for full CLI surface.

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MARKER_PREFIX: &str = "::  nockup:";
const DEFAULT_LIB_DIR: &str = "hoon/lib";

// ---------------------------------------------------------------------------
// Manifest schema (graft.toml)
// ---------------------------------------------------------------------------

/// Top-level wrapper for the `[graft]` table in a manifest file.
#[derive(Debug, Clone, Deserialize)]
struct ManifestFile {
    graft: Graft,
}

/// A discovered graft package — identity, ordering, and per-marker blocks.
#[derive(Debug, Clone, Deserialize)]
struct Graft {
    name: String,
    #[allow(dead_code)] // surfaced via --list in Phase 6
    version: String,
    priority: i32,
    #[serde(default)]
    after: Vec<String>,
    blocks: GraftBlocks,
    /// Hex sha256 of the raw TOML bytes. Populated by `load_manifest` at
    /// discovery time so the composer can surface per-manifest digests
    /// in the preview report and `--list --json` output (AUDIT 2026-04-19
    /// H-10 supply-chain surface).
    #[serde(skip, default)]
    sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GraftBlocks {
    imports: Option<Block>,
    state: Option<Block>,
    cause: Option<Block>,
    poke: Option<Block>,
    peek: Option<Block>,
}

#[derive(Debug, Clone, Deserialize)]
struct Block {
    // Retained in the schema for manifest authors to document intent;
    // idempotence switched from sentinel-substring matching to
    // `::  graft-inject:<name>:begin` banner comments in AUDIT
    // 2026-04-19 (H-11..H-14).
    #[allow(dead_code)]
    sentinel: String,
    body: String,
}

impl Block {
    /// Composition-ready body — leading and trailing newlines stripped so
    /// the inject step's indent-prepending lands on the first content line.
    fn trimmed_body(&self) -> &str {
        self.body.trim_matches('\n')
    }
}

impl Graft {
    /// Block for a marker, if the manifest declares one.
    #[allow(dead_code)] // consumed by the data-driven inject() in Phase 4
    fn block(&self, marker: Marker) -> Option<&Block> {
        match marker {
            Marker::Imports => self.blocks.imports.as_ref(),
            Marker::State => self.blocks.state.as_ref(),
            Marker::Cause => self.blocks.cause.as_ref(),
            Marker::Poke => self.blocks.poke.as_ref(),
            Marker::Peek => self.blocks.peek.as_ref(),
        }
    }
}

/// Load a single `*.toml` manifest. Returns Ok(None) if the file lacks a
/// `[graft]` table (caller skips it); Err for parse or I/O failures.
/// Populates `Graft::sha256` from the raw file bytes so downstream code
/// can surface provenance without reopening the file.
fn load_manifest(path: &Path) -> Result<Option<Graft>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    if value.get("graft").is_none() {
        return Ok(None);
    }
    let manifest: ManifestFile = toml::from_str(&raw)
        .with_context(|| format!("deserializing manifest {}", path.display()))?;
    let mut graft = manifest.graft;
    graft.sha256 = sha256_hex(raw.as_bytes());
    Ok(Some(graft))
}

/// Lowercase-hex sha256 digest of the given bytes.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Scan `lib_dir` for `*.toml` files and return loaded grafts in priority
/// order, ties broken by name. Files lacking a `[graft]` table are skipped
/// silently. Validates that every `after` hint names a discovered graft,
/// rejects duplicate graft names (AUDIT 2026-04-19 H-11), and rejects
/// graft names that don't match the kebab-case shape the schema documents.
fn discover_grafts(lib_dir: &Path) -> Result<Vec<Graft>> {
    let mut grafts: Vec<Graft> = Vec::new();
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    let entries = fs::read_dir(lib_dir)
        .with_context(|| format!("scanning {}", lib_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Some(g) = load_manifest(&path)? {
                if !is_valid_graft_name(&g.name) {
                    bail!(
                        "invalid graft name `{}` in {}: expected kebab-case \
                         matching ^[a-z][a-z0-9-]*$",
                        g.name,
                        path.display()
                    );
                }
                if let Some(prev) = seen.get(&g.name) {
                    bail!(
                        "duplicate graft name `{}` in {} and {}",
                        g.name,
                        prev.display(),
                        path.display()
                    );
                }
                seen.insert(g.name.clone(), path.clone());
                grafts.push(g);
            }
        }
    }
    grafts.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(&b.name)));
    let names: HashSet<&str> = grafts.iter().map(|g| g.name.as_str()).collect();
    for g in &grafts {
        for hint in &g.after {
            if !names.contains(hint.as_str()) {
                bail!(
                    "graft `{}` declares after = [\"{}\"], but no such graft was discovered",
                    g.name,
                    hint
                );
            }
        }
    }
    Ok(grafts)
}

/// Kebab-case validator. Names are interpolated into emitted banner
/// comments and into filesystem paths elsewhere — rejecting `.`/`/` keeps
/// a hostile manifest from injecting banner-collision or path-traversal
/// shapes through the name field.
fn is_valid_graft_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    Imports,
    State,
    Cause,
    Poke,
    Peek,
}

impl Marker {
    const ALL: [Marker; 5] = [
        Marker::Imports,
        Marker::State,
        Marker::Cause,
        Marker::Poke,
        Marker::Peek,
    ];

    #[cfg(test)]
    fn parse(name: &str) -> Option<Self> {
        match name {
            "imports" => Some(Self::Imports),
            "state" => Some(Self::State),
            "cause" => Some(Self::Cause),
            "poke" => Some(Self::Poke),
            "peek" => Some(Self::Peek),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::State => "state",
            Self::Cause => "cause",
            Self::Poke => "poke",
            Self::Peek => "peek",
        }
    }
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
                },
            )
        })
        .collect();

    for marker in Marker::ALL {
        match find_marker(&lines, marker)? {
            Some(idx) => {
                markers_in_source.push(marker);
                let indent = leading_whitespace(&lines[idx]).to_string();
                let mut pending: Vec<&Graft> = Vec::new();
                for g in grafts {
                    if g.block(marker).is_none() {
                        continue;
                    }
                    if already_wired(&lines, &g.name, marker) {
                        per_graft.get_mut(&g.name).unwrap().skipped.push(marker);
                    } else {
                        pending.push(g);
                    }
                }
                if pending.is_empty() {
                    continue;
                }
                match marker {
                    Marker::Peek => {
                        emit_peek_chain(&mut lines, idx, &indent, &pending);
                    }
                    _ => {
                        emit_block(&mut lines, idx, &indent, marker, &pending);
                    }
                }
                for g in &pending {
                    per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                }
            }
            None => {
                markers_missing.push(marker);
            }
        }
    }

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
        },
    ))
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
        composed.push(begin_banner(&g.name, marker));
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

/// Begin/end banner strings for per-graft-per-marker idempotence. Emitted
/// indented to match the marker's leading whitespace; the trimmed form is
/// what `already_wired` matches on.
fn begin_banner(name: &str, marker: Marker) -> String {
    format!("::  graft-inject:{}:{}:begin", name, marker.label())
}

fn end_banner(name: &str, marker: Marker) -> String {
    format!("::  graft-inject:{}:{}:end", name, marker.label())
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
                format!("{indent}{}", begin_banner(&g.name, Marker::Peek)),
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

fn find_marker(lines: &[String], marker: Marker) -> Result<Option<usize>> {
    let needle = format!("{}{}", MARKER_PREFIX, marker.label());
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Two-space law: the marker comment must be `::  nockup:<name>`.
        // We accept trailing whitespace and require exact prefix match.
        if trimmed.starts_with(&needle) {
            // Ensure the character right after the marker name is either
            // end-of-line or whitespace — guards against `nockup:pokemon`
            // swallowing a poke match.
            let tail = &trimmed[needle.len()..];
            if tail.is_empty() || tail.chars().all(|c| c.is_whitespace()) {
                return Ok(Some(i));
            }
        }
    }
    Ok(None)
}

fn leading_whitespace(s: &str) -> &str {
    let end = s
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

/// Per-graft-per-marker idempotence check: is `graft_name` wired at
/// `marker` somewhere in the file?
///
/// AUDIT 2026-04-19 H-11..H-14: the pre-audit implementation walked a
/// marker window for the graft's sentinel string. That had three
/// failure modes — cross-graft false positives (A's body containing B's
/// sentinel), peek-chain overflow past the 10-line window at 6+ grafts,
/// and early termination on an inner `==` inside any poke body. A banner
/// comment emitted alongside each injected block is an exact-match
/// invariant that removes all three footguns: it appears iff the
/// specific graft has been injected at this specific marker, it's never
/// a substring of any body, and a file-wide scan doesn't care how far
/// the expanding poke switch has pushed it.
fn already_wired(lines: &[String], graft_name: &str, marker: Marker) -> bool {
    let needle = begin_banner(graft_name, marker);
    lines.iter().any(|l| l.trim() == needle)
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

#[derive(Parser, Debug)]
#[command(
    name = "graft-inject",
    version,
    about = "Compose vesl-flavored grafts into a nockup app.hoon kernel",
    long_about = None,
)]
struct Cli {
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
}

impl<'a> GraftSummary<'a> {
    fn from_graft(g: &'a Graft) -> Self {
        let blocks: Vec<&'static str> = Marker::ALL
            .iter()
            .filter(|m| g.block(**m).is_some())
            .map(|m| m.label())
            .collect();
        let applicable = blocks.len();
        Self {
            name: &g.name,
            version: &g.version,
            priority: g.priority,
            blocks,
            applicable,
            deferred: false,
            sha256: &g.sha256,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let grafts = select_grafts(&cli)?;

    if cli.list {
        emit_list(&grafts, cli.json);
        return Ok(());
    }

    let path = cli.path.as_ref().ok_or_else(|| {
        anyhow!("missing target path (or use --list to enumerate discovered grafts)")
    })?;
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

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
            fs::write(path, &output)
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
        eprintln!("{summary}");
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
    eprintln!(
        "  markers present: {} ({})",
        present_labels.len(),
        present_labels.join(", ")
    );
    if !missing_labels.is_empty() {
        eprintln!(
            "  warning — markers not found: {}",
            missing_labels.join(", ")
        );
    }
    if !applied {
        eprintln!("  (preview only — pass --apply to write {})", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    ?-  -.u.act
        %cause  [~ state]
      ::  nockup:poke
    ==
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
                poke: Some(Block {
                    sentinel: format!("%{name}-do"),
                    body: format!(
                        "  %{name}-do\n=/  lc=cause  [%{name}-do ~]\n[~ state]"
                    ),
                }),
                peek: Some(Block {
                    sentinel: format!("{name}-peek"),
                    body: format!("({name}-peek state path)"),
                }),
            },
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
        // Peek emits the chain shape (Phase 4): the legacy expression
        // lives inside the `=/ settle-res ...` binding.
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("?.  =(~ settle-res)  settle-res"));

        assert_eq!(report.markers_in_source.len(), 5);
        assert!(report.markers_missing.is_empty());
        let settle = &report.grafts[0];
        assert_eq!(settle.name, "settle-graft");
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
        // bodies. Scan the loaded `settle-graft.toml` rather than the
        // (deleted) BLOCK_* constants — same content post-Phase 3.
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
        assert_eq!(report.markers_missing.len(), 5);
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn does_not_match_nockup_pokemon() {
        let grafts = settle_only_grafts();
        let src = "::  nockup:pokemon\n";
        let (_, report) = inject(src, &grafts).unwrap();
        assert_eq!(report.markers_missing.len(), 5);
        assert!(report.markers_in_source.is_empty());
    }

    #[test]
    fn loader_rejects_missing_graft_table() {
        let dir = tempdir_for_test("loader_no_graft_table");
        let path = dir.join("not-a-graft.toml");
        fs::write(&path, "[other]\nkey = \"value\"\n").unwrap();
        let result = load_manifest(&path).expect("toml itself parses");
        assert!(result.is_none(), "manifest without [graft] must return None");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn marker_parse_covers_five() {
        for name in ["imports", "state", "cause", "poke", "peek"] {
            assert!(Marker::parse(name).is_some(), "expected Some for {name}");
        }
        assert!(Marker::parse("load").is_none());
        assert!(Marker::parse("arms").is_none());
        assert!(Marker::parse("nonsense").is_none());
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
                .position(|l| l.trim_start().starts_with(&needle))
                .unwrap_or_else(|| panic!("marker `{}` missing from output", marker.label()));
            let marker_indent = leading_whitespace(lines[marker_idx]).to_string();
            let body = graft
                .block(marker)
                .expect("settle claims this marker")
                .trimmed_body();
            // Body lines land one row after the `begin_banner` emitted by
            // AUDIT 2026-04-19 H-11..H-14's idempotence refactor.
            let expected_begin =
                format!("{marker_indent}::  graft-inject:settle-graft:{}:begin", marker.label());
            assert_eq!(
                lines[marker_idx + 1],
                expected_begin,
                "marker `{}` begin banner missing",
                marker.label()
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
        assert_eq!(peek_lines[0], "::  graft-inject:settle-graft:peek:begin");
        assert_eq!(peek_lines[1], "=/  settle-res  (settle-peek settle.state path)");
        assert_eq!(peek_lines[2], "?.  =(~ settle-res)  settle-res");
        assert_eq!(peek_lines[3], "::  graft-inject:settle-graft:peek:end");
        assert_eq!(peek_lines[4], "::  graft-inject:alpha:peek:begin");
        assert_eq!(peek_lines[5], "=/  alpha-res  (alpha-peek state path)");
        assert_eq!(peek_lines[6], "?.  =(~ alpha-res)  alpha-res");
        assert_eq!(peek_lines[7], "::  graft-inject:alpha:peek:end");
        assert_eq!(peek_lines[8], "::  graft-inject:beta:peek:begin");
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
        assert_eq!(peek_lines[8], "::  graft-inject:beta:peek:begin");
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
        assert_eq!(
            peek_lines[0].trim_start(),
            "::  graft-inject:settle-graft:peek:begin"
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

    // ---------- Phase 6: CLI tests ----------

    fn cli_with(lib_dir: PathBuf) -> Cli {
        Cli {
            path: None,
            grafts: Vec::new(),
            exclude: Vec::new(),
            lib_dir,
            list: false,
            json: false,
            dry_run: false,
            apply: false,
        }
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
        run(cli).unwrap();

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
        run(cli).unwrap();

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
        run(cli).unwrap();

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
                poke: Some(Block {
                    sentinel: "%poison-do".to_string(),
                    body: "  %poison-do\n::  references %contaminant-do elsewhere\n[~ state]".to_string(),
                }),
                peek: None,
            },
            sha256: String::new(),
        };
        let contaminant = synthetic_graft("contaminant", 20);

        let (after_poison, _) = inject(BARE_SCAFFOLD, &[poison.clone()]).unwrap();
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
            .map(|i| synthetic_graft(&format!("g{i}"), 10 + i as i32 * 10))
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
                poke: Some(Block {
                    sentinel: "%nested-do".to_string(),
                    body: "  %nested-do\n?-  +.state\n  [%foo ~]  [~ state]\n  [%bar ~]  [~ state]\n==\n[~ state]".to_string(),
                }),
                peek: None,
            },
            sha256: String::new(),
        };
        let (first, _) = inject(BARE_SCAFFOLD, &[nested.clone()]).unwrap();
        assert!(first.lines().any(|l| l.trim() == "=="), "inner == present");
        let (second, report) = inject(&first, &[nested]).unwrap();
        assert_eq!(first, second, "inner == must not re-trigger inject");
        assert!(report.grafts[0].injected.is_empty());
    }

    /// Removing a graft from the injection set must NOT delete an
    /// already-wired banner block. The tool is additive by design; cleanup
    /// is a manual op, not a side-effect of `--grafts`.
    #[test]
    fn removed_graft_banner_preserved() {
        let a = synthetic_graft("alpha", 10);
        let b = synthetic_graft("beta", 20);
        let (after_both, _) = inject(BARE_SCAFFOLD, &[a.clone(), b.clone()]).unwrap();
        assert!(after_both.contains("::  graft-inject:beta:imports:begin"));
        let (after_alpha_only, _) = inject(&after_both, &[a]).unwrap();
        assert!(
            after_alpha_only.contains("::  graft-inject:beta:imports:begin"),
            "beta banner must survive a re-run with only alpha selected"
        );
        assert!(after_alpha_only.contains("/+  *beta"));
    }
}
