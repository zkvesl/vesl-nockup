//! graft-inject: auto-wire vesl graft into a nockup app.hoon kernel.
//!
//! Finds `::  nockup:<name>` markers in the target file and inserts the
//! corresponding block of Hoon. Idempotent: if wiring is already present,
//! the marker is left alone and a `skipped` line is logged.
//!
//! Usage: graft-inject <path-to-app.hoon>

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MARKER_PREFIX: &str = "::  nockup:";

// Sentinels used to detect already-injected wiring (idempotence).
const SENTINEL_IMPORTS: &str = "*vesl-graft";
const SENTINEL_STATE: &str = "vesl=vesl-state";
const SENTINEL_CAUSE: &str = "vesl-cause";
const SENTINEL_POKE: &str = "%vesl-register";
const SENTINEL_PEEK: &str = "vesl-peek";

// Injection blocks. Stored with no leading indent — re-indent at injection
// using the marker line's captured leading whitespace.
const BLOCK_IMPORTS: &str = "\
/+  *vesl-graft
/+  *vesl-merkle";

const BLOCK_STATE: &str = "\
vesl=vesl-state";

const BLOCK_CAUSE: &str = "\
vesl-cause";

// Poke block includes the `::` separator between arms. The `%vesl-*` tags
// are indented two spaces deeper than the body (matches `?-` switch layout).
const BLOCK_POKE: &str = "\
::
  %vesl-register
=/  lc=vesl-cause  [%vesl-register hull.u.act root.u.act]
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =((hash-leaf ;;(@ data)) expected-root)
=/  [efx=(list vesl-effect) new-vesl=vesl-state]
  (vesl-poke vesl.state lc hash-gate)
:_  state(vesl new-vesl)
^-  (list effect)
efx
::
  %vesl-verify
=/  lc=vesl-cause  [%vesl-verify payload.u.act]
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =((hash-leaf ;;(@ data)) expected-root)
=/  [efx=(list vesl-effect) new-vesl=vesl-state]
  (vesl-poke vesl.state lc hash-gate)
:_  state(vesl new-vesl)
^-  (list effect)
efx
::
  %vesl-settle
=/  lc=vesl-cause  [%vesl-settle payload.u.act]
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =((hash-leaf ;;(@ data)) expected-root)
=/  [efx=(list vesl-effect) new-vesl=vesl-state]
  (vesl-poke vesl.state lc hash-gate)
:_  state(vesl new-vesl)
^-  (list effect)
efx";

// Peek replacement: substituted in place of a bare `~` fallthrough.
const PEEK_REPLACEMENT: &str = "(vesl-peek vesl.state path)";

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
    Ok(Some(manifest.graft))
}

/// Scan `lib_dir` for `*.toml` files and return loaded grafts in priority
/// order, ties broken by name. Files lacking a `[graft]` table are skipped
/// silently. Validates that every `after` hint names a discovered graft.
fn discover_grafts(lib_dir: &Path) -> Result<Vec<Graft>> {
    let mut grafts: Vec<Graft> = Vec::new();
    let entries = fs::read_dir(lib_dir)
        .with_context(|| format!("scanning {}", lib_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Some(g) = load_manifest(&path)? {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    Imports,
    State,
    Cause,
    Poke,
    Peek,
}

impl Marker {
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

    fn sentinel(self) -> &'static str {
        match self {
            Self::Imports => SENTINEL_IMPORTS,
            Self::State => SENTINEL_STATE,
            Self::Cause => SENTINEL_CAUSE,
            Self::Poke => SENTINEL_POKE,
            Self::Peek => SENTINEL_PEEK,
        }
    }

    fn block(self) -> Option<&'static str> {
        match self {
            Self::Imports => Some(BLOCK_IMPORTS),
            Self::State => Some(BLOCK_STATE),
            Self::Cause => Some(BLOCK_CAUSE),
            Self::Poke => Some(BLOCK_POKE),
            Self::Peek => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerStatus {
    Injected,
    Skipped,
    Missing,
}

pub fn inject(
    source: &str,
    grafts: &[Graft],
) -> Result<(String, Vec<(Marker, MarkerStatus)>)> {
    // Normalize CRLF -> LF for processing; we re-emit LF regardless.
    let mut lines: Vec<String> = source.replace("\r\n", "\n").lines().map(String::from).collect();
    let trailing_newline = source.ends_with('\n');
    let mut report: Vec<(Marker, MarkerStatus)> = Vec::new();

    for marker in [Marker::Imports, Marker::State, Marker::Cause, Marker::Poke, Marker::Peek] {
        match find_marker(&lines, marker)? {
            Some(idx) => {
                let indent = leading_whitespace(&lines[idx]).to_string();
                // Grafts that contribute a block here AND aren't already wired.
                // Phase 4: Stage 1 ships only the vesl graft, so `pending` is
                // either empty or a one-element slice. Phase 5 generalizes.
                let pending: Vec<&Graft> = grafts
                    .iter()
                    .filter(|g| {
                        g.block(marker)
                            .map(|b| !already_wired_for(&lines, idx, marker, &b.sentinel))
                            .unwrap_or(false)
                    })
                    .collect();
                if pending.is_empty() {
                    // Marker is in source. Either every claiming graft is
                    // already wired (skip), or no graft claims the marker
                    // (also skip — nothing to do, no warning needed).
                    report.push((marker, MarkerStatus::Skipped));
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
                report.push((marker, MarkerStatus::Injected));
            }
            None => {
                report.push((marker, MarkerStatus::Missing));
            }
        }
    }

    let mut output = lines.join("\n");
    if trailing_newline {
        output.push('\n');
    }
    Ok((output, report))
}

/// Insert composed body lines after the marker, indented to match the
/// marker. Multi-graft composition: each pending graft's body is
/// concatenated in priority order. The poke marker uses `::` as the
/// inter-block separator (matching the existing intra-arm convention);
/// other non-peek markers use a blank line.
fn emit_block(
    lines: &mut Vec<String>,
    marker_idx: usize,
    indent: &str,
    marker: Marker,
    pending: &[&Graft],
) {
    let separator = match marker {
        Marker::Poke => "::",
        _ => "",
    };
    let mut composed: Vec<String> = Vec::new();
    for (i, g) in pending.iter().enumerate() {
        if i > 0 {
            composed.push(separator.to_string());
        }
        let body = g
            .block(marker)
            .expect("emit_block called with a graft missing this marker")
            .trimmed_body();
        for line in body.lines() {
            composed.push(line.to_string());
        }
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

/// Emit the peek-chain prelude(s) immediately before the terminal `~`
/// fallback. Each graft contributes two lines:
///
///   =/  <stub>-res  <peek.body>
///   ?.  =(~ <stub>-res)  <stub>-res
///
/// where `<stub>` is the graft name with the `-graft` suffix stripped.
/// The bare `~` already in the source remains as the chain's terminal
/// fallback. If no bare `~` is found in the window after the marker, a
/// synthetic one is appended so the `?+` still has something to evaluate.
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
                format!("{indent}=/  {stub}-res  {body}"),
                format!("{indent}?.  =(~ {stub}-res)  {stub}-res"),
            ]
        })
        .collect();

    if let Some(target) = find_bare_tilde(lines, marker_idx + 1) {
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
/// used in the peek chain (`vesl-graft` -> `vesl`, `mint-graft` -> `mint`).
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

/// Per-graft idempotence check: scan a window of lines after the marker
/// for THIS graft's sentinel. Replaces the pre-Phase-4 single-sentinel
/// `already_wired` so multiple grafts can share a marker without each
/// other's sentinels triggering false positives.
fn already_wired_for(lines: &[String], marker_idx: usize, marker: Marker, sentinel: &str) -> bool {
    let window = match marker {
        Marker::Poke => 60,
        Marker::Imports => 10,
        _ => 20,
    };
    let start = marker_idx + 1;
    let end = (start + window).min(lines.len());
    for line in &lines[start..end] {
        if matches!(marker, Marker::State | Marker::Cause)
            && line.trim_start().starts_with("::")
        {
            continue;
        }
        if line.contains(sentinel) {
            return true;
        }
    }
    false
}

fn find_bare_tilde(lines: &[String], from: usize) -> Option<usize> {
    for i in from..lines.len().min(from + 10) {
        let trimmed = lines[i].trim();
        if trimmed == "~" {
            return Some(i);
        }
    }
    None
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        bail!("usage: graft-inject <path-to-app.hoon>");
    }
    let path = PathBuf::from(&args[1]);
    let source = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Phase 4: discover grafts in the conventional ./hoon/lib/ root
    // relative to cwd. Phase 6 adds the --lib-dir / --grafts CLI flags
    // and richer discovery.
    let lib_dir = PathBuf::from("hoon").join("lib");
    let grafts = if lib_dir.is_dir() {
        discover_grafts(&lib_dir)
            .with_context(|| format!("discovering grafts under {}", lib_dir.display()))?
    } else {
        Vec::new()
    };
    if grafts.is_empty() {
        bail!(
            "no grafts discovered under {}; expected at least one *.toml manifest with a [graft] table",
            lib_dir.display()
        );
    }

    let (output, report) = inject(&source, &grafts)
        .with_context(|| format!("injecting into {}", path.display()))?;

    if output != source {
        fs::write(&path, output)
            .with_context(|| format!("writing {}", path.display()))?;
    }

    print_report(&path, &report)?;
    Ok(())
}

fn print_report(path: &PathBuf, report: &[(Marker, MarkerStatus)]) -> Result<()> {
    let mut injected = Vec::new();
    let mut skipped = Vec::new();
    let mut missing = Vec::new();
    for (m, s) in report {
        match s {
            MarkerStatus::Injected => injected.push(m.label()),
            MarkerStatus::Skipped => skipped.push(m.label()),
            MarkerStatus::Missing => missing.push(m.label()),
        }
    }
    println!("graft-inject: {}", path.display());
    if !injected.is_empty() {
        println!("  injected: {} ({}/5)", injected.join(", "), injected.len());
    }
    if !skipped.is_empty() {
        println!("  skipped (already wired): {}", skipped.join(", "));
    }
    if !missing.is_empty() {
        eprintln!("  warning — markers not found: {}", missing.join(", "));
    }
    if injected.is_empty() && skipped.is_empty() && missing.len() == 5 {
        return Err(anyhow!(
            "no nockup markers found in {}; nothing to wire",
            path.display()
        ));
    }
    Ok(())
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

    fn vesl_only_grafts() -> Vec<Graft> {
        let path = vesl_graft_manifest_path();
        let g = load_manifest(&path)
            .expect("load vesl-graft.toml")
            .expect("vesl-graft.toml has [graft] table");
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
        }
    }

    #[test]
    fn injects_all_markers() {
        let grafts = vesl_only_grafts();
        let (out, report) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        assert!(out.contains("/+  *vesl-graft"));
        assert!(out.contains("/+  *vesl-merkle"));
        assert!(out.contains("vesl=vesl-state"));
        assert!(out.contains("vesl-cause"));
        assert!(out.contains("%vesl-register"));
        assert!(out.contains("%vesl-verify"));
        assert!(out.contains("%vesl-settle"));
        // Phase 4: peek emits a chain instead of a flat replacement.
        // The body still contains the legacy `(vesl-peek vesl.state path)`
        // expression, now wrapped in `=/  vesl-res  ...` and a fall-through.
        assert!(out.contains("=/  vesl-res  (vesl-peek vesl.state path)"));
        assert!(out.contains("?.  =(~ vesl-res)  vesl-res"));

        let injected_count = report
            .iter()
            .filter(|(_, s)| *s == MarkerStatus::Injected)
            .count();
        assert_eq!(injected_count, 5);
    }

    #[test]
    fn is_idempotent() {
        let grafts = vesl_only_grafts();
        let (first, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let (second, report) = inject(&first, &grafts).unwrap();
        assert_eq!(first, second);
        for (m, s) in &report {
            assert!(
                matches!(s, MarkerStatus::Skipped | MarkerStatus::Injected),
                "marker {:?} had unexpected status {:?}",
                m,
                s
            );
        }
    }

    #[test]
    fn preserves_two_space_law() {
        // Check that runes are followed by exactly two spaces (or EOL).
        // Violation pattern: rune + single space + non-space character.
        for block in [BLOCK_IMPORTS, BLOCK_STATE, BLOCK_CAUSE, BLOCK_POKE] {
            for line in block.lines() {
                let trimmed = line.trim_start();
                for rune in ["=/", "|=", "/+", "/-", "/=", "^-", ":_", "?-", "?+", "?~", "?."] {
                    if let Some(rest) = trimmed.strip_prefix(rune) {
                        // Valid: EOL, or two or more spaces, or no space (e.g. "=/=").
                        let next_two: Vec<char> = rest.chars().take(2).collect();
                        match next_two.as_slice() {
                            [] => {}                       // rune alone on line — fine
                            [' ', ' '] => {}               // two spaces — correct
                            [' ', _] => panic!("single-space `{rune}` in block line: {line:?}"),
                            _ => {}                        // non-space — different token
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn missing_marker_is_warning_not_error() {
        let grafts = vesl_only_grafts();
        let src = "::  just a comment\n";
        let result = inject(src, &grafts);
        // inject() always succeeds; it's run() that errors if ALL markers are missing
        assert!(result.is_ok());
        let (_, report) = result.unwrap();
        for (_, status) in &report {
            assert_eq!(*status, MarkerStatus::Missing);
        }
    }

    #[test]
    fn does_not_match_nockup_pokemon() {
        let grafts = vesl_only_grafts();
        let src = "::  nockup:pokemon\n";
        let (_, report) = inject(src, &grafts).unwrap();
        for (_, status) in &report {
            assert_eq!(*status, MarkerStatus::Missing);
        }
    }

    fn vesl_graft_manifest_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("hoon")
            .join("lib")
            .join("vesl-graft.toml")
    }

    #[test]
    fn manifest_matches_hardcoded_blocks() {
        let path = vesl_graft_manifest_path();
        let graft = load_manifest(&path)
            .expect("manifest load failed")
            .expect("vesl-graft.toml missing [graft] table");
        assert_eq!(graft.name, "vesl-graft");
        assert_eq!(graft.priority, 10);

        let imports = graft.blocks.imports.as_ref().expect("imports block");
        assert_eq!(imports.trimmed_body(), BLOCK_IMPORTS);
        assert_eq!(imports.sentinel, SENTINEL_IMPORTS);

        let state = graft.blocks.state.as_ref().expect("state block");
        assert_eq!(state.trimmed_body(), BLOCK_STATE);
        assert_eq!(state.sentinel, SENTINEL_STATE);

        let cause = graft.blocks.cause.as_ref().expect("cause block");
        assert_eq!(cause.trimmed_body(), BLOCK_CAUSE);
        assert_eq!(cause.sentinel, SENTINEL_CAUSE);

        let poke = graft.blocks.poke.as_ref().expect("poke block");
        assert_eq!(poke.trimmed_body(), BLOCK_POKE);
        assert_eq!(poke.sentinel, SENTINEL_POKE);

        let peek = graft.blocks.peek.as_ref().expect("peek block");
        assert_eq!(peek.trimmed_body(), PEEK_REPLACEMENT);
        assert_eq!(peek.sentinel, SENTINEL_PEEK);
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
        // Stage-3-reserved names must not parse in Stage 1.
        assert!(Marker::parse("load").is_none());
        assert!(Marker::parse("arms").is_none());
        // Unknown name is None.
        assert!(Marker::parse("nonsense").is_none());
    }

    fn tempdir_for_test(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("graft-inject-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn single_graft_injection_byte_identical_to_hardcoded() {
        // Proves the data-driven inject() pastes the manifest body
        // verbatim at every non-peek marker, with the marker's leading
        // whitespace prepended and no other rewriting. Since the manifest
        // body matches BLOCK_* byte-for-byte (manifest_matches_hardcoded_blocks),
        // this transitively proves the data path produces the same output
        // a hardcoded inject() would have at those markers.
        //
        // Peek is intentionally excluded — Phase 4 changes peek from a
        // flat replacement to a chain. peek_chain_n1_matches_legacy_replacement
        // covers the new shape.
        let grafts = vesl_only_grafts();
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        for (label, block) in [
            ("imports", BLOCK_IMPORTS),
            ("state", BLOCK_STATE),
            ("cause", BLOCK_CAUSE),
            ("poke", BLOCK_POKE),
        ] {
            let needle = format!("::  nockup:{label}");
            let marker_idx = lines
                .iter()
                .position(|l| l.trim_start().starts_with(&needle))
                .unwrap_or_else(|| panic!("marker `{label}` missing from output"));
            let marker_indent = leading_whitespace(lines[marker_idx]).to_string();
            let body_lines: Vec<&str> = block.lines().collect();
            for (i, want) in body_lines.iter().enumerate() {
                let got = lines[marker_idx + 1 + i];
                let expected = if want.is_empty() {
                    String::new()
                } else {
                    format!("{marker_indent}{want}")
                };
                assert_eq!(
                    got, expected,
                    "marker `{label}` line {i} byte mismatch"
                );
            }
        }
    }

    #[test]
    fn multi_graft_injection_composes_blocks() {
        // vesl + two synthetic grafts, all three contribute to every marker.
        // Each marker region must contain all three sentinels in priority order.
        let mut grafts = vesl_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();

        // imports: all three import directives present
        assert!(out.contains("/+  *vesl-graft"));
        assert!(out.contains("/+  *alpha"));
        assert!(out.contains("/+  *beta"));
        // state: all three field declarations
        assert!(out.contains("vesl=vesl-state"));
        assert!(out.contains("alpha=alpha-state"));
        assert!(out.contains("beta=beta-state"));
        // cause: all three cause-union members
        assert!(out.contains("vesl-cause"));
        assert!(out.contains("alpha-cause"));
        assert!(out.contains("beta-cause"));
        // poke: all three first-arm tags
        assert!(out.contains("%vesl-register"));
        assert!(out.contains("%alpha-do"));
        assert!(out.contains("%beta-do"));
        // peek: all three chain bindings
        assert!(out.contains("=/  vesl-res  (vesl-peek vesl.state path)"));
        assert!(out.contains("=/  alpha-res  (alpha-peek state path)"));
        assert!(out.contains("=/  beta-res  (beta-peek state path)"));
    }

    #[test]
    fn peek_chain_composition() {
        // Three grafts → six chain lines + terminal `~` = seven lines total
        // immediately after the marker, in priority order.
        let mut grafts = vesl_only_grafts();
        grafts.push(synthetic_graft("alpha", 50));
        grafts.push(synthetic_graft("beta", 60));
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<String> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(7)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 7, "expected 7 lines after peek marker");
        assert_eq!(peek_lines[0], "=/  vesl-res  (vesl-peek vesl.state path)");
        assert_eq!(peek_lines[1], "?.  =(~ vesl-res)  vesl-res");
        assert_eq!(peek_lines[2], "=/  alpha-res  (alpha-peek state path)");
        assert_eq!(peek_lines[3], "?.  =(~ alpha-res)  alpha-res");
        assert_eq!(peek_lines[4], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[5], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[6], "~");
    }

    #[test]
    fn per_graft_idempotence_inject_vesl_then_alpha() {
        // First inject vesl alone; then re-inject with [vesl, alpha].
        // vesl region must not double-up (no duplicated sentinels), and
        // alpha must appear interleaved at every marker.
        let vesl = vesl_only_grafts();
        let (after_vesl, _) = inject(BARE_SCAFFOLD, &vesl).unwrap();

        let mut both = vesl.clone();
        both.push(synthetic_graft("alpha", 50));
        let (after_both, report) = inject(&after_vesl, &both).unwrap();

        // Use exact-trimmed-line matching to avoid spurious substring
        // hits inside the poke body (e.g., `new-vesl=vesl-state` contains
        // the `vesl=vesl-state` substring).
        let lines: Vec<&str> = after_both.lines().collect();
        let trimmed_eq_count = |needle: &str| -> usize {
            lines.iter().filter(|l| l.trim() == needle).count()
        };

        for needle in [
            "/+  *vesl-graft",
            "/+  *vesl-merkle",
            "vesl=vesl-state",
            "vesl-cause",
            "%vesl-register",
            "=/  vesl-res  (vesl-peek vesl.state path)",
        ] {
            assert_eq!(
                trimmed_eq_count(needle),
                1,
                "vesl line `{needle}` must appear exactly once"
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
        for (m, s) in &report {
            assert!(
                matches!(s, MarkerStatus::Skipped | MarkerStatus::Injected),
                "marker {m:?} reported {s:?}"
            );
        }
    }

    #[test]
    fn peek_chain_idempotence_append_third_graft() {
        // Build vesl+alpha chain, then add beta. Beta's two lines must
        // land immediately before the terminal `~`, after the existing
        // vesl and alpha chain lines.
        let vesl_alpha: Vec<Graft> = {
            let mut v = vesl_only_grafts();
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

        // The peek region after the marker is now: vesl pair, alpha pair,
        // beta pair, terminal `~`. Beta's pair lands immediately before the
        // terminal `~`.
        let peek_lines: Vec<String> = after_all
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(7)
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(peek_lines.len(), 7);
        assert_eq!(peek_lines[4], "=/  beta-res  (beta-peek state path)");
        assert_eq!(peek_lines[5], "?.  =(~ beta-res)  beta-res");
        assert_eq!(peek_lines[6], "~");
    }

    #[test]
    fn peek_chain_n1_matches_legacy_replacement() {
        // For N=1 the chain is:
        //   =/  vesl-res  (vesl-peek vesl.state path)
        //   ?.  =(~ vesl-res)  vesl-res
        //   ~                                   <- terminal fallback
        //
        // The legacy expression `(vesl-peek vesl.state path)` lives inside
        // the chain's =/ binding — same runtime semantics as the pre-Phase-4
        // flat replacement when only one graft contributes a peek body.
        let grafts = vesl_only_grafts();
        let (out, _) = inject(BARE_SCAFFOLD, &grafts).unwrap();
        let peek_lines: Vec<&str> = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .skip(1)
            .take(3)
            .collect();
        assert_eq!(peek_lines.len(), 3, "peek region has fewer than 3 lines");
        let line0 = peek_lines[0].trim_start();
        let line1 = peek_lines[1].trim_start();
        let line2 = peek_lines[2].trim_start();
        assert_eq!(line0, &format!("=/  vesl-res  {PEEK_REPLACEMENT}"));
        assert_eq!(line1, "?.  =(~ vesl-res)  vesl-res");
        assert_eq!(line2, "~");
    }
}
