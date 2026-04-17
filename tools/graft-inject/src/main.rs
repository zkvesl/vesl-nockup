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

pub fn inject(source: &str) -> Result<(String, Vec<(Marker, MarkerStatus)>)> {
    // Normalize CRLF -> LF for processing; we re-emit LF regardless.
    let mut lines: Vec<String> = source.replace("\r\n", "\n").lines().map(String::from).collect();
    let trailing_newline = source.ends_with('\n');
    let mut report: Vec<(Marker, MarkerStatus)> = Vec::new();

    for marker in [Marker::Imports, Marker::State, Marker::Cause, Marker::Poke, Marker::Peek] {
        match find_marker(&lines, marker)? {
            Some(idx) => {
                let indent = leading_whitespace(&lines[idx]).to_string();
                if already_wired(&lines, idx, marker) {
                    report.push((marker, MarkerStatus::Skipped));
                    continue;
                }
                match marker {
                    Marker::Peek => {
                        if let Some(target) = find_bare_tilde(&lines, idx + 1) {
                            let tilde_indent = leading_whitespace(&lines[target]).to_string();
                            lines[target] = format!("{}{}", tilde_indent, PEEK_REPLACEMENT);
                            report.push((marker, MarkerStatus::Injected));
                        } else {
                            // No `~` to replace — insert at marker+1 with the
                            // marker's indent so the surrounding `?+` still
                            // has something to eval against.
                            lines.insert(
                                idx + 1,
                                format!("{}{}", indent, PEEK_REPLACEMENT),
                            );
                            report.push((marker, MarkerStatus::Injected));
                        }
                    }
                    _ => {
                        let block = marker.block().expect("non-peek markers carry a block");
                        let indented: Vec<String> = block
                            .lines()
                            .map(|l| {
                                if l.is_empty() {
                                    String::new()
                                } else {
                                    format!("{}{}", indent, l)
                                }
                            })
                            .collect();
                        // Insert directly after the marker line.
                        for (offset, line) in indented.into_iter().enumerate() {
                            lines.insert(idx + 1 + offset, line);
                        }
                        report.push((marker, MarkerStatus::Injected));
                    }
                }
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

// Check whether the wiring for a marker is already present.
// Scans a window of lines after the marker for the marker's sentinel.
fn already_wired(lines: &[String], marker_idx: usize, marker: Marker) -> bool {
    let sentinel = marker.sentinel();
    // Window size depends on marker — poke wiring is large.
    let window = match marker {
        Marker::Poke => 60,
        Marker::Imports => 10,
        _ => 20,
    };
    let start = marker_idx + 1;
    let end = (start + window).min(lines.len());
    for line in &lines[start..end] {
        // Skip comment lines for state/cause to avoid false positives.
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

    let (output, report) = inject(&source)
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

    #[test]
    fn injects_all_markers() {
        let (out, report) = inject(BARE_SCAFFOLD).unwrap();
        assert!(out.contains("/+  *vesl-graft"));
        assert!(out.contains("/+  *vesl-merkle"));
        assert!(out.contains("vesl=vesl-state"));
        assert!(out.contains("vesl-cause"));
        assert!(out.contains("%vesl-register"));
        assert!(out.contains("%vesl-verify"));
        assert!(out.contains("%vesl-settle"));
        assert!(out.contains("(vesl-peek vesl.state path)"));
        // The original `~` fallthrough should be gone.
        let peek_region: String = out
            .lines()
            .skip_while(|l| !l.contains("nockup:peek"))
            .take(4)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(peek_region.contains("vesl-peek"));

        let injected_count = report
            .iter()
            .filter(|(_, s)| *s == MarkerStatus::Injected)
            .count();
        assert_eq!(injected_count, 5);
    }

    #[test]
    fn is_idempotent() {
        let (first, _) = inject(BARE_SCAFFOLD).unwrap();
        let (second, report) = inject(&first).unwrap();
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
        let src = "::  just a comment\n";
        let result = inject(src);
        // inject() always succeeds; it's run() that errors if ALL markers are missing
        assert!(result.is_ok());
        let (_, report) = result.unwrap();
        for (_, status) in &report {
            assert_eq!(*status, MarkerStatus::Missing);
        }
    }

    #[test]
    fn does_not_match_nockup_pokemon() {
        let src = "::  nockup:pokemon\n";
        let (_, report) = inject(src).unwrap();
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
}
