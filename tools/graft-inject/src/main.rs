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
    version: String,
    priority: i32,
    #[serde(default)]
    after: Vec<String>,
    blocks: GraftBlocks,
    /// Optional gate selection from `[graft.gates]`. EXPANSION Phase 01:
    /// when set, the manifest's poke body has its default hash-gate
    /// constructions rewritten to call into `vesl-gates`, and the imports
    /// block gains a `/+  vesl-gates` line. See `apply_gate_selection`.
    #[serde(default)]
    gates: Option<GateSelection>,
    /// Optional `[graft.types]` table. Phase 03f Lever 1 (typed effect
    /// union codegen): names the per-graft `effect` and `cause` types
    /// so `graft-inject` can emit a typed `+$ effect $%(...)` union at
    /// the `nockup:effect-union` marker. `cause` is read forward-compat
    /// for Lever 3 (cause destructuring); current codegen reads only
    /// `effect`. Manifests without this table parse with `types == None`.
    #[serde(default)]
    types: Option<GraftTypes>,
    /// Hex sha256 of the raw TOML bytes. Populated by `load_manifest` at
    /// discovery time so the composer can surface per-manifest digests
    /// in the preview report and `--list --json` output (AUDIT 2026-04-19
    /// H-10 supply-chain surface).
    #[serde(skip, default)]
    sha256: String,
}

/// `[graft.gates]` selection. `gate` and `gate-chain` are mutually
/// exclusive; both unset means the manifest keeps its default
/// hash-gate. Names are validated against `TIER_1A_GATES` at discovery.
#[derive(Debug, Clone, Deserialize)]
struct GateSelection {
    #[serde(default)]
    gate: Option<String>,
    #[serde(default, rename = "gate-chain")]
    gate_chain: Option<Vec<String>>,
}

/// `[graft.types]` declarations. Phase 03f Lever 1: lets the codegen
/// pass emit a typed effect union without parsing Hoon. `effect` is the
/// bare type name the graft exports for its effect variant (e.g.
/// `settle-effect`); the codegen splats it into the `+$ effect $%(...)`
/// union at the `nockup:effect-union` marker. `cause` is parsed for
/// forward-compat with Lever 3 (cause destructuring) and currently
/// unused.
#[derive(Debug, Clone, Deserialize)]
struct GraftTypes {
    #[serde(default)]
    effect: Option<String>,
    #[serde(default)]
    cause: Option<String>,
}

/// Allowlist of catalog gates currently shipped in `vesl-gates.hoon`.
/// Tier 1b additions extend this list as they land.
const TIER_1A_GATES: &[&str] = &[
    "sig-verify-ed25519",
    "sig-verify-schnorr",
    "manifest-verify",
    "set-membership-verify",
    "bounded-value-verify",
];

#[derive(Debug, Clone, Default, Deserialize)]
struct GraftBlocks {
    imports: Option<Block>,
    state: Option<Block>,
    cause: Option<Block>,
    /// Phase 03b: code spliced ahead of the `?-  -.u.act` switch. Composes
    /// as `?:` short-circuit guards (validate / fsm rejection paths) or as
    /// `=/  pre-snapshot` bindings that scope through the rest of the gate
    /// (index-graft pre-state capture). Multiple preludes stack in priority
    /// order; the first to short-circuit ends the gate before the switch
    /// runs. See docs/graft-manifest.md §poke-prelude.
    #[serde(rename = "poke-prelude")]
    poke_prelude: Option<Block>,
    poke: Option<Block>,
    /// Phase 03b: code spliced after the `?-  -.u.act` switch. The switch's
    /// `[(list effect) _state]` result is bound to `out`; postludes rebind
    /// `out` (e.g. `=/  out  (transform out)`) and the gate returns the
    /// final `out`. Multiple postludes compose left-to-right in priority
    /// order. See docs/graft-manifest.md §poke-postlude.
    #[serde(rename = "poke-postlude")]
    poke_postlude: Option<Block>,
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
    fn block(&self, marker: Marker) -> Option<&Block> {
        match marker {
            Marker::Imports => self.blocks.imports.as_ref(),
            Marker::State => self.blocks.state.as_ref(),
            Marker::Cause => self.blocks.cause.as_ref(),
            Marker::PokePrelude => self.blocks.poke_prelude.as_ref(),
            Marker::Poke => self.blocks.poke.as_ref(),
            Marker::PokePostlude => self.blocks.poke_postlude.as_ref(),
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
/// silently. `after` hints are soft: a hint to a graft that isn't in the
/// discovered set is logged on stderr and ignored (priority-based ordering
/// still applies); see `cli.md` §"Priority lattice" for the contract.
/// Rejects duplicate graft names (AUDIT 2026-04-19 H-11), and rejects
/// graft names that don't match the kebab-case shape the schema documents.
/// Also validates `[graft.gates]` (C2) and applies any gate selection to
/// the manifest's poke + imports blocks (EXPANSION Phase 01).
fn discover_grafts(lib_dir: &Path) -> Result<Vec<Graft>> {
    let mut grafts: Vec<Graft> = Vec::new();
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    let entries = fs::read_dir(lib_dir)
        .with_context(|| format!("scanning {}", lib_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Some(mut g) = load_manifest(&path)? {
                if !is_valid_graft_name(&g.name) {
                    bail!(
                        "invalid graft name `{}` in {}: expected kebab-case \
                         matching ^[a-z][a-z0-9-]*$",
                        g.name,
                        path.display()
                    );
                }
                validate_gate_selection(&g, &path)?;
                apply_gate_selection(&mut g, &path)?;
                validate_types(&g, &path)?;
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
                eprintln!(
                    "graft-inject: note — ignoring after-hint to `{}` from `{}` (not in cp set), proceeding with priority order",
                    hint, g.name
                );
            }
        }
    }
    Ok(grafts)
}

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

/// Validate `[graft.types]`: each declared name must be a kebab-case
/// identifier, since the codegen pass splices the bare name directly
/// into Hoon source. A garbage type name would surface as a hoonc
/// `find . X` failure with no path back to the offending manifest.
fn validate_types(g: &Graft, path: &Path) -> Result<()> {
    let Some(types) = &g.types else {
        return Ok(());
    };
    if let Some(name) = &types.effect {
        if !is_valid_graft_name(name) {
            bail!(
                "[graft.types].effect `{name}` in {}: expected kebab-case matching ^[a-z][a-z0-9-]*$",
                path.display()
            );
        }
    }
    if let Some(name) = &types.cause {
        if !is_valid_graft_name(name) {
            bail!(
                "[graft.types].cause `{name}` in {}: expected kebab-case matching ^[a-z][a-z0-9-]*$",
                path.display()
            );
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

/// Build the AND-fold gate-chain Hoon block. Layout matches the rest of
/// settle-graft.toml's poke body: `=/` at column 0, inner lines indented
/// by 2 spaces, `?&` first-arg on the same line (Hoon tall-form style),
/// continuation args aligned at column 6 (under `?& ` + space), `==` at
/// column 2.
///
///     =/  hash-gate=verify-gate
///       |=  [note-id=@ data=* expected-root=@]
///       ^-  ?
///       ?&  (a:vesl-gates note-id data expected-root)
///           (b:vesl-gates note-id data expected-root)
///       ==
fn build_chain_block(chain: &[String]) -> String {
    let mut out = String::from(
        "=/  hash-gate=verify-gate\n  \
         |=  [note-id=@ data=* expected-root=@]\n  \
         ^-  ?\n  ?&",
    );
    for (i, name) in chain.iter().enumerate() {
        let lead = if i == 0 { "  " } else { "\n      " };
        out.push_str(&format!(
            "{lead}({name}:vesl-gates note-id data expected-root)"
        ));
    }
    out.push_str("\n  ==");
    out
}

/// Atomic write: tempfile in the target's directory, fsync, rename.
///
/// AUDIT 2026-04-19 M-24: the prior direct `fs::write` left `app.hoon`
/// zero-length or partial if the process died mid-write (SIGKILL, power
/// loss, disk full). Tempfile + rename on the same filesystem gives
/// us atomic replacement; an fsync between write and rename ensures
/// the bytes are on disk before the directory entry flips.
fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("target has no parent dir: {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("target has no file name: {}", path.display()))?
        .to_string_lossy();
    let tmp_name = format!(".{}.graft-inject.{}.tmp", file_name, std::process::id());
    let tmp_path = dir.join(&tmp_name);

    // Best-effort cleanup of a stale tempfile from a previous aborted run.
    let _ = fs::remove_file(&tmp_path);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("creating tempfile {}", tmp_path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing tempfile {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync tempfile {}", tmp_path.display()))?;
    drop(file);

    fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming tempfile into place: {}", path.display()))?;
    Ok(())
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
    /// Phase 03b: spliced before the poke `?-` switch — guards (`?:`
    /// short-circuits) and pre-state captures (`=/  pre-X`).
    PokePrelude,
    Poke,
    /// Phase 03b: spliced after the `?-` switch — `out` rebinds that
    /// transform the switch's `[(list effect) _state]` result.
    PokePostlude,
    Peek,
}

impl Marker {
    const ALL: [Marker; 7] = [
        Marker::Imports,
        Marker::State,
        Marker::Cause,
        Marker::PokePrelude,
        Marker::Poke,
        Marker::PokePostlude,
        Marker::Peek,
    ];

    #[cfg(test)]
    fn parse(name: &str) -> Option<Self> {
        match name {
            "imports" => Some(Self::Imports),
            "state" => Some(Self::State),
            "cause" => Some(Self::Cause),
            "poke-prelude" => Some(Self::PokePrelude),
            "poke" => Some(Self::Poke),
            "poke-postlude" => Some(Self::PokePostlude),
            "peek" => Some(Self::Peek),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::State => "state",
            Self::Cause => "cause",
            Self::PokePrelude => "poke-prelude",
            Self::Poke => "poke",
            Self::PokePostlude => "poke-postlude",
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
                    Marker::Imports => {
                        emit_imports_block(&mut lines, idx, &indent, &pending);
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
        composed.push(begin_banner(&g.name, Marker::Imports));
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
    /// Phase 03f Lever 1: per-graft `[graft.types]` table contents,
    /// surfaced for tooling that wants to know which grafts contribute
    /// to the typed effect union. `null` when the manifest omits the
    /// table.
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

fn main() -> ExitCode {
    warn_if_stale();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft-inject: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// One-line stderr warning when the binary's source SHA (captured at
/// build time by `build.rs`) doesn't match the latest commit touching
/// `src/` in the manifest dir. Catches the dogfood case where a global
/// `cargo install --path tools/graft-inject` ran weeks ago and has
/// fallen behind source.
///
/// Silent when:
/// - The build SHA is `unknown` (no git context at build time).
/// - The manifest dir from build time no longer exists on this
///   machine (binary was moved, or the source checkout was deleted).
/// - `git` isn't on PATH or `git log` fails.
/// - The current source SHA matches the build SHA (binary is current).
///
/// Suppress entirely with `GRAFT_INJECT_NO_STALENESS_WARNING=1` for
/// CI runs that don't want the noise.
fn warn_if_stale() {
    if std::env::var("GRAFT_INJECT_NO_STALENESS_WARNING").is_ok() {
        return;
    }
    let build_sha = env!("GRAFT_INJECT_BUILD_SRC_SHA");
    if build_sha == "unknown" {
        return;
    }
    let manifest_dir = env!("GRAFT_INJECT_MANIFEST_DIR");
    if !Path::new(manifest_dir).exists() {
        return;
    }
    let Ok(output) = std::process::Command::new("git")
        .args(["-C", manifest_dir, "log", "-1", "--format=%H", "--", "src"])
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let current_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if current_sha.is_empty() || current_sha == build_sha {
        return;
    }
    let short = |s: &str| s.chars().take(8).collect::<String>();
    eprintln!(
        "graft-inject: warning — binary built from {} but tools/graft-inject/src/ \
         is now at {}. Rebuild: cargo install --path tools/graft-inject --force",
        short(build_sha),
        short(&current_sha),
    );
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
        // Peek emits the chain shape (Phase 4): the legacy expression
        // lives inside the `=/ settle-res ...` binding.
        assert!(out.contains("=/  settle-res  (settle-peek settle.state path)"));
        assert!(out.contains("?.  =(~ settle-res)  settle-res"));

        assert_eq!(report.markers_in_source.len(), 7);
        assert!(report.markers_missing.is_empty());
        let settle = &report.grafts[0];
        assert_eq!(settle.name, "settle-graft");
        // settle-graft contributes 5 of the 7 markers (no prelude / postlude).
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
    fn loader_rejects_missing_graft_table() {
        let dir = tempdir_for_test("loader_no_graft_table");
        let path = dir.join("not-a-graft.toml");
        fs::write(&path, "[other]\nkey = \"value\"\n").unwrap();
        let result = load_manifest(&path).expect("toml itself parses");
        assert!(result.is_none(), "manifest without [graft] must return None");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn marker_parse_covers_all() {
        for name in [
            "imports",
            "state",
            "cause",
            "poke-prelude",
            "poke",
            "poke-postlude",
            "peek",
        ] {
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

    // ---------------------------------------------------------------
    // [graft.gates] selection — EXPANSION Phase 01 / parametize_2
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
}
