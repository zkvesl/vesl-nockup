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
            // Codegen markers — synthesized by the inject pass, not
            // contributed per-graft.
            Marker::DomainEffect | Marker::EffectUnion => None,
        }
    }

    /// First 12 hex chars of the manifest sha256, for banner embedding.
    /// Twelve chars (48 bits) is enough to disambiguate any realistic
    /// manifest set with no collision risk while keeping the banner
    /// scannable. Falls back to the full sha if it's somehow shorter.
    fn sha256_short(&self) -> &str {
        let n = 12.min(self.sha256.len());
        &self.sha256[..n]
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
    validate_unique_type_names(&grafts, &seen)?;
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

/// Cross-graft uniqueness check on `[graft.types].effect` and `.cause`.
/// Two manifests claiming the same effect or cause type name would
/// produce a Hoon `$%` with two arms named the same — hoonc surfaces
/// it as `not a fork`, with no path back to the offending pair. Mirror
/// the existing duplicate-graft-name guard so the failure has both
/// manifest paths in the error.
///
/// `seen` is the discovery-time graft-name → path map; we re-derive
/// type-name → graft-name maps here so the error message can name both
/// the type collision and the manifest paths.
fn validate_unique_type_names(
    grafts: &[Graft],
    seen: &HashMap<String, PathBuf>,
) -> Result<()> {
    for field in ["effect", "cause"] {
        let mut by_type: HashMap<&str, &str> = HashMap::new();
        for g in grafts {
            let Some(types) = g.types.as_ref() else { continue };
            let name = match field {
                "effect" => types.effect.as_deref(),
                "cause" => types.cause.as_deref(),
                _ => unreachable!(),
            };
            let Some(name) = name else { continue };
            if let Some(prev_graft) = by_type.get(name) {
                let prev_path = seen
                    .get(*prev_graft)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| (*prev_graft).to_string());
                let cur_path = seen
                    .get(g.name.as_str())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| g.name.clone());
                bail!(
                    "duplicate [graft.types].{field} `{name}` in {} and {}: \
                     two grafts cannot export the same type name (Hoon's $% would \
                     reject as `not a fork`)",
                    prev_path,
                    cur_path,
                );
            }
            by_type.insert(name, g.name.as_str());
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
    /// Phase 03f Lever 1: anchor for the developer's
    /// `+$ domain-effect $%(...)` declaration. Marker only — grafts do
    /// not contribute a block here. The codegen pass reads its presence
    /// to decide whether to splat `domain-effect` into the union.
    DomainEffect,
    /// Phase 03f Lever 1: REPLACE-IF-PRESENT codegen target for the
    /// typed effect union `+$ effect $%(<graft-effects> domain-effect ==)`.
    /// Marker only — grafts do not contribute a block here. The
    /// codegen pass synthesizes the union body from each graft's
    /// `[graft.types].effect` plus `domain-effect` if DomainEffect is
    /// present.
    EffectUnion,
}

impl Marker {
    const ALL: [Marker; 9] = [
        Marker::Imports,
        Marker::State,
        Marker::Cause,
        Marker::PokePrelude,
        Marker::Poke,
        Marker::PokePostlude,
        Marker::Peek,
        Marker::DomainEffect,
        Marker::EffectUnion,
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
            "domain-effect" => Some(Self::DomainEffect),
            "effect-union" => Some(Self::EffectUnion),
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
            Self::DomainEffect => "domain-effect",
            Self::EffectUnion => "effect-union",
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
    /// Grafts whose banner pairs were present in source but absent from
    /// the active `--grafts` set on this run. Their orphan blocks were
    /// auto-pruned. Carrier separate from `grafts` because no manifest
    /// is loaded for these names.
    pruned_grafts: Vec<GraftReport>,
    /// Phase 03f Lever 1: outcome of the typed effect-union codegen pass.
    codegen: CodegenReport,
    /// Phase 03f Lever 1.5: weld-friction lint findings in domain code.
    weld_lint: WeldLint,
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

/// Phase 03f Lever 1.5: weld-friction lint.
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
        // Find the marker once for indent/fresh-inject; we'll re-find
        // after any drift strips that shifted lines.
        let Some(initial_idx) = find_marker(&lines, marker)? else {
            markers_missing.push(marker);
            continue;
        };
        markers_in_source.push(marker);
        let indent = leading_whitespace(&lines[initial_idx]).to_string();

        // RH1 step 2 (HARD-FRICTION-2): for emit_block-class markers
        // (state/cause/poke/poke-prelude/poke-postlude), drift re-injection
        // strips and re-emits AT THE SAME LINE INDEX so the file's graft
        // ordering survives a non-semantic manifest edit (e.g., a gate
        // swap). Position preservation is scoped to emit_block — Imports
        // anchors at the marker line and Peek inserts before the
        // structural terminal `~`, neither of which exposes the same
        // friction.
        //
        // R5/A2 (legacy comment): strip any per-graft banner pair whose
        // embedded sha256 doesn't match the current manifest (drift) or
        // whose banner is in pre-A2 legacy format (no sha256 suffix).
        let mut pending: Vec<&Graft> = Vec::new();
        for g in grafts {
            if g.block(marker).is_none() {
                continue;
            }
            match check_injection(&lines, g, marker) {
                InjectStatus::Drift { old_sha } => {
                    eprintln!(
                        "graft-inject: {}: manifest drift at {} (banner sha256 {} → current {}). Re-injecting.",
                        g.name,
                        marker.label(),
                        old_sha,
                        g.sha256_short()
                    );
                    if marker_supports_position_preserve(marker) {
                        if let Some(orig_idx) =
                            strip_banner_pair(&mut lines, &g.name, marker)
                        {
                            emit_position_preserving(
                                &mut lines, orig_idx, &indent, marker, g,
                            );
                            per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                        }
                    } else {
                        strip_banner_pair(&mut lines, &g.name, marker);
                        pending.push(g);
                    }
                }
                InjectStatus::Legacy => {
                    eprintln!(
                        "graft-inject: {}: legacy banner at {} (pre-A2, no sha256). Re-injecting in current format.",
                        g.name,
                        marker.label()
                    );
                    if marker_supports_position_preserve(marker) {
                        if let Some(orig_idx) =
                            strip_banner_pair(&mut lines, &g.name, marker)
                        {
                            emit_position_preserving(
                                &mut lines, orig_idx, &indent, marker, g,
                            );
                            per_graft.get_mut(&g.name).unwrap().injected.push(marker);
                        }
                    } else {
                        strip_banner_pair(&mut lines, &g.name, marker);
                        pending.push(g);
                    }
                }
                InjectStatus::UpToDate => {
                    per_graft.get_mut(&g.name).unwrap().skipped.push(marker);
                }
                InjectStatus::NotInjected => {
                    pending.push(g);
                }
            }
        }

        if pending.is_empty() {
            continue;
        }
        // Re-find the marker — drift strips may have shifted line indices.
        let Some(idx) = find_marker(&lines, marker)? else {
            unreachable!("marker {:?} disappeared mid-loop", marker);
        };
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

    // Phase 03f Lever 1: typed effect-union codegen runs after the
    // marker loop. REPLACE-IF-PRESENT semantics keep the union in sync
    // with the current graft set on every rerun.
    let codegen = emit_effect_union(&mut lines, grafts)?;

    // Phase 03f Lever 1.5: weld-friction lint scans developer code
    // (outside graft-inject banners) for narrow effect bindings that
    // will nest-fail at any cross-graft `(weld a b)` site. Advisory
    // only; surfaces in the stderr report.
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
        },
    ))
}

/// RH1 step 2: markers whose drift re-injection should preserve the
/// original block position rather than re-batching at the marker line.
/// Imports and the emit_block-class markers (state / cause / poke*)
/// all exhibit HARD-FRICTION-2: a single-graft drift via the batched
/// path lands the drifted block at marker_idx+1, displacing every
/// later graft and changing app.hoon's sha256 even though the file is
/// logically equivalent. Peek is excluded because `emit_peek_chain`
/// anchors against the structural terminal `~` rather than the marker
/// line, so a per-graft strip-and-reinject would need different
/// machinery; the chain shape is structurally ordered already.
fn marker_supports_position_preserve(marker: Marker) -> bool {
    matches!(
        marker,
        Marker::Imports
            | Marker::State
            | Marker::Cause
            | Marker::PokePrelude
            | Marker::Poke
            | Marker::PokePostlude
    )
}

/// RH1 step 2: dispatch to the appropriate single-graft emitter for
/// drift re-injection. `marker_supports_position_preserve` gates the
/// caller — markers excluded there should never reach this dispatch.
fn emit_position_preserving(
    lines: &mut Vec<String>,
    insert_idx: usize,
    indent: &str,
    marker: Marker,
    g: &Graft,
) {
    match marker {
        Marker::Imports => {
            emit_imports_block_single_at(lines, insert_idx, indent, g);
        }
        Marker::State
        | Marker::Cause
        | Marker::PokePrelude
        | Marker::Poke
        | Marker::PokePostlude => {
            emit_block_single_at(lines, insert_idx, indent, marker, g);
        }
        Marker::Peek | Marker::DomainEffect | Marker::EffectUnion => {
            unreachable!(
                "emit_position_preserving called with non-preserving marker {:?}; \
                 marker_supports_position_preserve gate should have rejected it",
                marker
            );
        }
    }
}

/// Insert one graft's banner-wrapped block at an explicit line index.
/// Used by the drift re-injection path to preserve original block
/// ordering across non-semantic manifest edits (RH1 step 2). `emit_block`
/// remains the batch-at-marker entry point used for fresh injects.
fn emit_block_single_at(
    lines: &mut Vec<String>,
    insert_idx: usize,
    indent: &str,
    marker: Marker,
    g: &Graft,
) {
    let mut composed: Vec<String> = Vec::new();
    composed.push(begin_banner_with_sha(&g.name, marker, g.sha256_short()));
    let body = g
        .block(marker)
        .expect("emit_block_single_at called with a graft missing this marker")
        .trimmed_body();
    for line in body.lines() {
        composed.push(line.to_string());
    }
    composed.push(end_banner(&g.name, marker));
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
        lines.insert(insert_idx + offset, line);
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

/// Phase 03f Lever 1: synthesize the typed effect union beneath the
/// `nockup:effect-union` marker. REPLACE-IF-PRESENT semantics — the
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
    for i in (union_idx + 1)..lines.len() {
        let trimmed = lines[i].trim();
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
            for i in (union_idx + 1)..scan_end {
                let trimmed = lines[i].trim();
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

/// Codegen banner has no per-graft name (the codegen is global to the
/// kernel, not per-graft). Distinguishes from `begin_banner` which
/// embeds the contributing graft's name.
fn codegen_begin_banner(marker: Marker) -> String {
    format!("::  graft-inject:{}:begin", marker.label())
}

fn codegen_end_banner(marker: Marker) -> String {
    format!("::  graft-inject:{}:end", marker.label())
}

/// Recognize the legacy `+$  effect  *` open-type line. Tolerates one or
/// more spaces between tokens (Hoon two-space-law authors usually write
/// `+$  effect  *`). Rejects custom forms like `+$ effect (list @t)` so
/// the codegen leaves user-typed effects alone (a stderr warning is the
/// right surface for those, not a silent rewrite).
fn is_bare_effect_open_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.len() == 3 && parts[0] == "+$" && parts[1] == "effect" && parts[2] == "*"
}

/// Phase 03f Lever 1.5: scan domain code for narrow `(list <X>-effect)`
/// bindings that will nest-fail at a cross-graft `weld`. Skips lines
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

/// Phase 03f Lever 1: rewrite a kernel's bare `+$  effect  *` line to
/// the post-migration marker shape — placeholder `+$ domain-effect`
/// block, `nockup:domain-effect` marker, `nockup:effect-union` marker,
/// and a temporary `+$ effect *` that the codegen pass replaces on the
/// same `--apply` run.
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
/// RH1 step 2 single-graft variant of `emit_imports_block`. Inserts at
/// an explicit line index (the begin-banner position the drift path
/// captured before stripping) so re-injection preserves graft order in
/// the imports block. Dedup logic mirrors the batch emitter.
fn emit_imports_block_single_at(
    lines: &mut Vec<String>,
    insert_idx: usize,
    indent: &str,
    g: &Graft,
) {
    let mut seen: HashSet<String> = lines
        .iter()
        .filter_map(|l| parse_glob_import(l).map(|s| s.to_string()))
        .collect();

    let mut composed: Vec<String> = Vec::new();
    composed.push(begin_banner_with_sha(&g.name, Marker::Imports, g.sha256_short()));
    let body = g
        .block(Marker::Imports)
        .expect("emit_imports_block_single_at called with a graft missing imports")
        .trimmed_body();
    for line in body.lines() {
        if let Some(name) = parse_glob_import(line) {
            if !seen.insert(name.to_string()) {
                continue;
            }
        }
        composed.push(line.to_string());
    }
    composed.push(end_banner(&g.name, Marker::Imports));
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
        lines.insert(insert_idx + offset, line);
    }
}

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

/// Prefix form of the begin banner — used for line-prefix matching when
/// scanning the source for existing injections. Banners emitted into the
/// composed file always carry a ` sha256:<short>` suffix (see
/// `begin_banner_with_sha`); this prefix matches both the new and the
/// pre-A2 legacy format and lets the idempotence check distinguish them.
fn begin_banner(name: &str, marker: Marker) -> String {
    format!("::  graft-inject:{}:{}:begin", name, marker.label())
}

/// Full begin-banner form emitted into the composed file. The 12-char
/// sha256 prefix lets a re-run detect manifest drift: if the user edits
/// `<graft>.toml` (e.g. swaps a `[graft.gates]` selection or bumps a
/// version), the sha256 changes, the embedded prefix doesn't match, and
/// the inject pass strips the stale banner pair and re-emits with the
/// new one. Pre-A2 banners (no sha256 suffix) are detected by the same
/// scan and force-reinjected once on first run after the upgrade.
fn begin_banner_with_sha(name: &str, marker: Marker, sha256_short: &str) -> String {
    format!(
        "::  graft-inject:{}:{}:begin sha256:{}",
        name,
        marker.label(),
        sha256_short
    )
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
fn strip_banner_pair(
    lines: &mut Vec<String>,
    graft_name: &str,
    marker: Marker,
) -> Option<usize> {
    let begin_prefix = begin_banner(graft_name, marker);
    let end_str = end_banner(graft_name, marker);
    let begin_idx = lines
        .iter()
        .position(|l| l.trim().starts_with(&begin_prefix))?;
    let end_idx = lines
        .iter()
        .enumerate()
        .skip(begin_idx + 1)
        .find(|(_, l)| l.trim() == end_str)
        .map(|(i, _)| i)?;
    lines.drain(begin_idx..=end_idx);
    Some(begin_idx)
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

    /// Skip the Phase 03f Lever 1 auto-migration of legacy
    /// `+$  effect  *` to the marker-shape (`nockup:domain-effect` +
    /// `nockup:effect-union` + bare `+$ effect *`). Default behavior
    /// is to migrate transparently; `--no-migrate` is the opt-out for
    /// paranoid review. The codegen pass still skips kernels without
    /// the `nockup:effect-union` marker.
    #[arg(long = "no-migrate")]
    no_migrate: bool,
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
    let raw_source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Phase 03f Lever 1: optional auto-migration of legacy `+$ effect *`
    // to the marker shape. Runs before the inject pass so the codegen
    // can take over the rewritten line in the same `--apply` invocation.
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

        // BARE_SCAFFOLD ships with the seven non-codegen markers (imports,
        // state, cause, poke-prelude, poke, poke-postlude, peek). The two
        // codegen markers (domain-effect, effect-union) land via commit 7
        // auto-migration and the commit 8 template refresh, so they are
        // expected to be missing here.
        assert_eq!(report.markers_in_source.len(), 7);
        assert_eq!(report.markers_missing.len(), 2);
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
            "domain-effect",
            "effect-union",
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
            no_migrate: false,
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

    // ---------------------------------------------------------------
    // Phase 03f Lever 1: typed effect-union codegen
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
        let (first, _) = inject(SCAFFOLD_WITH_UNION_MARKER, &[g.clone()]).unwrap();
        let (second, report) = inject(&first, &[g]).unwrap();
        assert_eq!(first, second, "second run must be byte-identical");
        assert_eq!(report.codegen.status, CodegenStatus::Unchanged);
    }

    #[test]
    fn codegen_replace_grows_when_graft_added() {
        let alpha = synthetic_graft_with_effect("alpha", 10);
        let beta = synthetic_graft_with_effect("beta", 20);
        let (one, _) = inject(SCAFFOLD_WITH_UNION_MARKER, &[alpha.clone()]).unwrap();
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
    // Phase 03f Lever 1.5: weld-friction lint
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
    // Phase 03f Lever 1: migrate_legacy_effect
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
}
