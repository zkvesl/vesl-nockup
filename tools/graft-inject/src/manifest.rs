//! Manifest schema, TOML loader, and non-gate validators.
//!
//! Audit §3.2 extraction: items moved verbatim from the pre-split
//! lib.rs (formerly main.rs). Gate-specific validators stay in the
//! crate root until step 5 promotes them into `gates.rs`.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::gates::{apply_gate_selection, validate_gate_selection};
use crate::marker::Marker;

/// Top-level wrapper for the `[graft]` table in a manifest file.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ManifestFile {
    pub(crate) graft: Graft,
}

/// A discovered graft package — identity, ordering, and per-marker blocks.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Graft {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) priority: i32,
    #[serde(default)]
    pub(crate) after: Vec<String>,
    pub(crate) blocks: GraftBlocks,
    /// Optional gate selection from `[graft.gates]`. When set, the
    /// manifest's poke body has its default hash-gate constructions
    /// rewritten to call into `vesl-gates`, and the imports block gains
    /// a `/+  vesl-gates` line. See `apply_gate_selection`.
    #[serde(default)]
    pub(crate) gates: Option<GateSelection>,
    /// Optional `[graft.types]` table. Names the per-graft `effect` and
    /// `cause` types so `graft-inject` can emit a typed
    /// `+$ effect $%(...)` union at the `nockup:effect-union` marker.
    /// `cause` is read forward-compat for cause destructuring; current
    /// codegen reads only `effect`. Manifests without this table parse
    /// with `types == None`.
    #[serde(default)]
    pub(crate) types: Option<GraftTypes>,
    /// Hex sha256 of the raw TOML bytes. Populated by `load_manifest` at
    /// discovery time so the composer can surface per-manifest digests
    /// in the preview report and `--list --json` output (AUDIT 2026-04-19
    /// H-10 supply-chain surface).
    #[serde(skip, default)]
    pub(crate) sha256: String,
}

/// `[graft.gates]` selection. `gate` and `gate-chain` are mutually
/// exclusive; both unset means the manifest keeps its default
/// hash-gate. Names are validated against `TIER_1A_GATES` at discovery.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GateSelection {
    #[serde(default)]
    pub(crate) gate: Option<String>,
    #[serde(default, rename = "gate-chain")]
    pub(crate) gate_chain: Option<Vec<String>>,
}

/// `[graft.types]` declarations. Lets the codegen pass emit a typed
/// effect union without parsing Hoon. `effect` is the bare type name
/// the graft exports for its effect variant (e.g. `settle-effect`);
/// the codegen splats it into the `+$ effect $%(...)` union at the
/// `nockup:effect-union` marker. `cause` is parsed for forward-compat
/// with cause destructuring and currently unused.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GraftTypes {
    #[serde(default)]
    pub(crate) effect: Option<String>,
    #[serde(default)]
    pub(crate) cause: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct GraftBlocks {
    pub(crate) imports: Option<Block>,
    pub(crate) state: Option<Block>,
    pub(crate) cause: Option<Block>,
    /// Code spliced ahead of the `?-  -.u.act` switch. Composes as `?:`
    /// short-circuit guards (validate / fsm rejection paths) or as
    /// `=/  pre-snapshot` bindings that scope through the rest of the
    /// gate (index-graft pre-state capture). Multiple preludes stack in
    /// priority order; the first to short-circuit ends the gate before
    /// the switch runs. See docs/graft-manifest.md §poke-prelude.
    #[serde(rename = "poke-prelude")]
    pub(crate) poke_prelude: Option<Block>,
    pub(crate) poke: Option<Block>,
    /// Code spliced after the `?-  -.u.act` switch. The switch's
    /// `[(list effect) _state]` result is bound to `out`; postludes
    /// rebind `out` (e.g. `=/  out  (transform out)`) and the gate
    /// returns the final `out`. Multiple postludes compose left-to-right
    /// in priority order. See docs/graft-manifest.md §poke-postlude.
    #[serde(rename = "poke-postlude")]
    pub(crate) poke_postlude: Option<Block>,
    pub(crate) peek: Option<Block>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Block {
    pub(crate) body: String,
}

impl Block {
    /// Composition-ready body — leading and trailing newlines stripped so
    /// the inject step's indent-prepending lands on the first content line.
    pub(crate) fn trimmed_body(&self) -> &str {
        self.body.trim_matches('\n')
    }
}

impl Graft {
    /// Block for a marker, if the manifest declares one.
    pub(crate) fn block(&self, marker: Marker) -> Option<&Block> {
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
            Marker::DomainEffect | Marker::EffectUnion | Marker::LoadDefaults => None,
        }
    }

    /// First 12 hex chars of the manifest sha256, for banner embedding.
    /// Twelve chars (48 bits) is enough to disambiguate any realistic
    /// manifest set with no collision risk while keeping the banner
    /// scannable. Falls back to the full sha if it's somehow shorter.
    pub(crate) fn sha256_short(&self) -> &str {
        let n = 12.min(self.sha256.len());
        &self.sha256[..n]
    }
}

/// Load a single `*.toml` manifest. Returns Ok(None) if the file lacks a
/// `[graft]` table (caller skips it); Err for parse or I/O failures.
/// Populates `Graft::sha256` from the raw file bytes so downstream code
/// can surface provenance without reopening the file.
pub(crate) fn load_manifest(path: &Path) -> Result<Option<Graft>> {
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
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
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
/// the manifest's poke + imports blocks.
pub(crate) fn discover_grafts(lib_dir: &Path) -> Result<Vec<Graft>> {
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
pub(crate) fn validate_unique_type_names(
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
pub(crate) fn validate_types(g: &Graft, path: &Path) -> Result<()> {
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
pub(crate) fn build_chain_block(chain: &[String]) -> String {
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
pub(crate) fn atomic_write(path: &Path, contents: &str) -> Result<()> {
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
pub(crate) fn is_valid_graft_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[test]
    fn loader_rejects_missing_graft_table() {
        let dir = tempdir_for_test("loader_no_graft_table");
        let path = dir.join("not-a-graft.toml");
        fs::write(&path, "[other]\nkey = \"value\"\n").unwrap();
        let result = load_manifest(&path).expect("toml itself parses");
        assert!(result.is_none(), "manifest without [graft] must return None");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------- AUDIT 2026-04-19 H-11..H-14 regressions ----------

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
}
