//! ManifestSummary — read the graft manifest dir at boot and expose it
//! through [`crate::api::StatusResponse`] so operators can confirm via
//! HTTP that a gate swap or graft compose actually landed (R6 §2).
//!
//! Mirrors the [`SettlementConfig`](crate::config::SettlementConfig)
//! resolve-at-boot pattern: a snapshot of the manifest state is loaded
//! once at server start, stored in [`AppState`](crate::api::AppState),
//! and serialized by `/status`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Snapshot of the graft manifests that composed the kernel — graft
/// names, per-manifest sha256 (the same digest `nockup graft inject`
/// banners on each block, R6 positive finding #17), and the resolved
/// verify-gate selection.
#[derive(Clone, Debug, Serialize)]
pub struct ManifestSummary {
    /// Active verify-gate name. `"default-hash"` when no graft declares
    /// `[graft.gates]`. Otherwise the gate selection from the
    /// highest-priority graft with one (in practice, settle-graft).
    /// `gate-chain` selections render as `"A&B"` joined with `&`.
    pub gate: String,
    /// Graft names discovered in the manifest dir, sorted alphabetically
    /// for stable JSON output.
    pub grafts: Vec<String>,
    /// Per-graft sha256 of the raw manifest TOML bytes — same digest the
    /// graft-inject CLI surfaces in its preview report.
    pub manifest_shas: BTreeMap<String, String>,
}

impl ManifestSummary {
    /// Empty fallback used when the manifest dir is absent (e.g., the
    /// hull was started from a directory that doesn't contain a graft
    /// project). Reports gate=default-hash, no grafts.
    pub fn empty() -> Self {
        Self {
            gate: "default-hash".into(),
            grafts: Vec::new(),
            manifest_shas: BTreeMap::new(),
        }
    }

    /// Load all `*.toml` manifests in `dir` and summarize them.
    ///
    /// Files lacking a `[graft]` table are silently skipped (matches
    /// `graft-inject`'s discovery semantics). A missing `dir` yields
    /// [`Self::empty`] — running the hull outside a graft project
    /// scaffold is supported.
    pub fn from_manifest_dir(dir: &Path) -> Result<Self, ManifestSummaryError> {
        if !dir.exists() {
            return Ok(Self::empty());
        }
        let entries = fs::read_dir(dir).map_err(|e| ManifestSummaryError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let mut by_priority: Vec<DiscoveredGraft> = Vec::new();
        let mut manifest_shas: BTreeMap<String, String> = BTreeMap::new();

        for entry in entries {
            let entry = entry.map_err(|e| ManifestSummaryError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let raw = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let parsed: ManifestFile = match toml::from_str(&raw) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let Some(graft) = parsed.graft else { continue };
            manifest_shas.insert(graft.name.clone(), sha256_hex(raw.as_bytes()));
            by_priority.push(DiscoveredGraft {
                name: graft.name,
                priority: graft.priority.unwrap_or(0),
                gate: graft.gates.as_ref().and_then(GateSelection::resolve),
            });
        }

        let mut grafts: Vec<String> = manifest_shas.keys().cloned().collect();
        grafts.sort();

        // Active gate = the highest-priority graft's selection if any
        // exists. Lower `priority` wins (matches graft-inject's
        // `priority.cmp(&b.priority)` ascending sort).
        by_priority.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(&b.name)));
        let gate = by_priority
            .iter()
            .find_map(|g| g.gate.clone())
            .unwrap_or_else(|| "default-hash".into());

        Ok(Self {
            gate,
            grafts,
            manifest_shas,
        })
    }
}

/// Errors raised while reading the manifest dir. Parse errors on
/// individual files are tolerated (the file is skipped); only I/O
/// failures on the dir itself bubble up.
#[derive(Debug)]
pub enum ManifestSummaryError {
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for ManifestSummaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "manifest dir {} unreadable: {}", path.display(), source)
            }
        }
    }
}

impl std::error::Error for ManifestSummaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// TOML schema — minimal mirror of tools/graft-inject/src/manifest.rs.
// Kept narrow on purpose: we read the *shape*, not the body.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ManifestFile {
    #[serde(default)]
    graft: Option<Graft>,
}

#[derive(Deserialize)]
struct Graft {
    name: String,
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    gates: Option<GateSelection>,
}

#[derive(Deserialize)]
struct GateSelection {
    #[serde(default)]
    gate: Option<String>,
    #[serde(default, rename = "gate-chain")]
    gate_chain: Option<Vec<String>>,
}

impl GateSelection {
    fn resolve(&self) -> Option<String> {
        if let Some(g) = &self.gate {
            return Some(g.clone());
        }
        if let Some(chain) = &self.gate_chain {
            if !chain.is_empty() {
                return Some(chain.join("&"));
            }
        }
        None
    }
}

struct DiscoveredGraft {
    name: String,
    priority: i32,
    gate: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_toml(dir: &Path, name: &str, contents: &str) {
        let mut f = fs::File::create(dir.join(name)).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn missing_dir_yields_empty() {
        let s = ManifestSummary::from_manifest_dir(Path::new("/nonexistent/dir")).unwrap();
        assert_eq!(s.gate, "default-hash");
        assert!(s.grafts.is_empty());
    }

    #[test]
    fn discovers_grafts_and_default_gate() {
        let tmp = tempdir();
        write_toml(
            tmp.path(),
            "settle-graft.toml",
            r#"
[graft]
name = "settle-graft"
priority = 10
version = "0.1.0"
"#,
        );
        write_toml(
            tmp.path(),
            "mint-graft.toml",
            r#"
[graft]
name = "mint-graft"
priority = 20
version = "0.1.0"
"#,
        );

        let s = ManifestSummary::from_manifest_dir(tmp.path()).unwrap();
        assert_eq!(s.gate, "default-hash", "no [graft.gates] block -> default");
        assert_eq!(s.grafts, vec!["mint-graft", "settle-graft"]);
        assert_eq!(s.manifest_shas.len(), 2);
        assert!(s.manifest_shas["settle-graft"].len() == 64);
    }

    #[test]
    fn surfaces_single_gate_selection() {
        let tmp = tempdir();
        write_toml(
            tmp.path(),
            "settle-graft.toml",
            r#"
[graft]
name = "settle-graft"
priority = 10
version = "0.1.0"
[graft.gates]
gate = "manifest-verify"
"#,
        );
        let s = ManifestSummary::from_manifest_dir(tmp.path()).unwrap();
        assert_eq!(s.gate, "manifest-verify");
    }

    #[test]
    fn surfaces_gate_chain_joined_with_amp() {
        let tmp = tempdir();
        write_toml(
            tmp.path(),
            "settle-graft.toml",
            r#"
[graft]
name = "settle-graft"
priority = 10
version = "0.1.0"
[graft.gates]
gate-chain = ["manifest-verify", "schnorr"]
"#,
        );
        let s = ManifestSummary::from_manifest_dir(tmp.path()).unwrap();
        assert_eq!(s.gate, "manifest-verify&schnorr");
    }

    #[test]
    fn highest_priority_gate_wins_on_multi_graft() {
        let tmp = tempdir();
        // Lower priority sorts first; settle-graft (priority=10) beats
        // mint-graft (priority=20). Mint declaring a gate is contrived but
        // exercises the priority ordering.
        write_toml(
            tmp.path(),
            "settle-graft.toml",
            r#"
[graft]
name = "settle-graft"
priority = 10
version = "0.1.0"
[graft.gates]
gate = "schnorr"
"#,
        );
        write_toml(
            tmp.path(),
            "mint-graft.toml",
            r#"
[graft]
name = "mint-graft"
priority = 20
version = "0.1.0"
[graft.gates]
gate = "manifest-verify"
"#,
        );
        let s = ManifestSummary::from_manifest_dir(tmp.path()).unwrap();
        assert_eq!(s.gate, "schnorr", "priority=10 wins over priority=20");
    }

    #[test]
    fn skips_files_without_graft_table() {
        let tmp = tempdir();
        write_toml(tmp.path(), "settle-graft.toml", r#"
[graft]
name = "settle-graft"
priority = 10
version = "0.1.0"
"#);
        // No [graft] table — skipped silently.
        write_toml(tmp.path(), "junk.toml", "[other]\nx = 1\n");
        let s = ManifestSummary::from_manifest_dir(tmp.path()).unwrap();
        assert_eq!(s.grafts, vec!["settle-graft"]);
    }

    // Minimal in-memory tempdir to avoid pulling the `tempfile` crate
    // into vesl-hull's dep graph just for tests.
    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    fn tempdir() -> TempDir {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("vesl-hull-manifest-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
}
