//! Public domain types + shared state + on-disk note counter persistence.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use nockapp::NockApp;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use vesl_core::MerkleTree;

use crate::config::{RbacConfig, SettlementConfig};
use crate::manifest_summary::ManifestSummary;
use crate::settle_builder::SettlePayloadBuilder;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A key-value field. The atomic unit of committed data.
/// Community developers: replace this with your domain primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Shared state for the HTTP API.
///
/// Held behind `Arc<Mutex<...>>`. A single mutex suffices since no
/// handler blocks for long.
pub struct AppState {
    pub app: NockApp,
    pub fields: Vec<Field>,
    pub tree: Option<MerkleTree>,
    pub hull_id: u64,
    pub note_counter: u64,
    pub settlement: SettlementConfig,
    pub output_dir: PathBuf,
    /// Snapshot of the graft manifests that composed the kernel (R6 §2).
    /// Surfaced verbatim via `/status` so operators can confirm a gate
    /// swap or graft compose actually landed.
    pub manifest: ManifestSummary,
    /// Gate-aware `%settle-note` payload assembly (R6 §3). Binary picks
    /// the impl from `manifest.gate` at boot; the stock `/settle`
    /// handler dispatches through it so a manifest-verify (or other
    /// catalog-gate) kernel succeeds without a custom route.
    pub settle_builder: Arc<dyn SettlePayloadBuilder>,
    /// RBAC pre-check configuration. When `enabled`, `/commit` and
    /// `/settle` peek `[%rbac-has-perm pubkey perm ~]` against the
    /// composed rbac-graft before poking; an `%.n` (or absent) result
    /// short-circuits to HTTP 403 without invoking the kernel. The
    /// pubkey is taken from the `X-Hull-Pubkey` request header. Default
    /// is disabled — see `RbacConfig::from_toml`.
    pub rbac: RbacConfig,
    /// Readiness flag for the `/health` gate. False while the hull is
    /// still booting (PMA snapshot verify, post-boot warmup, cache
    /// priming, etc.); true once it can serve real traffic. A k8s
    /// readiness probe or load-balancer hitting `/health` during the
    /// boot window gets 503 with a `{"status":"booting"}` body and
    /// does NOT route traffic; flipping this to true is what lets
    /// traffic in.
    ///
    /// Construction sites set this false and the orchestrator (the
    /// binary's serve arm) flips it true after any post-boot warmup —
    /// see `templates/vesl/src/main.rs` for the canonical pattern.
    pub kernel_ready: AtomicBool,
}

pub type SharedState = Arc<Mutex<AppState>>;

// ---------------------------------------------------------------------------
// Note counter persistence
// ---------------------------------------------------------------------------

const NOTE_COUNTER_FILE: &str = ".hull_note_counter";

pub fn load_note_counter(output_dir: &std::path::Path) -> u64 {
    let path = output_dir.join(NOTE_COUNTER_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub(super) fn save_note_counter(output_dir: &std::path::Path, counter: u64) {
    // AUDIT 2026-04-17 L-05: atomic write via tempfile + rename.
    // Eliminates torn writes on mid-write kill or coincidental racing
    // writers, but does not prevent read-modify-write races between two
    // hull processes sharing `output_dir` — that's still a
    // single-writer invariant by design.
    let path = output_dir.join(NOTE_COUNTER_FILE);
    let tmp = output_dir.join(format!("{NOTE_COUNTER_FILE}.{}.tmp", std::process::id()));
    if std::fs::write(&tmp, counter.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CommitRequest {
    pub fields: Vec<Field>,
}

#[derive(Serialize)]
pub struct CommitResponse {
    pub field_count: usize,
    pub merkle_root: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct SettleResponse {
    pub note_id: u64,
    pub merkle_root: String,
    pub settled: bool,
    pub effects_count: usize,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub field: Field,
    /// Hex-encoded tip5 Merkle root to verify against.
    pub merkle_root: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub field_key: String,
    pub merkle_root: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub has_tree: bool,
    pub field_count: usize,
    pub merkle_root: Option<String>,
    pub notes_settled: u64,
    pub hull_id: u64,
    pub settlement_mode: String,
    /// Active verify-gate name (R6 §2). `"default-hash"` when no graft
    /// declares `[graft.gates]`. Mirrors `ManifestSummary::gate`.
    pub gate: String,
    /// Graft names that composed the kernel, alphabetically sorted (R6 §2).
    pub grafts: Vec<String>,
    /// Per-graft sha256 of the raw manifest TOML — same digest
    /// `nockup graft inject` banners on each block (R6 §2 / R6 positive
    /// finding #17).
    pub manifest_shas: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    /// `"ok"` when the hull is ready to serve traffic; `"booting"`
    /// when [`AppState::kernel_ready`] is still false. The HTTP
    /// status code (200 / 503) tracks the same gate.
    pub status: String,
    /// Coarse stage label for the booting state — surfaced so an
    /// operator scraping `/health` knows whether the hull is mid-PMA
    /// verify, mid-warmup, etc. `None` (omitted from the JSON) when
    /// `status == "ok"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ErrorBody {
    pub(super) error: String,
}
