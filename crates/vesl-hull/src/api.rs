//! HTTP API — axum server for the generic hull.
//!
//! Three domain endpoints: /commit, /settle, /verify.
//! Plus /health and /status for ops.
//!
//! Community developers: modify /commit to accept your domain data,
//! adjust the Merkle leaf encoding, and add domain-specific endpoints.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use nockapp::wire::{SystemWire, Wire};
use nockapp::NockApp;
use nockvm::noun::NounAllocator;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::limit::RequestBodyLimitLayer;

use vesl_core::{
    classify_effects, decode_settle_error, effect_head_tag, fetch_receipt, format_tip5,
    ChainClient, MerkleTree, NounSlab, PokeCrashError, PokeOutcome, RejectionReason,
    SettlementMode, TxReceipt, VerifyTxError,
};

use crate::config::SettlementConfig;
use crate::manifest_summary::ManifestSummary;
use crate::settle_builder::{SettleBuilderError, SettleContext, SettlePayloadBuilder};
use crate::verify::field_to_leaf_bytes;

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

fn save_note_counter(output_dir: &std::path::Path, counter: u64) {
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
    pub status: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// Input limits
// ---------------------------------------------------------------------------

/// Maximum fields per /commit request.
const MAX_FIELDS: usize = 500;
/// Maximum size of a single field key or value in bytes.
const MAX_FIELD_BYTES: usize = 100_000;

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

/// Set at startup when `--no-auth` is passed. Replaces the previous
/// `unsafe { env::set_var() }` pattern (V-N01).
static NO_AUTH: AtomicBool = AtomicBool::new(false);

/// Constant-time byte-slice equality. A plain `==` on the API key would
/// return as soon as two bytes differ, leaking the position of the first
/// mismatch through response timing; this folds every byte before
/// returning. The length check is deliberate — key length is not the
/// secret, and comparing unequal-length buffers any other way leaks more.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// API key authentication middleware (C-004).
///
/// Checks `Authorization: Bearer <key>` against the HULL_API_KEY env
/// var. /health is always exempt. Auth is required unless `--no-auth`
/// is passed at startup.
async fn check_api_key(
    req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    // --no-auth disables auth entirely (C-004: explicit opt-out)
    if NO_AUTH.load(Ordering::Relaxed) {
        return Ok(next.run(req).await);
    }

    let expected = match std::env::var("HULL_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let authorized = provided
        .map(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);
    if authorized {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Pre-flight auth check (C-004). Call before starting the server.
///
/// Assumes a loopback bind. Production callers should use
/// `check_auth_config_with_bind` so the M-15 non-loopback refusal runs.
pub fn check_auth_config(no_auth: bool) -> Result<(), String> {
    check_auth_config_with_bind(no_auth, "127.0.0.1")
}

/// CLI-entry-point variant — knows the bind address, so it can reject
/// `--no-auth` on non-loopback binds.
///
/// AUDIT 2026-04-19 M-15: `--no-auth` on an exposed bind leaks state
/// and lets anyone poke the kernel. Fail-closed when `no_auth` is set
/// AND `bind_addr` isn't loopback.
pub fn check_auth_config_with_bind(no_auth: bool, bind_addr: &str) -> Result<(), String> {
    if no_auth {
        if !is_loopback_bind(bind_addr) {
            return Err(format!(
                "--no-auth on bind address `{bind_addr}` is refused. \
                 --no-auth is only permitted on loopback binds (127.0.0.1, ::1, localhost). \
                 Set HULL_API_KEY and drop --no-auth, or change bind-addr to loopback."
            ));
        }
        NO_AUTH.store(true, Ordering::Relaxed);
        return Ok(());
    }
    match std::env::var("HULL_API_KEY") {
        Ok(k) if !k.is_empty() => Ok(()),
        _ => Err(
            "HULL_API_KEY is not set. Either set it or pass --no-auth for local dev.\n\
             Example: HULL_API_KEY=mysecret hull --port 3000"
                .into(),
        ),
    }
}

fn is_loopback_bind(bind_addr: &str) -> bool {
    let host = bind_addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind_addr);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    matches!(host, "127.0.0.1" | "::1" | "localhost")
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the axum router with all hull endpoints.
///
/// Equivalent to `router_with_extra(state, Router::new())`. Callers that
/// want to mount their own routes alongside the hull's stock ones must
/// use [`router_with_extra`] or [`serve_with_extra_routes`] — a bare
/// `Router::merge(router(state), my_routes)` will NOT apply the auth,
/// body-limit, or rate-limit layers to the merged-in routes (R6 §1).
pub fn router(state: SharedState) -> Router {
    router_with_extra(state, Router::new())
}

/// Build the router with extra custom routes mounted alongside the hull's
/// stock endpoints, layered uniformly under the same middleware stack
/// (auth, 4 MiB body limit, 200/60s rate limit + 256-deep buffer).
///
/// Layers wrap the **merged** Router, so they apply to every route
/// regardless of which half it came from. This is the canonical
/// composition entry point post-R6 §1.
pub fn router_with_extra(state: SharedState, extra: Router<SharedState>) -> Router {
    stock_routes()
        .merge(extra)
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(|_: tower::BoxError| async {
                    StatusCode::TOO_MANY_REQUESTS
                }))
                .buffer(256)
                .rate_limit(200, std::time::Duration::from_secs(60)),
        )
        .layer(RequestBodyLimitLayer::new(4 * 1024 * 1024)) // H-001
        .layer(middleware::from_fn(check_api_key))
        .with_state(state)
}

/// The hull's stock routes, with no layers and no state applied. Private
/// so callers cannot accidentally re-introduce the pre-fix
/// `Router::merge(router(state), my_routes)` pattern that bypassed
/// middleware (R6 §1).
fn stock_routes() -> Router<SharedState> {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/commit", post(commit_handler))
        .route("/settle", post(settle_handler))
        .route("/verify", post(verify_handler))
        .route("/tx/{tx_id}", get(verify_tx_handler))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Poke the kernel with a 30s timeout, classifying the result into a
/// typed [`PokeOutcome`]. `log_prefix` names the poke for stderr logging
/// (e.g. "register", "settle") on the crash paths.
///
/// Callers match the returned outcome to dispatch on success / rejection /
/// crash without scraping stderr or string-matching effect tags blindly.
/// `classify_effects` (in `vesl-core`) routes a non-empty effect list by
/// the head tag of its first effect; the wrapper here adds the
/// timeout, `NockAppError`, and empty-list cases that the classifier
/// cannot see from `effects` alone.
async fn poke_kernel_with_timeout(
    app: &mut NockApp,
    poke: NounSlab,
    log_prefix: &str,
) -> PokeOutcome {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        app.poke(SystemWire.to_wire(), poke),
    )
    .await
    {
        Err(_) => {
            eprintln!("kernel {log_prefix} poke timed out");
            PokeOutcome::Crashed {
                error: PokeCrashError::Timeout,
            }
        }
        Ok(Err(e)) => {
            eprintln!("kernel {log_prefix} poke failed: {e}");
            PokeOutcome::Crashed {
                error: PokeCrashError::KernelPoke(e),
            }
        }
        Ok(Ok(effects)) => classify_effects(effects),
    }
}

/// Map a [`PokeCrashError`] to the handler's HTTP error tuple. Shared by
/// the handlers because the crash mapping is identical across pokes —
/// timeout → 504, `NockAppError` → 500, protocol violation (kernel emitted
/// an unparsable effect) → 502.
fn crash_to_error(err: PokeCrashError) -> (StatusCode, Json<ErrorBody>) {
    match err {
        PokeCrashError::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(ErrorBody {
                error: "kernel operation timed out".into(),
            }),
        ),
        PokeCrashError::KernelPoke(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "internal error".into(),
            }),
        ),
        PokeCrashError::UnexpectedTag { tag, .. } => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("kernel emitted unparsable effect (head tag: {tag:?})"),
            }),
        ),
    }
}

/// Temporary adapter — flatten a [`PokeOutcome`] back to the
/// `Result<Vec<NounSlab>, (StatusCode, Json<ErrorBody>)>` shape the
/// handlers consume today. The shape is preserved so existing handler
/// bodies stay untouched while the typed-outcome surface lands; the
/// adapter is removed once each handler migrates to direct `PokeOutcome`
/// matching.
fn collapse_to_legacy_result(
    outcome: PokeOutcome,
) -> Result<Vec<NounSlab>, (StatusCode, Json<ErrorBody>)> {
    match outcome {
        PokeOutcome::Accepted { effects } => Ok(effects),
        PokeOutcome::Rejected {
            reason: RejectionReason::Unknown,
        } => Ok(Vec::new()),
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelError { raw_effects, .. },
        }
        | PokeOutcome::Rejected {
            reason: RejectionReason::KernelRejected { raw_effects, .. },
        }
        | PokeOutcome::Rejected {
            reason: RejectionReason::GateDenied { raw_effects, .. },
        } => Ok(raw_effects),
        PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied { .. },
        } => {
            // classify_effects never produces RbacDenied; the hull-side
            // RBAC pre-check that constructs it lands in a follow-up commit.
            unreachable!("classify_effects does not produce RbacDenied")
        }
        PokeOutcome::Crashed {
            error: PokeCrashError::Timeout,
        } => Err((
            StatusCode::GATEWAY_TIMEOUT,
            Json(ErrorBody {
                error: "kernel operation timed out".into(),
            }),
        )),
        PokeOutcome::Crashed {
            error: PokeCrashError::KernelPoke(_),
        } => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "internal error".into(),
            }),
        )),
        PokeOutcome::Crashed {
            error: PokeCrashError::UnexpectedTag { raw_effects, .. },
        } => Ok(raw_effects),
    }
}

/// Decode the `existing-root` atom from a `[%settle-register-rejected
/// hull=@ existing-root=@]` effect (audit L-09). Returns lowercase hex of
/// the atom's LE bytes — the same byte representation `tip5_to_atom_le_bytes`
/// produced at register time. Returns `None` if the effect's tail isn't a
/// cell with an atom on the right; callers fall back to a generic body
/// hint in that case.
fn decode_register_rejected_existing_root(effect: &NounSlab) -> Option<String> {
    // SAFETY: the slab outlives this call.
    let root_noun = unsafe { *effect.root() };
    let space = effect.noun_space();
    let outer = root_noun.in_space(&space).as_cell().ok()?;
    let inner = outer.tail().as_cell().ok()?;
    let existing_atom = inner.tail().as_atom().ok()?;
    let bytes = existing_atom.as_ne_bytes();
    let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    if trimmed_len == 0 {
        return Some(String::from("00"));
    }
    Some(hex::encode(&bytes[..trimmed_len]))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

async fn status(State(state): State<SharedState>) -> Json<StatusResponse> {
    let st = state.lock().await;
    let merkle_root = st.tree.as_ref().map(|t| format_tip5(&t.root()));
    Json(StatusResponse {
        has_tree: st.tree.is_some(),
        field_count: st.fields.len(),
        merkle_root,
        notes_settled: st.note_counter,
        hull_id: st.hull_id,
        settlement_mode: st.settlement.mode.to_string(),
        gate: st.manifest.gate.clone(),
        grafts: st.manifest.grafts.clone(),
        manifest_shas: st.manifest.manifest_shas.clone(),
    })
}

/// POST /commit — accept fields, build Merkle tree, register root.
///
/// Sends a `%settle-register` poke (post-Phase-12A settle-graft cause).
/// Returns 409 Conflict if the kernel has already registered a root for
/// this hull_id — settle-graft is single-shot per (hull, root), so
/// subsequent commits would silently desync local state from kernel
/// state (audit §2.C-01). Returns 502 Bad Gateway if the kernel emits
/// an unexpected first-effect tag. See `docs/AUDIT_C01_FOLLOWUP.md` for
/// the deferred rotate-root work.
async fn commit_handler(
    State(state): State<SharedState>,
    Json(req): Json<CommitRequest>,
) -> Result<Json<CommitResponse>, (StatusCode, Json<ErrorBody>)> {
    if req.fields.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "fields array must not be empty".into(),
            }),
        ));
    }

    if req.fields.len() > MAX_FIELDS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("too many fields ({}, max {})", req.fields.len(), MAX_FIELDS),
            }),
        ));
    }

    for (i, field) in req.fields.iter().enumerate() {
        if field.key.len() > MAX_FIELD_BYTES || field.value.len() > MAX_FIELD_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("field {} too large (max {} bytes per key/value)", i, MAX_FIELD_BYTES),
                }),
            ));
        }
        if field.key.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("field {} has empty key", i),
                }),
            ));
        }
    }

    // Build Merkle tree from field data
    let leaf_data: Vec<Vec<u8>> = req.fields.iter().map(field_to_leaf_bytes).collect();
    let leaf_refs: Vec<&[u8]> = leaf_data.iter().map(|v| v.as_slice()).collect();
    // AUDIT 2026-05-21 L-21: MerkleTree::build is fallible (empty leaves).
    let tree = MerkleTree::build(&leaf_refs).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("merkle tree build failed: {e}"),
            }),
        )
    })?;
    let root = tree.root();
    let root_hex = format_tip5(&root);
    let field_count = req.fields.len();

    // Register root with kernel.
    let mut st = state.lock().await;
    let register_poke = vesl_core::build_settle_register_poke(st.hull_id, &root);
    let effects = match poke_kernel_with_timeout(&mut st.app, register_poke, "settle-register").await {
        PokeOutcome::Accepted { effects } => effects,
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelRejected { tag, raw_effects },
        } if tag == "settle-register-rejected" => {
            // L-09: typed duplicate-register. Surface the existing root from
            // the kernel effect so callers can verify what's actually
            // registered without re-reading the slog.
            let body_text = match decode_register_rejected_existing_root(&raw_effects[0]) {
                Some(hex) => format!(
                    "hull already registered with root 0x{hex}; \
                     this hull is single-shot per process"
                ),
                None => "hull already registered (could not decode existing root \
                         from kernel effect)"
                    .into(),
            };
            return Err((StatusCode::CONFLICT, Json(ErrorBody { error: body_text })));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelError { .. },
        } => {
            // Today %settle-register only emits %settle-error when the
            // registered-map hits the capacity cap (M-01 path).
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "kernel rejected %settle-register; likely cause: \
                            registered-map at capacity"
                        .into(),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::Unknown,
        } => {
            // Belt-and-suspenders: %settle-register has emitted typed
            // effects (registered / register-rejected / settle-error) for
            // several revisions. Reaching Unknown means an outdated kernel
            // dropped the typed effect — kept until downstream callers all
            // track the typed-effect revision.
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "kernel returned empty effects for %settle-register; \
                            likely an outdated kernel revision"
                        .into(),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelRejected { tag, .. },
        } => {
            // A `*-rejected` tag other than %settle-register-rejected — kernel
            // protocol drift for this endpoint.
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!(
                        "unexpected kernel rejection tag from %settle-register poke: {tag}"
                    ),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::GateDenied { .. },
        } => {
            // %settle-register has no verify-gate; a `*-denied` here is
            // kernel protocol drift.
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: "unexpected %settle-denied from %settle-register poke".into(),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied { .. },
        } => {
            // classify_effects never constructs RbacDenied; the hull's RBAC
            // pre-check (when wired) doesn't gate %settle-register either.
            unreachable!("RbacDenied not constructed for %settle-register at this site")
        }
        PokeOutcome::Crashed { error } => return Err(crash_to_error(error)),
    };

    match effect_head_tag(&effects[0]).as_deref() {
        Some("settle-registered") => {}
        _ => {
            // classify_effects routes %settle-error / %settle-register-rejected
            // through Rejected; reaching Accepted with a non-success tag is
            // protocol drift.
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: "unexpected kernel effect tag from %settle-register poke".into(),
                }),
            ));
        }
    }

    st.fields = req.fields;
    st.tree = Some(tree);

    Ok(Json(CommitResponse {
        field_count,
        merkle_root: root_hex,
        status: "committed".into(),
    }))
}

/// POST /settle — settle a note against the current Merkle root.
///
/// Sends a `%settle-note` poke whose payload shape is set by the active
/// verify gate. The hull dispatches through
/// [`SettlePayloadBuilder`](crate::SettlePayloadBuilder) so each gate
/// gets its expected payload (R6 §3):
///
/// - `default-hash` — body `{}` re-mints from `field[0]`; `{"data": "<hex>"}`
///   passes the leaf through.
/// - `manifest-verify` — body `{"fields": [{"name": ..., "value": ...}, ...]}`;
///   the hull re-derives proofs from the committed tree.
/// - Other catalog gates — add an impl in `settle_builder.rs` and a
///   match arm in [`payload_builder_for_gate`](crate::payload_builder_for_gate).
///
/// `note_id` and `hull` come from the request envelope (`{"note_id":
/// ..., "hull": ..., ...gate-specific...}`); both are optional and
/// default to the hull's counter + configured `hull_id`.
///
/// Returns 409 Conflict when the kernel rejects (note replay,
/// unregistered hull, gate deny, root mismatch); 400 Bad Request when
/// the body shape doesn't match the active gate; 502 Bad Gateway on
/// unexpected effect tag.
async fn settle_handler(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<SettleResponse>, (StatusCode, Json<ErrorBody>)> {
    let mut st = state.lock().await;

    let hull_id = match body.get("hull") {
        Some(serde_json::Value::Null) | None => st.hull_id,
        Some(v) => v.as_u64().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "`hull` must be a non-negative integer".into(),
                }),
            )
        })?,
    };
    let note_id = match body.get("note_id") {
        Some(serde_json::Value::Null) | None => st.note_counter + 1,
        Some(v) => v.as_u64().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "`note_id` must be a non-negative integer".into(),
                }),
            )
        })?,
    };

    // Build the poke inside a borrow scope so st.tree / st.fields can
    // be released before we take &mut st.app for the kernel poke.
    let (settle_poke, root_hex) = {
        let tree = st.tree.as_ref().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "no tree committed yet -- POST /commit first".into(),
                }),
            )
        })?;
        let root = tree.root();
        let root_hex = format_tip5(&root);
        let ctx = SettleContext {
            note_id,
            hull_id,
            root: &root,
            tree: Some(tree),
            fields: &st.fields,
        };
        let poke = st
            .settle_builder
            .build_settle_poke(&ctx, &body)
            .map_err(|e| match e {
                SettleBuilderError::BadRequest(msg) => (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody { error: msg }),
                ),
                SettleBuilderError::InternalError(msg) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody { error: msg }),
                ),
            })?;
        (poke, root_hex)
    };

    let effects = collapse_to_legacy_result(
        poke_kernel_with_timeout(&mut st.app, settle_poke, "settle-note").await,
    )?;

    // Audit §2.C-01: gate counter advancement and HTTP success on the
    // kernel actually accepting the poke. Empty effects covers every
    // settle-graft rejection path (replay on note_id, unregistered
    // hull, gate deny, root mismatch); the kernel's slog distinguishes
    // them at priority 1.
    if effects.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "kernel returned no effects for %settle-note (see kernel slog)".into(),
            }),
        ));
    }
    match effect_head_tag(&effects[0]).as_deref() {
        Some("settle-noted") => {}
        Some("settle-error") => {
            // Audit §2.C-01 §3.3: route the kernel's typed cord to a
            // matching HTTP status. The seven cords below cover every
            // %settle-error emitted by the %settle-note arm in
            // settle-graft.hoon:170-228.
            let cord = decode_settle_error(&effects[0]).unwrap_or_default();
            let (status, hint) = match cord.as_str() {
                "settle-graft: malformed payload" => (StatusCode::BAD_REQUEST, cord.clone()),
                "settle-graft: root not registered"
                | "settle-graft: root mismatch"
                | "settle-graft: note root does not match expected root"
                | "settle-graft: note already settled"
                | "settle-graft: note already settled (prior epoch)" => {
                    (StatusCode::CONFLICT, cord.clone())
                }
                "settle-graft: verify gate crashed" => (StatusCode::BAD_GATEWAY, cord.clone()),
                _ => (
                    StatusCode::CONFLICT,
                    format!("kernel rejected %settle-note ({cord})"),
                ),
            };
            return Err((status, Json(ErrorBody { error: hint })));
        }
        _ => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: "unexpected kernel effect tag from %settle-note poke".into(),
                }),
            ));
        }
    }

    st.note_counter += 1;
    save_note_counter(&st.output_dir, st.note_counter);

    Ok(Json(SettleResponse {
        note_id,
        merkle_root: root_hex,
        settled: true,
        effects_count: effects.len(),
    }))
}

/// POST /verify — verify a field's commitment against a Merkle root.
async fn verify_handler(
    State(state): State<SharedState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorBody>)> {
    let st = state.lock().await;

    let tree = st.tree.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "no tree committed yet -- POST /commit first".into(),
            }),
        )
    })?;

    let root = tree.root();
    let current_root_hex = format_tip5(&root);

    // If the caller provided a specific root, verify against that
    let target_root_hex = if req.merkle_root.is_empty() {
        current_root_hex.clone()
    } else {
        req.merkle_root.clone()
    };

    // Find the field in committed fields
    let leaf_bytes = field_to_leaf_bytes(&req.field);
    let position = st.fields.iter().position(|f| {
        f.key == req.field.key && f.value == req.field.value
    });

    let valid = match position {
        // AUDIT 2026-05-21 L-21: MerkleTree::proof is fallible; a proof
        // that cannot be generated reads as "not valid".
        Some(idx) => match tree.proof(idx) {
            Ok(proof) => {
                // Verify against current root (the only one we have locally)
                nockchain_tip5_rs::verify_proof(&leaf_bytes, &proof, &root)
                    && target_root_hex == current_root_hex
            }
            Err(_) => false,
        },
        None => false,
    };

    Ok(Json(VerifyResponse {
        valid,
        field_key: req.field.key,
        merkle_root: target_root_hex,
    }))
}

/// GET /tx/:tx_id — fetch a chain-attested receipt for a previously submitted tx.
///
/// Requires a chain-connected settlement mode (fakenet or dumbnet). In local
/// mode, returns 400 with a clear error.
async fn verify_tx_handler(
    State(state): State<SharedState>,
    axum::extract::Path(tx_id): axum::extract::Path<String>,
) -> Result<Json<TxReceipt>, (StatusCode, Json<ErrorBody>)> {
    let chain_config = {
        let st = state.lock().await;
        if st.settlement.mode == SettlementMode::Local {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "verify-tx requires a chain-connected settlement mode \
                            (fakenet or dumbnet)"
                        .into(),
                }),
            ));
        }
        st.settlement.chain_config().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "settlement mode has no chain endpoint configured".into(),
                }),
            )
        })?
    };

    let mut client = ChainClient::connect(chain_config).await.map_err(|e| {
        eprintln!("verify-tx: failed to connect to chain: {e}");
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: "failed to reach chain endpoint".into(),
            }),
        )
    })?;

    match fetch_receipt(&mut client, &tx_id).await {
        Ok(receipt) => Ok(Json(receipt)),
        Err(VerifyTxError::NotFound(_)) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: format!("transaction `{tx_id}` not found on chain"),
            }),
        )),
        Err(VerifyTxError::Chain(e)) => {
            eprintln!("verify-tx: chain RPC error for {tx_id}: {e}");
            Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: "chain RPC error".into(),
                }),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Start the HTTP server with stock routes only.
pub async fn serve(state: SharedState, port: u16, bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_extra_routes(state, port, bind_addr, Router::new()).await
}

/// Start the HTTP server with extra custom routes merged into the hull's
/// stock router. Layers (auth, body limit, rate limit) apply to every
/// route uniformly — see [`router_with_extra`] for the merge ordering.
///
/// Recommended over `Router::merge(router(state), my_routes)`, which
/// silently drops the middleware stack on the merged-in routes (R6 §1).
pub async fn serve_with_extra_routes(
    state: SharedState,
    port: u16,
    bind_addr: &str,
    extra: Router<SharedState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router_with_extra(state, extra);
    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}")).await?;
    if std::env::var("HULL_API_KEY").map_or(true, |k| k.is_empty()) {
        eprintln!("WARNING: HULL_API_KEY not set -- API endpoints are unauthenticated");
    }
    println!("Hull API listening on http://{bind_addr}:{port}");
    println!("  POST /commit    -- commit key-value fields");
    println!("  POST /settle    -- settle a note");
    println!("  POST /verify    -- verify a field commitment");
    println!("  GET  /tx/:tx_id -- fetch chain-attested receipt for a submitted tx");
    println!("  GET  /status    -- current state");
    println!("  GET  /health    -- liveness check");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_plain_equality() {
        assert!(constant_time_eq(b"s3cret-key", b"s3cret-key"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-keX"));
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-ke")); // shorter
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-key-")); // longer
        assert!(!constant_time_eq(b"", b"x"));
    }
}
