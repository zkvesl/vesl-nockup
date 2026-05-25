//! POST /commit — accept fields, build a Merkle tree, register the root
//! with the kernel via `%settle-register`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use vesl_core::{effect_head_tag, format_tip5, MerkleTree, PokeOutcome, RejectionReason};

use crate::api::error::{crash_to_error, decode_register_rejected_existing_root};
use crate::api::poke::poke_kernel_with_timeout;
use crate::api::rbac::{check_rbac_perm, extract_pubkey_header, handle_rbac_outcome, COMMIT_PERM};
use crate::api::types::{CommitRequest, CommitResponse, ErrorBody, SharedState};
use crate::verify::field_to_leaf_bytes;

/// Maximum fields per /commit request.
const MAX_FIELDS: usize = 500;
/// Maximum size of a single field key or value in bytes.
const MAX_FIELD_BYTES: usize = 100_000;

/// POST /commit — accept fields, build Merkle tree, register root.
///
/// Sends a `%settle-register` poke (post-Phase-12A settle-graft cause).
/// Returns 409 Conflict if the kernel has already registered a root for
/// this hull_id — settle-graft is single-shot per (hull, root), so
/// subsequent commits would silently desync local state from kernel
/// state (audit §2.C-01). Returns 502 Bad Gateway if the kernel emits
/// an unexpected first-effect tag. See `docs/AUDIT_C01_FOLLOWUP.md` for
/// the deferred rotate-root work.
pub(in crate::api) async fn commit_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
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

    // RBAC pre-check: if enabled, peek `[%rbac-has-perm pubkey commit ~]`
    // against the composed rbac-graft and short-circuit to 403 on denial
    // — the kernel never sees the poke, so its slog stays clean.
    if st.rbac.enabled {
        let pubkey = extract_pubkey_header(&headers)?;
        let outcome = check_rbac_perm(&mut st.app, &pubkey, COMMIT_PERM).await?;
        handle_rbac_outcome(outcome)?;
    }

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
