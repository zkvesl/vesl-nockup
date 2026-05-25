//! POST /settle — settle a note against the current Merkle root via
//! `%settle-note`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use vesl_core::{effect_head_tag, format_tip5, PokeOutcome, RejectionReason};

use crate::api::error::crash_to_error;
use crate::api::poke::poke_kernel_with_timeout;
use crate::api::rbac::{check_rbac_perm, extract_pubkey_header, handle_rbac_outcome, SETTLE_PERM};
use crate::api::types::{save_note_counter, ErrorBody, SettleResponse, SharedState};
use crate::settle_builder::{SettleBuilderError, SettleContext};

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
pub(in crate::api) async fn settle_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<SettleResponse>, (StatusCode, Json<ErrorBody>)> {
    let mut st = state.lock().await;

    // RBAC pre-check: if enabled, peek `[%rbac-has-perm pubkey settle ~]`
    // against the composed rbac-graft and short-circuit to 403 on denial.
    if st.rbac.enabled {
        let pubkey = extract_pubkey_header(&headers)?;
        let outcome = check_rbac_perm(&mut st.app, &pubkey, SETTLE_PERM).await?;
        handle_rbac_outcome(outcome)?;
    }

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

    // Audit §2.C-01: gate counter advancement and HTTP success on the
    // kernel actually accepting the poke. The classifier splits the
    // settle-graft rejection paths between typed variants:
    //   - %settle-error cords (replay, root mismatch, unregistered hull,
    //     malformed payload, gate crash, capacity) land in KernelError
    //   - typed gate-clean-deny (%settle-denied) lands in GateDenied
    //     once settle-graft emits it
    //   - empty effects (pre-typed-denial gate clean-deny) land in
    //     Unknown
    let effects = match poke_kernel_with_timeout(&mut st.app, settle_poke, "settle-note").await {
        PokeOutcome::Accepted { effects } => effects,
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelError { cord, .. },
        } => {
            // Audit §2.C-01 §3.3: route the kernel's typed cord to a
            // matching HTTP status. The seven cords below cover every
            // %settle-error emitted by the %settle-note arm in
            // settle-graft.hoon:170-228.
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
        PokeOutcome::Rejected {
            reason: RejectionReason::GateDenied { reason, .. },
        } => {
            // Typed gate-clean-deny — surface the reason cord in the body.
            // Parity with today's empty-effects 409 until callers update.
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: format!("kernel denied %settle-note: {reason}"),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::Unknown,
        } => {
            // Pre-typed-denial gate clean-deny — slog has the mule trace.
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "kernel returned no effects for %settle-note (see kernel slog)".into(),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::KernelRejected { tag, .. },
        } => {
            // %settle-note emits no `*-rejected` effects today; reaching
            // here is kernel protocol drift.
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!(
                        "unexpected kernel rejection tag from %settle-note poke: {tag}"
                    ),
                }),
            ));
        }
        PokeOutcome::Rejected {
            reason: RejectionReason::RbacDenied { .. },
        } => {
            // classify_effects never constructs RbacDenied; the hull's
            // RBAC pre-check, when wired, produces the variant before
            // poke_kernel_with_timeout is reached.
            unreachable!("RbacDenied not constructed at this site")
        }
        PokeOutcome::Crashed { error } => return Err(crash_to_error(error)),
    };

    match effect_head_tag(&effects[0]).as_deref() {
        Some("settle-noted") => {}
        _ => {
            // classify_effects routes %settle-error / %settle-denied
            // through Rejected; reaching Accepted with a non-success tag
            // is protocol drift.
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
