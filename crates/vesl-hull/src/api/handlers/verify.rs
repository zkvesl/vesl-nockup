//! POST /verify and GET /tx/:tx_id — field-commitment verification
//! against the local Merkle root, plus chain-attested receipt fetch.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use vesl_core::{fetch_receipt, format_tip5, ChainClient, SettlementMode, TxReceipt, VerifyTxError};

use crate::api::types::{ErrorBody, SharedState, VerifyRequest, VerifyResponse};
use crate::verify::field_to_leaf_bytes;

/// POST /verify — verify a field's commitment against a Merkle root.
pub(in crate::api) async fn verify_handler(
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
pub(in crate::api) async fn verify_tx_handler(
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
        tracing::error!(target: "vesl_hull::verify_tx", "failed to connect to chain: {e}");
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
            tracing::error!(target: "vesl_hull::verify_tx", "chain RPC error for {tx_id}: {e}");
            Err((
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: "chain RPC error".into(),
                }),
            ))
        }
    }
}
