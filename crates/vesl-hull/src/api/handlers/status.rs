//! GET /status — operational snapshot of kernel state, settlement
//! configuration, and the composed graft manifest set.

use axum::extract::State;
use axum::Json;

use vesl_core::format_tip5;

use crate::api::types::{SharedState, StatusResponse};

pub(in crate::api) async fn status(State(state): State<SharedState>) -> Json<StatusResponse> {
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
