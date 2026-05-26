//! GET /health — readiness gate.
//!
//! Returns 200 + `{"status":"ok"}` once [`AppState::kernel_ready`]
//! flips true; 503 + `{"status":"booting","stage":"<stage>"}` before
//! then. K8s readiness probes / load-balancer health checks gate
//! traffic on the 200, so flipping the flag is what lets requests in.

use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::api::types::{AppState, HealthResponse, SharedState};

pub(in crate::api) async fn health(
    State(state): State<SharedState>,
) -> (StatusCode, Json<HealthResponse>) {
    let st = state.lock().await;
    if st.kernel_ready.load(Ordering::Relaxed) {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".into(),
                stage: None,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "booting".into(),
                stage: Some(boot_stage(&st)),
            }),
        )
    }
}

/// Coarse label for the booting stage. Today only one stage is
/// observable ("initializing") because the template's serve flow
/// boots the kernel synchronously before constructing AppState; a
/// future hull that adds async post-boot warmup (cache priming,
/// schema fetch, RPC handshake) can branch here on its own progress
/// flags to surface a more specific label.
fn boot_stage(_st: &AppState) -> String {
    "initializing".to_string()
}
