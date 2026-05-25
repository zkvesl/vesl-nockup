//! GET /health — liveness check.

use axum::Json;

use crate::api::types::HealthResponse;

pub(in crate::api) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
}
