//! HTTP API — axum server for the generic hull.
//!
//! Three domain endpoints: /commit, /settle, /verify.
//! Plus /health and /status for ops.
//!
//! Community developers: modify /commit to accept your domain data,
//! adjust the Merkle leaf encoding, and add domain-specific endpoints.
//!
//! Module layout:
//! - [`types`] — public Field / AppState / *Request / *Response shapes,
//!   plus on-disk note-counter persistence.
//! - [`auth`] — API-key middleware, body-size precheck, `HULL_BODY_LIMIT`,
//!   start-up auth config sanity check.
//! - [`rbac`] — `[%rbac-has-perm pubkey perm ~]` peek + header extraction
//!   + outcome → HTTP mapping.
//! - [`poke`] — timed `NockApp::poke` wrapper that classifies into
//!   [`vesl_core::PokeOutcome`].
//! - [`error`] — `PokeCrashError` → HTTP tuple mapping + the typed
//!   decoder for `%settle-register-rejected` existing-root payloads.
//! - [`handlers`] — one file per stock route; each handler is
//!   self-contained.
//!
//! Adding a new HTTP route: drop a new file under `handlers/`, expose
//! the handler with `pub(in crate::api)`, and wire it into [`stock_routes`].

use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;

mod auth;
mod error;
mod handlers;
mod poke;
mod rbac;
mod types;

pub use auth::{check_auth_config, check_auth_config_with_bind};
pub(crate) use auth::HULL_BODY_LIMIT;
pub use types::{
    AppState, CommitRequest, CommitResponse, Field, HealthResponse, SettleResponse, SharedState,
    StatusResponse, VerifyRequest, VerifyResponse, load_note_counter,
};

use auth::{check_api_key, enforce_body_size_upfront};
use handlers::commit::commit_handler;
use handlers::health::health;
use handlers::settle::settle_handler;
use handlers::status::status;
use handlers::verify::{verify_handler, verify_tx_handler};

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
/// (auth, body size enforcement, 200/60s rate limit + 256-deep buffer).
///
/// Body-size enforcement is two-stage: an upfront `Body::size_hint`
/// precheck (catches in-process bodies + wire bodies whose parser
/// populated the size_hint from `Content-Length`) plus tower-http's
/// streaming [`RequestBodyLimitLayer`]. A handler that never reads its
/// body still receives a 413 from the upfront stage when the size is
/// known; chunked or unknown-length bodies fall through to the
/// streaming layer, which fires when the handler polls past the cap.
///
/// All layers wrap the **merged** Router, so they apply to every route
/// regardless of which half it came from. This is the canonical
/// composition entry point post-R6 §1.
pub fn router_with_extra(state: SharedState, extra: Router<SharedState>) -> Router {
    router_with_extra_inner(state, extra, 200, std::time::Duration::from_secs(60))
}

/// Inner builder. Exposed `pub` so integration tests can drive the
/// rate-limit layer with a shorter window without re-implementing the
/// layer stack.
pub fn router_with_extra_inner(
    state: SharedState,
    extra: Router<SharedState>,
    rate_per_window: u64,
    rate_window: std::time::Duration,
) -> Router {
    stock_routes()
        .merge(extra)
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(|_: tower::BoxError| async {
                    StatusCode::TOO_MANY_REQUESTS
                }))
                .buffer(256)
                .rate_limit(rate_per_window, rate_window),
        )
        .layer(RequestBodyLimitLayer::new(HULL_BODY_LIMIT)) // H-001: streaming cap
        .layer(middleware::from_fn(enforce_body_size_upfront)) // H-001: upfront cap
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
// Server entry point
// ---------------------------------------------------------------------------

/// Start the HTTP server with stock routes only.
pub async fn serve(state: SharedState, port: u16, bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_extra_routes(state, port, bind_addr, Router::new()).await
}

/// Start the HTTP server with extra custom routes merged into the hull's
/// stock router. Auth, the two-stage body-size cap (upfront `size_hint`
/// precheck + streaming `RequestBodyLimitLayer`), and the 200/60s rate
/// limit apply to every route uniformly — see [`router_with_extra`] for
/// the merge ordering and the body-size semantics.
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
        tracing::warn!(
            target: "vesl_hull::serve",
            "HULL_API_KEY not set -- API endpoints are unauthenticated"
        );
    }
    // Ready signal: the listener is bound and `axum::serve` is about to take
    // over the socket. Orchestration scripts (kubernetes readinessProbe,
    // systemd, `wait-for-it`) can grep this line instead of port-polling.
    tracing::info!(
        target: "vesl_hull::serve",
        "hull listening on http://{bind_addr}:{port}"
    );
    tracing::info!(target: "vesl_hull::serve", "  POST /commit    -- commit key-value fields");
    tracing::info!(target: "vesl_hull::serve", "  POST /settle    -- settle a note");
    tracing::info!(target: "vesl_hull::serve", "  POST /verify    -- verify a field commitment");
    tracing::info!(target: "vesl_hull::serve", "  GET  /tx/:tx_id -- fetch chain-attested receipt for a submitted tx");
    tracing::info!(target: "vesl_hull::serve", "  GET  /status    -- current state");
    tracing::info!(target: "vesl_hull::serve", "  GET  /health    -- liveness check");
    axum::serve(listener, app).await?;
    Ok(())
}
