//! API-key auth middleware + body-size precheck + start-up auth config
//! sanity check. The body-size cap lives here because the upfront
//! precheck and the streaming `RequestBodyLimitLayer` share the same
//! constant ([`HULL_BODY_LIMIT`]).

use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::HttpBody;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;

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
pub(super) async fn check_api_key(
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

/// Hull-wide request-body size cap (4 MiB). Shared by the streaming
/// `RequestBodyLimitLayer` and the upfront size_hint precheck below.
pub(crate) const HULL_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Reject requests whose body advertises a known size larger than
/// [`HULL_BODY_LIMIT`] before invoking the handler.
///
/// Tower-http's `RequestBodyLimitLayer` only checks the `Content-Length`
/// header. Bodies built in-process (`Body::from(Vec<u8>)`, `Body::from_stream`
/// with a sized stream) propagate their length via `Body::size_hint`
/// without setting the header; without this precheck, a handler that
/// ignores the body lets such a request through despite exceeding the
/// limit. Wire requests are unaffected — axum's H1/H2 parsers populate
/// `size_hint` from the parsed `Content-Length`, so an honest client
/// trips this check upfront either way.
pub(super) async fn enforce_body_size_upfront(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(upper) = req.body().size_hint().upper() {
        if upper > HULL_BODY_LIMIT as u64 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    Ok(next.run(req).await)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn constant_time_eq_matches_plain_equality() {
        assert!(constant_time_eq(b"s3cret-key", b"s3cret-key"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-keX"));
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-ke")); // shorter
        assert!(!constant_time_eq(b"s3cret-key", b"s3cret-key-")); // longer
        assert!(!constant_time_eq(b"", b"x"));
    }

    // ---- Body-size precheck (H-001 upfront stage) ----
    //
    // Pinned regression for the gap surfaced in the 2026-05-24 sandbox-build
    // DX review: tower-http's `RequestBodyLimitLayer` only inspects the
    // `Content-Length` header. A request whose body advertises its size via
    // `Body::size_hint` (e.g. `Body::from(Vec<u8>)`, or a wire body parsed
    // from an honest `Content-Length`) but does not set the header is let
    // through tower-http when the handler ignores the body. The precheck
    // middleware closes that gap by inspecting `size_hint` directly.

    async fn echo_ignore_body() -> &'static str {
        "ok"
    }

    fn precheck_only_router() -> Router {
        Router::new()
            .route("/x", post(echo_ignore_body))
            .layer(middleware::from_fn(enforce_body_size_upfront))
    }

    #[tokio::test]
    async fn precheck_rejects_oversize_body_without_content_length_header() {
        let app = precheck_only_router();
        let big_body = vec![b'x'; HULL_BODY_LIMIT + 1];
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/x")
                    .body(Body::from(big_body))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn precheck_passes_undersize_body() {
        let app = precheck_only_router();
        let small_body = vec![b'x'; 1024];
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/x")
                    .body(Body::from(small_body))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Unknown-length bodies (size_hint().upper() == None) fall through to
    // tower-http's streaming layer in the real router. The precheck on its
    // own must not synthesise a 413; it short-circuits only when the body
    // advertises a known upper size that exceeds the cap. Covered by code
    // review: the `if let Some(upper)` guard in `enforce_body_size_upfront`
    // is unreachable when `upper()` is None, so the request passes through.
}
