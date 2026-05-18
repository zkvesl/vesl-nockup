//! Regression tests for audit §2.C-01 — the hull's /commit and
//! /settle handlers must propagate kernel rejection back to the
//! HTTP caller instead of silently overwriting local state with a
//! root the settle kernel has not attested.
//!
//! The settle kernel's `%register` cause is single-shot per
//! `hull_id`. After the first /commit, a second /commit poke
//! produces an empty effect list (handle-register returns ~) and
//! pre-fix the hull returned HTTP 200 with the new (unattested)
//! root anyway. These tests fail against pre-fix code; they exist
//! to keep the fix from regressing.
//!
//! Prereq: compose settle-graft and compile the kernel before
//! running:
//!
//!     nockup graft inject --apply hoon/app/app.hoon
//!     hoonc hoon/app/app.hoon hoon/
//!     cargo test --test desync_regression

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use nockapp::kernel::boot;
use nockapp::NockApp;
use tokio::sync::Mutex;
use tower::ServiceExt;
use vesl_hull::{
    check_auth_config_with_bind, resolve_with_demo_key_checked, router, AppState,
    HullConfig, SettlementCliOverrides,
};

async fn boot_state() -> Arc<Mutex<AppState>> {
    // Disable auth on loopback — the static flag is process-wide,
    // so the first test to call this wins, but every test wants
    // the same behaviour.
    check_auth_config_with_bind(true, "127.0.0.1").expect("loopback no-auth");

    let cli = boot::default_boot_cli(false);
    let kernel = fs::read("out.jam")
        .expect("out.jam missing — run `hoonc hoon/app/app.hoon hoon/` first");
    let app: NockApp = boot::setup(&kernel, cli, &[], "vesl-desync-test", None)
        .await
        .expect("kernel boot");

    let settlement = resolve_with_demo_key_checked(
        &SettlementCliOverrides::default(),
        &HullConfig::default(),
    )
    .expect("default settlement resolves to Local mode");

    Arc::new(Mutex::new(AppState {
        app,
        fields: Vec::new(),
        tree: None,
        hull_id: 1,
        note_counter: 0,
        settlement,
        output_dir: PathBuf::from("."),
    }))
}

async fn json_post(app: axum::Router, uri: &str, body: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
}

async fn get_uri(app: axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn double_commit_returns_409() {
    let state = boot_state().await;

    let body_a = r#"{"fields":[{"key":"k","value":"v1"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body_a).await;
    assert_eq!(status, StatusCode::OK, "first /commit must succeed");

    let body_b = r#"{"fields":[{"key":"k","value":"v2"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body_b).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "second /commit must be rejected by the kernel — empty effect list"
    );

    let st = state.lock().await;
    assert_eq!(st.fields.len(), 1, "local state unchanged after rejection");
    assert_eq!(st.fields[0].value, "v1", "first commit's value retained");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_after_commit_returns_409() {
    let state = boot_state().await;

    let body = r#"{"fields":[{"key":"a","value":"1"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body).await;
    assert_eq!(status, StatusCode::OK, "/commit must succeed first");

    // Post-877988f: /settle pokes %settle-note (not %settle-register).
    // For a 1-field commit, the default single-leaf hash gate's
    // hash(field_to_leaf_bytes) does not match MerkleTree::root() (the
    // tree pads/depth-tags), so the gate cleanly returns %.n and the
    // kernel's ?> panics outside the mule wrap — settle-graft emits no
    // typed cord. The hull surfaces the empty-effect list as 409. The
    // counter must NOT advance on this rejection path.
    let (status, _) = json_post(router(state.clone()), "/settle", "{}").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "/settle's %settle-note is gate-denied for 1-field commits, surfaces as 409"
    );

    let st = state.lock().await;
    assert_eq!(st.note_counter, 0, "counter must not advance on rejected settle");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_success_path_still_updates_state() {
    let state = boot_state().await;

    let body = r#"{"fields":[{"key":"x","value":"y"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body).await;
    assert_eq!(status, StatusCode::OK);

    let (status, bytes) = get_uri(router(state.clone()), "/status").await;
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("status returns JSON");
    assert_eq!(body["has_tree"], serde_json::Value::Bool(true));
    assert_eq!(body["field_count"], serde_json::Value::from(1u64));
    assert!(body["merkle_root"].as_str().is_some());
}

// Audit C-01 follow-up §4 regressions for the §3.2 + §3.3 work
// (.dev/AUDIT_C01_REAL_SETTLE.md). The audit doc's third proposed
// case — settle_with_explicit_data_succeeds_against_commit — is
// dropped here: it depends on the default single-leaf hash gate
// accepting `hash(data) == tree.root()` for our 1-field commit,
// which the existing settle_after_commit_returns_409 test
// demonstrates does NOT hold. Without gate-success the replay
// scenario (a second settled note_id) is unreachable through the
// default gate. Re-add when a hash-or-gate combination admits the
// success path.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_unregistered_hull_returns_409_with_cord() {
    // Exercises the new `hull` field on SettleRequest AND the new
    // cord routing: hull=99 was never registered, so settle-graft
    // emits [%settle-error 'settle-graft: root not registered']
    // and the hull surfaces the cord verbatim in the 409 body.
    let state = boot_state().await;

    let body = r#"{"fields":[{"key":"a","value":"1"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body).await;
    assert_eq!(status, StatusCode::OK, "/commit must succeed first");

    let (status, bytes) =
        json_post(router(state.clone()), "/settle", r#"{"hull": 99}"#).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "unregistered hull → kernel emits 'root not registered' cord → 409"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("error body is JSON");
    let err = body["error"].as_str().expect("error field is a string");
    assert!(
        err.contains("settle-graft: root not registered"),
        "409 body must contain the kernel cord verbatim; got: {err}"
    );

    let st = state.lock().await;
    assert_eq!(
        st.note_counter, 0,
        "counter must not advance on rejected settle"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_invalid_data_hex_returns_400() {
    // Exercises the new `data` field's hex-decoding validation in
    // the hull. "zzz" is not valid hex, so the handler returns 400
    // before pokeing the kernel — the kernel never sees this
    // request and the counter must not advance.
    let state = boot_state().await;

    let body = r#"{"fields":[{"key":"a","value":"1"}]}"#;
    let (status, _) = json_post(router(state.clone()), "/commit", body).await;
    assert_eq!(status, StatusCode::OK, "/commit must succeed first");

    let (status, bytes) =
        json_post(router(state.clone()), "/settle", r#"{"data": "zzz"}"#).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid hex in `data` rejected by hull, never reaches kernel"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("error body is JSON");
    let err = body["error"].as_str().expect("error field is a string");
    assert!(
        err.contains("invalid hex"),
        "400 body must explain the hex parse failure; got: {err}"
    );

    let st = state.lock().await;
    assert_eq!(
        st.note_counter, 0,
        "counter must not advance on hull-side rejection"
    );
}
