mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

// Cloud-Run-shaped X-Forwarded-For (<client-ip>,<lb-ip>) — matches what
// CloudRunKeyExtractor expects (src/rate_limit.rs): the real client IP
// is the second-to-last entry. Unlike every other test in this crate,
// these tests build `app()` once per test and reuse (clone) that same
// Router across calls, specifically so the in-memory rate-limit bucket
// persists across the loop — see src/lib.rs's `app()` doc comment for
// why that's otherwise per-call-isolated.
const XFF: &str = "192.0.2.10,35.190.0.1";

async fn get(app: Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("x-forwarded-for", XFF)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn post_login(app: Router, email: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", XFF)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "email": email,
                        "password": "whatever password",
                        "mfa_code": "000000"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test]
async fn login_rate_limit_trips_after_burst() {
    let state = common::test_app_state().await;
    let app = auth_service::app(state);
    let email = common::unique_email("rate-limit");

    // login_config()'s burst is 20 (src/rate_limit.rs) — comfortably
    // exceeded by 30 rapid same-IP requests. Some of the responses along
    // the way will be `account_locked` (the separate per-account lockout
    // also triggers at 10 failures) rather than `invalid_credentials` —
    // that's expected and not what this test checks; it only asserts
    // that the run eventually hits the rate limiter specifically.
    let mut last_status = StatusCode::OK;
    let mut last_body = Value::Null;
    for _ in 0..30 {
        let (status, body) = post_login(app.clone(), &email).await;
        last_status = status;
        last_body = body;
        if status == StatusCode::TOO_MANY_REQUESTS && last_body["error"] == "rate_limited" {
            break;
        }
    }

    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(last_body["error"], "rate_limited");
}

#[tokio::test]
async fn healthz_is_not_rate_limited() {
    let state = common::test_app_state().await;
    let app = auth_service::app(state);

    // Comfortably past every rate-limited route's burst size, on the
    // same synthetic IP — /healthz has no GovernorLayer at all
    // (src/lib.rs), so none of these should ever 429.
    for _ in 0..30 {
        let (status, _) = get(app.clone(), "/healthz").await;
        assert_eq!(status, StatusCode::OK);
    }
}
