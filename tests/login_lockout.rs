mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{create_test_user, create_test_user_with_mfa};

// Cloud-Run-shaped X-Forwarded-For, well within login_config()'s burst
// (20) for the request counts these tests use — keeps the IP-based rate
// limiter from preempting the account-lockout responses under test here.
const XFF: &str = "203.0.113.50,35.190.0.1";

async fn login_attempt(app: Router, email: &str, password: &str) -> (StatusCode, Value) {
    // "mfa_code" is a filler value — every call in this file uses a wrong
    // password (or is already locked out), so MFA is never reached; the
    // field just needs to be present so the request passes JSON body
    // deserialization (a missing required field is 422, not the
    // 401/429 these tests assert).
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", XFF)
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({ "email": email, "password": password, "mfa_code": "000000" }),
                    )
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
async fn login_locks_out_after_threshold_failures() {
    let state = common::test_app_state().await;
    let email = common::unique_email("lockout-threshold");
    let password = "a genuinely long passphrase 7";
    create_test_user(&state, &email, password).await;

    // LOGIN_FAILURE_THRESHOLD (src/store/firestore.rs) is 10 — this many
    // wrong-password attempts should each still be the generic rejection.
    for _ in 0..10 {
        let (status, body) =
            login_attempt(auth_service::app(state.clone()), &email, "wrong password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_credentials");
    }

    // The next attempt crosses the threshold — locked out now, distinct
    // response from the generic rejection above.
    let response = auth_service::app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", XFF)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "email": email,
                        "password": "wrong password",
                        "mfa_code": "000000"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "account_locked");

    // Even the *correct* password is rejected while locked out — the
    // lockout check runs before credential verification.
    let (status, body) = login_attempt(auth_service::app(state.clone()), &email, password).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "account_locked");
}

#[tokio::test]
async fn successful_login_resets_attempt_counter() {
    let state = common::test_app_state().await;
    let email = common::unique_email("lockout-reset");
    let password = "a genuinely long passphrase 8";
    let (_, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    // A handful of failures, well under the threshold.
    for _ in 0..5 {
        let (status, _) =
            login_attempt(auth_service::app(state.clone()), &email, "wrong password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // A correct login must reset the counter, not just succeed.
    let keypair = common::dpop::DpopKeypair::generate();
    let login_url = format!("{}/login", common::TEST_PUBLIC_BASE_URL);
    let proof = common::dpop::DpopProofBuilder::new("POST", &login_url).sign(&keypair);
    let response = auth_service::app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .header("x-forwarded-for", XFF)
                .header("DPoP", proof)
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "email": email,
                        "password": password,
                        "mfa_code": enrollment.generate_current()
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 9 more wrong attempts: 5 (pre-reset) + 9 would be 14 — past the
    // threshold of 10 if the counter hadn't reset. Since it did, this
    // stays under threshold and every one of these must still be the
    // generic rejection, not a lockout.
    for _ in 0..9 {
        let (status, body) =
            login_attempt(auth_service::app(state.clone()), &email, "wrong password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_credentials");
    }
}
