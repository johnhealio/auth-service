mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::password;
use common::TEST_PUBLIC_BASE_URL;
use common::dpop::{DpopKeypair, DpopProofBuilder};

fn login_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/login")
}

async fn post_json(
    app: axum::Router,
    uri: &str,
    body: Value,
    dpop_proof: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(proof) = dpop_proof {
        builder = builder.header("DPoP", proof);
    }

    let response = app
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_register(app: axum::Router, body: Value) -> (StatusCode, Value) {
    post_json(app, "/register", body, None).await
}

async fn post_confirm(app: axum::Router, body: Value) -> (StatusCode, Value) {
    post_json(app, "/register/confirm", body, None).await
}

#[tokio::test]
async fn register_succeeds_and_password_is_hashed_not_plaintext() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-success");
    let password_plain = "a genuinely long passphrase 1";

    let (status, body) = post_register(
        auth_service::app(state.clone()),
        json!({ "email": email, "password": password_plain }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["email"], email);
    assert!(body.get("password_hash").is_none());
    assert!(body.get("password").is_none());
    assert!(
        body["mfa_enrollment_url"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert!(!body["mfa_secret_base32"].as_str().unwrap().is_empty());

    let stored = state
        .store
        .find_by_email(&email)
        .await
        .expect("store lookup should succeed")
        .expect("user should exist after registration");

    assert_ne!(stored.password_hash, password_plain);
    assert!(stored.password_hash.starts_with("$argon2id$"));
    assert!(password::verify_password(password_plain, &stored.password_hash).unwrap());
    // Not usable for login until /register/confirm succeeds (Module 11).
    assert!(!stored.mfa_enrolled);
}

#[tokio::test]
async fn full_registration_ceremony_issues_recovery_codes_and_allows_recovery_code_login() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-ceremony");
    let password_plain = "a genuinely long ceremony passphrase";

    let (reg_status, reg_body) = post_register(
        auth_service::app(state.clone()),
        json!({ "email": email, "password": password_plain }),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);
    let base32_secret = reg_body["mfa_secret_base32"].as_str().unwrap();
    let code = auth_service::totp::generate_current_for_base32(base32_secret, &email);

    let (confirm_status, confirm_body) = post_confirm(
        auth_service::app(state.clone()),
        json!({ "email": email, "mfa_code": code }),
    )
    .await;
    assert_eq!(confirm_status, StatusCode::OK);
    let recovery_codes = confirm_body["recovery_codes"].as_array().unwrap();
    assert_eq!(recovery_codes.len(), 10);

    let recovery_code = recovery_codes[0].as_str().unwrap();

    // Login using a recovery code instead of a TOTP code.
    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (login_status, login_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password_plain, "mfa_code": recovery_code }),
        Some(&login_proof),
    )
    .await;
    assert_eq!(login_status, StatusCode::OK);
    assert!(login_body.get("access_token").is_some());

    // The same recovery code cannot be reused.
    let login_proof_2 = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (second_status, second_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password_plain, "mfa_code": recovery_code }),
        Some(&login_proof_2),
    )
    .await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
    assert_eq!(second_body["error"], "mfa_code_invalid");
}

#[tokio::test]
async fn login_before_confirming_mfa_is_rejected() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-not-confirmed");
    let password_plain = "a genuinely long unconfirmed passphrase";

    let (reg_status, _) = post_register(
        auth_service::app(state.clone()),
        json!({ "email": email, "password": password_plain }),
    )
    .await;
    assert_eq!(reg_status, StatusCode::CREATED);

    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password_plain, "mfa_code": "000000" }),
        Some(&login_proof),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "mfa_not_enrolled");
}

#[tokio::test]
async fn login_with_wrong_mfa_code_after_confirming_is_rejected() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-wrong-code");
    let password_plain = "a genuinely long wrong code passphrase";

    let (_, reg_body) = post_register(
        auth_service::app(state.clone()),
        json!({ "email": email, "password": password_plain }),
    )
    .await;
    let base32_secret = reg_body["mfa_secret_base32"].as_str().unwrap();
    let code = auth_service::totp::generate_current_for_base32(base32_secret, &email);
    let (confirm_status, _) = post_confirm(
        auth_service::app(state.clone()),
        json!({ "email": email, "mfa_code": code }),
    )
    .await;
    assert_eq!(confirm_status, StatusCode::OK);

    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password_plain, "mfa_code": "000000" }),
        Some(&login_proof),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "mfa_code_invalid");
}

#[tokio::test]
async fn duplicate_email_returns_409() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-duplicate");
    let payload = json!({ "email": email, "password": "a genuinely long passphrase 2" });

    let (first_status, _) = post_register(auth_service::app(state.clone()), payload.clone()).await;
    assert_eq!(first_status, StatusCode::CREATED);

    let (second_status, second_body) =
        post_register(auth_service::app(state.clone()), payload).await;

    assert_eq!(second_status, StatusCode::CONFLICT);
    assert_eq!(second_body["error"], "email_already_registered");
}

#[tokio::test]
async fn password_below_minimum_length_returns_400() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-short-password");

    let (status, body) = post_register(
        auth_service::app(state),
        json!({ "email": email, "password": "short1" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn known_breached_password_returns_400() {
    let state = common::test_app_state().await;
    let email = common::unique_email("register-breached-password");

    // Long enough to pass the length check, but a widely-known leaked
    // password — must appear in the Pwned Passwords corpus.
    let (status, body) = post_register(
        auth_service::app(state),
        json!({ "email": email, "password": "password12345678" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}
