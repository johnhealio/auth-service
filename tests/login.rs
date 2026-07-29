mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::refresh_token::REFRESH_TOKEN_TTL_DAYS;
use common::TEST_PUBLIC_BASE_URL;
use common::dpop::{DpopKeypair, DpopProofBuilder};
use common::{create_test_user, create_test_user_with_mfa};

async fn post_json(
    app: Router,
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

async fn get_with_auth(
    app: Router,
    uri: &str,
    auth_header: Option<&str>,
    dpop_proof: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(header) = auth_header {
        builder = builder.header("authorization", header);
    }
    if let Some(proof) = dpop_proof {
        builder = builder.header("DPoP", proof);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

fn login_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/login")
}

fn me_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/me")
}

#[tokio::test]
async fn login_succeeds_and_returns_valid_tokens() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-success");
    let password = "a genuinely long passphrase 3";
    let (user, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    let keypair = DpopKeypair::generate();
    let proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);

    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        Some(&proof),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 600);

    let access_token = body["access_token"].as_str().unwrap();
    let claims = state.jwt.verify_access_token(access_token).unwrap();
    assert_eq!(claims.sub, user.user_id);
    assert_eq!(claims.exp - claims.iat, 600);
    assert!(!claims.jti.is_empty());
    assert_eq!(claims.cnf.jkt, keypair.thumbprint());

    let refresh_token = body["refresh_token"].as_str().unwrap();
    let token_hash = auth_service::random::hash_token(refresh_token);
    let record = state
        .refresh_store
        .find_by_hash(&token_hash)
        .await
        .unwrap()
        .expect("refresh token record should exist");

    assert_eq!(record.user_email, email);
    assert_eq!(record.jkt, keypair.thumbprint());
    assert_eq!(
        (record.expires_at - record.created_at).num_days(),
        REFRESH_TOKEN_TTL_DAYS
    );
}

#[tokio::test]
async fn login_without_dpop_header_rejected() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-no-dpop");
    let password = "a genuinely long passphrase 3a";
    let (_, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn wrong_password_and_unknown_email_return_identical_generic_error() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-wrong-password");
    let password = "a genuinely long passphrase 4";
    create_test_user(&state, &email, password).await;

    // No DPoP header needed here: credential verification fails before
    // DPoP (or MFA) is ever considered, so both these paths short-circuit
    // first. "mfa_code" is a filler value here — it's only required so
    // the request passes JSON body deserialization at all (a missing
    // required field is a 422, not the 401 this test is about); its
    // actual value never gets checked since the password fails first.
    let (wrong_status, wrong_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": "not the right password", "mfa_code": "000000" }),
        None,
    )
    .await;

    let unknown_email = common::unique_email("login-unknown-email");
    let (unknown_status, unknown_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": unknown_email, "password": "whatever password", "mfa_code": "000000" }),
        None,
    )
    .await;

    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_status, unknown_status);
    // Field-for-field identical, not just "also generic" — that equality
    // is the property that matters for enumeration resistance.
    assert_eq!(wrong_body, unknown_body);
    assert_eq!(wrong_body["error"], "invalid_credentials");
}

#[tokio::test]
async fn logins_for_same_user_have_unique_jti() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-jti-unique");
    let password = "a genuinely long passphrase 5";
    let (_, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    let keypair = DpopKeypair::generate();

    let proof_a = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (_, body_a) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        Some(&proof_a),
    )
    .await;

    let proof_b = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (_, body_b) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        Some(&proof_b),
    )
    .await;

    let claims_a = state
        .jwt
        .verify_access_token(body_a["access_token"].as_str().unwrap())
        .unwrap();
    let claims_b = state
        .jwt
        .verify_access_token(body_b["access_token"].as_str().unwrap())
        .unwrap();

    assert_ne!(claims_a.jti, claims_b.jti);
}

#[tokio::test]
async fn access_token_authenticates_protected_route() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-me-route");
    let password = "a genuinely long passphrase 6";
    let (user, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);

    let (_, login_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        Some(&login_proof),
    )
    .await;
    let access_token = login_body["access_token"].as_str().unwrap();

    let me_proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(access_token)
        .sign(&keypair);

    let (status, body) = get_with_auth(
        auth_service::app(state.clone()),
        "/me",
        Some(&format!("Bearer {access_token}")),
        Some(&me_proof),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], user.user_id);

    let (no_header_status, _) =
        get_with_auth(auth_service::app(state.clone()), "/me", None, None).await;
    assert_eq!(no_header_status, StatusCode::UNAUTHORIZED);

    let another_proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(access_token)
        .sign(&keypair);
    let (garbage_status, _) = get_with_auth(
        auth_service::app(state.clone()),
        "/me",
        Some("Bearer garbage.token.value"),
        Some(&another_proof),
    )
    .await;
    assert_eq!(garbage_status, StatusCode::UNAUTHORIZED);
}
