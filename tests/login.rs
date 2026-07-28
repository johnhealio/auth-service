mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::AppState;
use auth_service::refresh_token::REFRESH_TOKEN_TTL_DAYS;
use auth_service::user::{NewUser, User};

async fn post_json(app: Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
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

async fn get_with_auth(app: Router, uri: &str, auth_header: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(header) = auth_header {
        builder = builder.header("authorization", header);
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

async fn create_test_user(state: &AppState, email: &str, password: &str) -> User {
    let password_hash = auth_service::password::hash_password(password).unwrap();
    state
        .store
        .create_user(NewUser {
            user_id: auth_service::random::generate_opaque_token(16),
            email: email.to_string(),
            password_hash,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn login_succeeds_and_returns_valid_tokens() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-success");
    let password = "a genuinely long passphrase 3";
    let user = create_test_user(&state, &email, password).await;

    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password }),
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

    let refresh_token = body["refresh_token"].as_str().unwrap();
    let token_hash = auth_service::random::hash_token(refresh_token);
    let record = state
        .refresh_store
        .find_by_hash(&token_hash)
        .await
        .unwrap()
        .expect("refresh token record should exist");

    assert_eq!(record.user_email, email);
    assert_eq!(
        (record.expires_at - record.created_at).num_days(),
        REFRESH_TOKEN_TTL_DAYS
    );
}

#[tokio::test]
async fn wrong_password_and_unknown_email_return_identical_generic_error() {
    let state = common::test_app_state().await;
    let email = common::unique_email("login-wrong-password");
    let password = "a genuinely long passphrase 4";
    create_test_user(&state, &email, password).await;

    let (wrong_status, wrong_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": "not the right password" }),
    )
    .await;

    let unknown_email = common::unique_email("login-unknown-email");
    let (unknown_status, unknown_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": unknown_email, "password": "whatever password" }),
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
    create_test_user(&state, &email, password).await;

    let (_, body_a) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password }),
    )
    .await;
    let (_, body_b) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password }),
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
    let user = create_test_user(&state, &email, password).await;

    let (_, login_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password }),
    )
    .await;
    let access_token = login_body["access_token"].as_str().unwrap();

    let (status, body) = get_with_auth(
        auth_service::app(state.clone()),
        "/me",
        Some(&format!("Bearer {access_token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], user.user_id);

    let (no_header_status, _) = get_with_auth(auth_service::app(state.clone()), "/me", None).await;
    assert_eq!(no_header_status, StatusCode::UNAUTHORIZED);

    let (garbage_status, _) = get_with_auth(
        auth_service::app(state.clone()),
        "/me",
        Some("Bearer garbage.token.value"),
    )
    .await;
    assert_eq!(garbage_status, StatusCode::UNAUTHORIZED);
}
