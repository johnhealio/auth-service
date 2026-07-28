mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::AppState;
use auth_service::refresh_token::RefreshTokenStatus;
use common::TEST_PUBLIC_BASE_URL;
use common::create_test_user;
use common::dpop::{DpopKeypair, DpopProofBuilder};

fn login_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/login")
}

fn refresh_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/refresh")
}

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

/// A logged-in session (real login, real DPoP-bound refresh token) shared
/// as the baseline every refresh test starts from.
struct Session {
    state: AppState,
    keypair: DpopKeypair,
    refresh_token: String,
}

async fn login_session(prefix: &str) -> Session {
    let state = common::test_app_state().await;
    let email = common::unique_email(prefix);
    let password = "a genuinely long refresh test passphrase";
    create_test_user(&state, &email, password).await;

    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);

    let (status, body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password }),
        Some(&login_proof),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup login should succeed");

    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    Session {
        state,
        keypair,
        refresh_token,
    }
}

async fn call_refresh(
    state: &AppState,
    refresh_token: &str,
    keypair: &DpopKeypair,
) -> (StatusCode, Value) {
    let proof = DpopProofBuilder::new("POST", &refresh_url()).sign(keypair);
    post_json(
        auth_service::app(state.clone()),
        "/refresh",
        json!({ "refresh_token": refresh_token }),
        Some(&proof),
    )
    .await
}

#[tokio::test]
async fn refresh_succeeds_and_rotates() {
    let session = login_session("refresh-success").await;

    let (status, body) =
        call_refresh(&session.state, &session.refresh_token, &session.keypair).await;
    assert_eq!(status, StatusCode::OK);

    let new_refresh_token = body["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh_token, session.refresh_token);

    let old_hash = auth_service::random::hash_token(&session.refresh_token);
    let new_hash = auth_service::random::hash_token(new_refresh_token);

    let old_record = session
        .state
        .refresh_store
        .find_by_hash(&old_hash)
        .await
        .unwrap()
        .unwrap();
    let new_record = session
        .state
        .refresh_store
        .find_by_hash(&new_hash)
        .await
        .unwrap()
        .unwrap();

    assert_ne!(old_record.status, RefreshTokenStatus::Active);
    assert_eq!(new_record.status, RefreshTokenStatus::Active);
    assert_eq!(new_record.family_id, old_record.family_id);
    assert_eq!(new_record.user_email, old_record.user_email);
    assert_eq!(new_record.jkt, old_record.jkt);

    // Re-presenting the original refresh token again is rejected.
    let (replay_status, _) =
        call_refresh(&session.state, &session.refresh_token, &session.keypair).await;
    assert_eq!(replay_status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reuse_after_rotation_revokes_family() {
    let session = login_session("refresh-reuse").await;

    let (rotate_status, rotate_body) =
        call_refresh(&session.state, &session.refresh_token, &session.keypair).await;
    assert_eq!(rotate_status, StatusCode::OK);
    let token_b = rotate_body["refresh_token"].as_str().unwrap().to_string();

    // Replay the original (now-rotated-away) token — the reuse signal.
    let (reuse_status, reuse_body) =
        call_refresh(&session.state, &session.refresh_token, &session.keypair).await;
    assert_eq!(reuse_status, StatusCode::UNAUTHORIZED);
    assert_eq!(reuse_body["error"], "refresh_token_reused");

    // The legitimately-rotated-to token is now ALSO rejected — proving
    // family-wide revocation, not just single-token invalidation.
    let (token_b_status, _) = call_refresh(&session.state, &token_b, &session.keypair).await;
    assert_eq!(token_b_status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_with_wrong_key_rejected_without_side_effects() {
    let session = login_session("refresh-wrong-key").await;
    let other_keypair = DpopKeypair::generate();

    let (status, body) = call_refresh(&session.state, &session.refresh_token, &other_keypair).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");

    // A subsequent correctly-keyed refresh of the same token still
    // succeeds — a key mismatch didn't rotate or revoke anything.
    let (retry_status, _) =
        call_refresh(&session.state, &session.refresh_token, &session.keypair).await;
    assert_eq!(retry_status, StatusCode::OK);
}

#[tokio::test]
async fn expired_refresh_token_rejected() {
    let state = common::test_app_state().await;
    let email = common::unique_email("refresh-expired");
    let password = "a genuinely long refresh test passphrase 2";
    create_test_user(&state, &email, password).await;

    let keypair = DpopKeypair::generate();
    let jkt = keypair.thumbprint();
    let expired_token = common::insert_backdated_refresh_token(&email, &jkt).await;

    let (status, body) = call_refresh(&state, &expired_token, &keypair).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Generic response, not the reuse signal — expiry isn't reuse.
    assert_eq!(body["error"], "invalid_refresh_token");
}

#[tokio::test]
async fn unknown_refresh_token_rejected() {
    let state = common::test_app_state().await;
    let keypair = DpopKeypair::generate();
    let garbage_token = auth_service::random::generate_opaque_token(32);

    let (status, body) = call_refresh(&state, &garbage_token, &keypair).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_refresh_token");
}
