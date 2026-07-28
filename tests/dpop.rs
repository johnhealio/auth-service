mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::AppState;
use common::TEST_PUBLIC_BASE_URL;
use common::create_test_user;
use common::dpop::{DpopKeypair, DpopProofBuilder};

fn login_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/login")
}

fn me_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/me")
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

/// A logged-in session (real login, real DPoP-bound access token) shared
/// as the baseline every negative test starts from.
struct Session {
    state: AppState,
    keypair: DpopKeypair,
    access_token: String,
}

async fn login_session(prefix: &str) -> Session {
    let state = common::test_app_state().await;
    let email = common::unique_email(prefix);
    let password = "a genuinely long dpop test passphrase";
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

    let access_token = body["access_token"].as_str().unwrap().to_string();

    Session {
        state,
        keypair,
        access_token,
    }
}

async fn call_me(session: &Session, proof: Option<&str>) -> (StatusCode, Value) {
    get_with_auth(
        auth_service::app(session.state.clone()),
        "/me",
        Some(&format!("Bearer {}", session.access_token)),
        proof,
    )
    .await
}

#[tokio::test]
async fn wrong_htm_rejected() {
    let session = login_session("dpop-wrong-htm").await;

    // Proof claims POST but the actual request is GET /me.
    let proof = DpopProofBuilder::new("POST", &me_url())
        .ath_for_token(&session.access_token)
        .sign(&session.keypair);

    let (status, body) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn wrong_htu_rejected() {
    let session = login_session("dpop-wrong-htu").await;

    let proof = DpopProofBuilder::new("GET", &format!("{TEST_PUBLIC_BASE_URL}/somewhere-else"))
        .ath_for_token(&session.access_token)
        .sign(&session.keypair);

    let (status, _) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stale_iat_rejected() {
    let session = login_session("dpop-stale-iat").await;

    // Older than the 300s replay window.
    let proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(&session.access_token)
        .iat_offset(-400)
        .sign(&session.keypair);

    let (status, _) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn future_iat_beyond_skew_rejected() {
    let session = login_session("dpop-future-iat").await;

    // Beyond the 60s clock-skew tolerance.
    let proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(&session.access_token)
        .iat_offset(120)
        .sign(&session.keypair);

    let (status, _) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replayed_jti_rejected() {
    let session = login_session("dpop-replay").await;

    let proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(&session.access_token)
        .sign(&session.keypair);

    let (first_status, _) = call_me(&session, Some(&proof)).await;
    assert_eq!(first_status, StatusCode::OK);

    // Exact same proof, presented again.
    let (second_status, _) = call_me(&session, Some(&proof)).await;
    assert_eq!(second_status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_key_rejected() {
    let session = login_session("dpop-wrong-key").await;

    // Signed by a different keypair than the one bound at login — the
    // proof is otherwise perfectly valid and self-consistent.
    let other_keypair = DpopKeypair::generate();
    let proof = DpopProofBuilder::new("GET", &me_url())
        .ath_for_token(&session.access_token)
        .sign(&other_keypair);

    let (status, _) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_ath_rejected() {
    let session = login_session("dpop-wrong-ath").await;

    let proof = DpopProofBuilder::new("GET", &me_url())
        .ath_raw("not-the-real-token-hash")
        .sign(&session.keypair);

    let (status, _) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_dpop_header_on_me_rejected() {
    let session = login_session("dpop-missing-header").await;

    // A valid bearer token, but no DPoP header at all.
    let (status, body) = call_me(&session, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn disallowed_algorithm_rejected() {
    let session = login_session("dpop-wrong-alg").await;

    // jsonwebtoken has no `Algorithm::None`, so this covers the
    // alg-restriction check via a symmetric algorithm (HS256) instead —
    // the point is any alg other than ES256 must be rejected outright,
    // before any key or signature is even inspected.
    let claims = json!({
        "htm": "GET",
        "htu": me_url(),
        "iat": jsonwebtoken::get_current_timestamp(),
        "jti": auth_service::random::generate_opaque_token(16),
        "ath": "irrelevant",
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some("dpop+jwt".to_string());
    let proof = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"irrelevant-hs256-secret"),
    )
    .unwrap();

    let (status, body) = call_me(&session, Some(&proof)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_dpop_proof");
}
