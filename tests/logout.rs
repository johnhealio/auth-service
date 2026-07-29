mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::TEST_PUBLIC_BASE_URL;
use common::create_test_user_with_mfa;
use common::dpop::{DpopKeypair, DpopProofBuilder};

fn login_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/login")
}

fn refresh_url() -> String {
    format!("{TEST_PUBLIC_BASE_URL}/refresh")
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

#[tokio::test]
async fn logout_revokes_refresh_token() {
    let state = common::test_app_state().await;
    let email = common::unique_email("logout-success");
    let password = "a genuinely long logout test passphrase";
    let (_, enrollment) = create_test_user_with_mfa(&state, &email, password).await;

    let keypair = DpopKeypair::generate();
    let login_proof = DpopProofBuilder::new("POST", &login_url()).sign(&keypair);
    let (login_status, login_body) = post_json(
        auth_service::app(state.clone()),
        "/login",
        json!({ "email": email, "password": password, "mfa_code": enrollment.generate_current() }),
        Some(&login_proof),
    )
    .await;
    assert_eq!(login_status, StatusCode::OK);
    let refresh_token = login_body["refresh_token"].as_str().unwrap().to_string();

    let (logout_status, logout_body) = post_json(
        auth_service::app(state.clone()),
        "/logout",
        json!({ "refresh_token": refresh_token }),
        None,
    )
    .await;
    assert_eq!(logout_status, StatusCode::OK);
    assert_eq!(logout_body["logged_out"], true);

    // The now-revoked refresh token no longer works.
    let refresh_proof = DpopProofBuilder::new("POST", &refresh_url()).sign(&keypair);
    let (refresh_status, _) = post_json(
        auth_service::app(state.clone()),
        "/refresh",
        json!({ "refresh_token": refresh_token }),
        Some(&refresh_proof),
    )
    .await;
    assert_eq!(refresh_status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_with_unknown_token_still_reports_success() {
    let state = common::test_app_state().await;
    let garbage_token = auth_service::random::generate_opaque_token(32);

    let (status, body) = post_json(
        auth_service::app(state),
        "/logout",
        json!({ "refresh_token": garbage_token }),
        None,
    )
    .await;

    // No information leak about token validity — always success.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["logged_out"], true);
}
