mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use auth_service::password;

async fn post_register(app: axum::Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
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

#[tokio::test]
async fn register_succeeds_and_password_is_hashed_not_plaintext() {
    let store = common::test_store().await;
    let email = common::unique_email("register-success");
    let password_plain = "a genuinely long passphrase 1";

    let (status, body) = post_register(
        auth_service::app(store.clone()),
        json!({ "email": email, "password": password_plain }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["email"], email);
    assert!(body.get("password_hash").is_none());
    assert!(body.get("password").is_none());

    let stored = store
        .find_by_email(&email)
        .await
        .expect("store lookup should succeed")
        .expect("user should exist after registration");

    assert_ne!(stored.password_hash, password_plain);
    assert!(stored.password_hash.starts_with("$argon2id$"));
    assert!(password::verify_password(password_plain, &stored.password_hash).unwrap());
}

#[tokio::test]
async fn duplicate_email_returns_409() {
    let store = common::test_store().await;
    let email = common::unique_email("register-duplicate");
    let payload = json!({ "email": email, "password": "a genuinely long passphrase 2" });

    let (first_status, _) = post_register(auth_service::app(store.clone()), payload.clone()).await;
    assert_eq!(first_status, StatusCode::CREATED);

    let (second_status, second_body) =
        post_register(auth_service::app(store.clone()), payload).await;

    assert_eq!(second_status, StatusCode::CONFLICT);
    assert_eq!(second_body["error"], "email_already_registered");
}

#[tokio::test]
async fn password_below_minimum_length_returns_400() {
    let store = common::test_store().await;
    let email = common::unique_email("register-short-password");

    let (status, body) = post_register(
        auth_service::app(store),
        json!({ "email": email, "password": "short1" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn known_breached_password_returns_400() {
    let store = common::test_store().await;
    let email = common::unique_email("register-breached-password");

    // Long enough to pass the length check, but a widely-known leaked
    // password — must appear in the Pwned Passwords corpus.
    let (status, body) = post_register(
        auth_service::app(store),
        json!({ "email": email, "password": "password12345678" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}
