use std::sync::{Arc, LazyLock};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::password;
use crate::random::{generate_opaque_token, hash_token};
use crate::refresh_token::NewRefreshToken;
use crate::store::{RefreshTokenStore, UserStore};
use crate::token::JwtKeys;

// Paid on every login where the account doesn't exist, so that path costs
// the same Argon2 time as a real-account wrong-password attempt — closing
// a timing side channel that would otherwise leak account existence even
// with an identical error message.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    password::hash_password("dummy-value-paid-for-timing-parity-only")
        .expect("dummy hash must succeed")
});

const REFRESH_TOKEN_BYTE_LEN: usize = 32; // 256 bits

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
}

pub async fn login_handler(
    State(store): State<Arc<dyn UserStore>>,
    State(refresh_store): State<Arc<dyn RefreshTokenStore>>,
    State(jwt): State<Arc<JwtKeys>>,
    Json(request): Json<LoginRequest>,
) -> Response {
    let email = request.email.trim().to_lowercase();

    let user = match store.find_by_email(&email).await {
        Ok(user) => user,
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error during login lookup");
            return internal_error();
        }
    };

    let verification = match &user {
        Some(user) => password::verify_password(&request.password, &user.password_hash),
        None => password::verify_password(&request.password, &DUMMY_HASH),
    };

    let verified = match verification {
        Ok(verified) => verified,
        Err(err) => {
            tracing::error!(error = %err, "password verification failed");
            return internal_error();
        }
    };

    let Some(user) = user.filter(|_| verified) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid email or password",
        );
    };

    let (access_token, _claims) = match jwt.issue_access_token(&user.user_id) {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(error = %err, "failed to issue access token");
            return internal_error();
        }
    };

    let refresh_token = generate_opaque_token(REFRESH_TOKEN_BYTE_LEN);
    let token_hash = hash_token(&refresh_token);

    if let Err(err) = refresh_store
        .create(
            NewRefreshToken {
                user_email: user.email.clone(),
            },
            &token_hash,
        )
        .await
    {
        tracing::error!(error = %err, "failed to store refresh token");
        return internal_error();
    }

    Json(LoginResponse {
        access_token,
        token_type: "Bearer",
        expires_in: jwt.ttl().as_secs(),
        refresh_token,
    })
    .into_response()
}

fn internal_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "failed to process login",
    )
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({ "error": error, "message": message }))).into_response()
}
