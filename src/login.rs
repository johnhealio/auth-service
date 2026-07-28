use std::sync::{Arc, LazyLock};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::dpop::{self, DpopError, PublicBaseUrl};
use crate::password;
use crate::random::{generate_opaque_token, hash_token};
use crate::refresh_token::NewRefreshToken;
use crate::store::{DpopReplayStore, RefreshTokenStore, UserStore};
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

/// Shared by `/login` and `/refresh` — both hand back a fresh access +
/// refresh token pair, just via different store operations internally
/// (`create` establishes a new family, `rotate` continues one).
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn login_handler(
    State(store): State<Arc<dyn UserStore>>,
    State(refresh_store): State<Arc<dyn RefreshTokenStore>>,
    State(dpop_replay): State<Arc<dyn DpopReplayStore>>,
    State(jwt): State<Arc<JwtKeys>>,
    State(base_url): State<PublicBaseUrl>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
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

    // Validated only after credentials succeed: a bad DPoP proof on a
    // doomed-anyway login attempt shouldn't get a different error path or
    // add a timing signal distinguishing "bad password" from "bad proof."
    let dpop_header = match headers.get("DPoP").and_then(|value| value.to_str().ok()) {
        Some(header) => header,
        None => return dpop_error_response(StatusCode::BAD_REQUEST, &DpopError::Missing),
    };

    let proof = match dpop::validate_dpop_proof(
        dpop_header,
        &method,
        &base_url,
        uri.path(),
        None,
        dpop_replay.as_ref(),
    )
    .await
    {
        Ok(proof) => proof,
        Err(err) => return dpop_error_response(StatusCode::BAD_REQUEST, &err),
    };

    let (access_token, _claims) = match jwt.issue_access_token(&user.user_id, &proof.jkt) {
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
                jkt: proof.jkt.clone(),
            },
            &token_hash,
        )
        .await
    {
        tracing::error!(error = %err, "failed to store refresh token");
        return internal_error();
    }

    Json(TokenResponse {
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

fn dpop_error_response(status: StatusCode, err: &DpopError) -> Response {
    error_response(status, "invalid_dpop_proof", err.message())
}
