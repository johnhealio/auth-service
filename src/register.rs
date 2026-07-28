use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::password;
use crate::random::generate_opaque_token;
use crate::store::{StoreError, UserStore};
use crate::user::NewUser;

// Raised from NIST 800-63B's 8-char floor: the standard stronger default
// when MFA isn't in place yet. Backed by the breached-password check below
// so "strong password" is enforced, not just assumed.
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 256;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub email: String,
    pub created_at: DateTime<Utc>,
}

pub async fn register_handler(
    State(store): State<Arc<dyn UserStore>>,
    Json(request): Json<RegisterRequest>,
) -> Response {
    let email = request.email.trim().to_lowercase();

    if let Err(message) = validate_email(&email) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
    }

    if let Err(message) = validate_password(&request.password) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", &message);
    }

    match password::check_breached(&request.password).await {
        Ok(true) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this password has appeared in a data breach; choose a different one",
            );
        }
        Ok(false) => {}
        Err(err) => {
            // Fail-open: don't couple registration availability to a third
            // party's uptime.
            tracing::warn!(error = %err, "breached-password check failed; allowing registration");
        }
    }

    let password_hash = match password::hash_password(&request.password) {
        Ok(hash) => hash,
        Err(err) => {
            tracing::error!(error = %err, "password hashing failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to process registration",
            );
        }
    };

    match store
        .create_user(NewUser {
            user_id: generate_opaque_token(16),
            email,
            password_hash,
        })
        .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(RegisterResponse {
                email: user.email,
                created_at: user.created_at,
            }),
        )
            .into_response(),
        Err(StoreError::DuplicateEmail) => error_response(
            StatusCode::CONFLICT,
            "email_already_registered",
            "an account with this email already exists",
        ),
        Err(StoreError::Backend(err)) => {
            tracing::error!(error = %err, "firestore backend error during registration");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to process registration",
            )
        }
        Err(other) => {
            // Not real code paths for user creation — a UserStore never
            // returns these variants — but StoreError is shared across
            // store traits, so match exhaustively rather than panic if one
            // ever did.
            tracing::error!(error = %other, "unexpected StoreError from create_user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to process registration",
            )
        }
    }
}

fn validate_email(email: &str) -> Result<(), String> {
    let Some((local, domain)) = email.split_once('@') else {
        return Err("email must contain '@'".to_string());
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("email is not a valid address".to_string());
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("password must not be empty".to_string());
    }
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if len > MAX_PASSWORD_LEN {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({ "error": error, "message": message }))).into_response()
}
