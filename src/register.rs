use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{AppJson, error_response, internal_error};
use crate::password;
use crate::random::{generate_opaque_token, hash_token};
use crate::store::{StoreError, UserStore};
use crate::totp;
use crate::user::NewUser;

// Raised from NIST 800-63B's 8-char floor: the standard stronger default
// when MFA isn't in place yet. Backed by the breached-password check below
// so "strong password" is enforced, not just assumed.
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 256;

// Module 11: mandatory MFA. 10 single-use recovery codes are generated at
// confirm time, shown exactly once, never retrievable again.
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_BYTE_LEN: usize = 5; // -> 10 hex chars, grouped "abcde-fghij"

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub email: String,
    pub created_at: DateTime<Utc>,
    /// `otpauth://` URL — scan or paste into an authenticator app.
    pub mfa_enrollment_url: String,
    /// Base32 secret, for manual entry when a QR code isn't practical.
    pub mfa_secret_base32: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub email: String,
    pub mfa_code: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmResponse {
    pub email: String,
    /// Plaintext, shown exactly once — never retrievable again.
    pub recovery_codes: Vec<String>,
}

pub async fn register_handler(
    State(store): State<Arc<dyn UserStore>>,
    AppJson(request): AppJson<RegisterRequest>,
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
            return internal_error("failed to process registration");
        }
    };

    let enrollment = totp::generate_enrollment_secret(&email);

    match store
        .create_user(NewUser {
            user_id: generate_opaque_token(16),
            email,
            password_hash,
            mfa_secret: enrollment.secret_bytes(),
        })
        .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(RegisterResponse {
                email: user.email,
                created_at: user.created_at,
                mfa_enrollment_url: enrollment.otpauth_url(),
                mfa_secret_base32: enrollment.base32_secret(),
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
            internal_error("failed to process registration")
        }
        Err(other) => {
            // Not real code paths for user creation — a UserStore never
            // returns these variants — but StoreError is shared across
            // store traits, so match exhaustively rather than panic if one
            // ever did.
            tracing::error!(error = %other, "unexpected StoreError from create_user");
            internal_error("failed to process registration")
        }
    }
}

/// Step two of the mandatory-MFA ceremony (Module 11): an account created
/// by `register_handler` isn't usable for login until this succeeds. On
/// success, generates and returns the account's recovery codes exactly
/// once.
pub async fn register_confirm_handler(
    State(store): State<Arc<dyn UserStore>>,
    AppJson(request): AppJson<ConfirmRequest>,
) -> Response {
    let email = request.email.trim().to_lowercase();

    let user = match store.find_by_email(&email).await {
        Ok(Some(user)) => user,
        Ok(None) => return invalid_confirmation_response(),
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error during confirm lookup");
            return internal_error("failed to process confirmation");
        }
    };

    // Generic response for "already enrolled", "wrong code", and
    // "unknown email" alike — no reason to distinguish them to the caller.
    if user.mfa_enrolled || !totp::check_code(&user.mfa_secret, &email, &request.mfa_code) {
        return invalid_confirmation_response();
    }

    let plaintext_codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| format_recovery_code(&generate_opaque_token(RECOVERY_CODE_BYTE_LEN)))
        .collect();
    let hashes: Vec<String> = plaintext_codes
        .iter()
        .map(|code| hash_token(code))
        .collect();

    match store.confirm_mfa_enrollment(&email, hashes).await {
        Ok(_) => (
            StatusCode::OK,
            Json(ConfirmResponse {
                email,
                recovery_codes: plaintext_codes,
            }),
        )
            .into_response(),
        Err(StoreError::MfaAlreadyEnrolled) | Err(StoreError::NotFound) => {
            invalid_confirmation_response()
        }
        Err(StoreError::Backend(err)) => {
            tracing::error!(error = %err, "firestore backend error during confirm");
            internal_error("failed to process confirmation")
        }
        Err(other) => {
            tracing::error!(error = %other, "unexpected StoreError from confirm_mfa_enrollment");
            internal_error("failed to process confirmation")
        }
    }
}

fn invalid_confirmation_response() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_confirmation",
        "invalid email or MFA code",
    )
}

fn format_recovery_code(raw_hex: &str) -> String {
    raw_hex
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
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
