use std::sync::{Arc, LazyLock};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::dpop::{self, DpopError, PublicBaseUrl};
use crate::error::{AppJson, dpop_error_response, error_response};
use crate::password;
use crate::random::{generate_opaque_token, hash_token};
use crate::refresh_token::NewRefreshToken;
use crate::store::{
    DpopReplayStore, LoginAttemptState, LoginAttemptStore, RecoveryCodeStore, RefreshTokenStore,
    UserStore,
};
use crate::token::JwtKeys;
use crate::totp;

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
    /// Required — every account has MFA enrolled (Module 11, mandatory).
    /// Tried first as a TOTP code; if that fails, tried as a recovery
    /// code. A non-matching string for either shape just fails
    /// harmlessly, so no format-sniffing is needed.
    pub mfa_code: String,
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
    State(login_attempts): State<Arc<dyn LoginAttemptStore>>,
    State(recovery_codes): State<Arc<dyn RecoveryCodeStore>>,
    State(jwt): State<Arc<JwtKeys>>,
    State(base_url): State<PublicBaseUrl>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    AppJson(request): AppJson<LoginRequest>,
) -> Response {
    let email = request.email.trim().to_lowercase();

    // Checked before any Argon2 work, using the *submitted* email string
    // unconditionally — same enumeration-safety requirement as
    // DUMMY_HASH below: must not distinguish real accounts from fake
    // ones.
    match login_attempts.check(&email).await {
        Ok(LoginAttemptState::Locked { retry_after }) => {
            return account_locked_response(retry_after);
        }
        Ok(LoginAttemptState::Allowed) => {}
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error during lockout check");
            return internal_error();
        }
    }

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
        // Recorded unconditionally, whether or not `email` is a real
        // account — the increment itself must stay symmetric, or lockout
        // state becomes an enumeration side channel.
        if let Err(err) = login_attempts.record_failure(&email).await {
            tracing::error!(error = %err, "failed to record login failure");
            // Fail open: a lockout-bookkeeping error shouldn't block the
            // (already-decided) generic rejection response.
        }
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid email or password",
        );
    };

    if let Err(err) = login_attempts.reset(&email).await {
        tracing::error!(error = %err, "failed to reset login attempt counter");
        // Not fatal to the login itself.
    }

    // Every account must have completed enrollment (Module 11) before
    // it's usable — the password was already confirmed correct above, so
    // this doesn't leak account existence, only that this particular,
    // already-proven-real account isn't finished setting up.
    if !user.mfa_enrolled {
        return error_response(
            StatusCode::FORBIDDEN,
            "mfa_not_enrolled",
            "finish MFA enrollment via /register/confirm before logging in",
        );
    }

    let mfa_ok = if totp::check_code(&user.mfa_secret, &user.email, &request.mfa_code) {
        true
    } else {
        let code_hash = hash_token(&request.mfa_code);
        match recovery_codes.redeem(&user.email, &code_hash).await {
            Ok(redeemed) => redeemed,
            Err(err) => {
                tracing::error!(error = %err, "firestore backend error during recovery-code redemption");
                return internal_error();
            }
        }
    };

    if !mfa_ok {
        // Shared lockout budget with wrong-password failures — one
        // account-level brute-force counter, not two independent ones.
        if let Err(err) = login_attempts.record_failure(&email).await {
            tracing::error!(error = %err, "failed to record login failure");
        }
        return error_response(
            StatusCode::UNAUTHORIZED,
            "mfa_code_invalid",
            "invalid MFA code",
        );
    }

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
    crate::error::internal_error("failed to process login")
}

fn account_locked_response(retry_after: chrono::DateTime<chrono::Utc>) -> Response {
    let retry_after_secs = (retry_after - chrono::Utc::now()).num_seconds().max(0);
    let mut response = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "account_locked",
        "too many failed login attempts; try again later",
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert("retry-after", value);
    }
    response
}
