use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::dpop::{self, DpopError, PublicBaseUrl};
use crate::login::TokenResponse;
use crate::random::{generate_opaque_token, hash_token};
use crate::refresh_token::RefreshTokenStatus;
use crate::store::{DpopReplayStore, RefreshTokenStore, StoreError, UserStore};
use crate::token::JwtKeys;

const REFRESH_TOKEN_BYTE_LEN: usize = 32; // 256 bits

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn refresh_handler(
    State(store): State<Arc<dyn UserStore>>,
    State(refresh_store): State<Arc<dyn RefreshTokenStore>>,
    State(dpop_replay): State<Arc<dyn DpopReplayStore>>,
    State(jwt): State<Arc<JwtKeys>>,
    State(base_url): State<PublicBaseUrl>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Response {
    let token_hash = hash_token(&request.refresh_token);

    // Token lookup before DPoP validation, mirroring login's
    // password-before-DPoP ordering: branch structure shouldn't differ
    // based on which check would've failed first.
    let record = match refresh_store.find_by_hash(&token_hash).await {
        Ok(record) => record,
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error during refresh lookup");
            return internal_error();
        }
    };

    let Some(record) = record else {
        return invalid_refresh_token_response();
    };

    // Non-Active here means this token was already rotated away or
    // revoked — presenting it again is the reuse signal, handled
    // distinctly from "not found" (see CLAUDE.md Module 7 decisions).
    if record.status != RefreshTokenStatus::Active {
        if let Err(err) = refresh_store.revoke_family(&record.family_id).await {
            tracing::error!(error = %err, "failed to revoke family after detecting refresh token reuse");
        }
        return reused_refresh_token_response();
    }
    if record.expires_at < Utc::now() {
        return invalid_refresh_token_response();
    }

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

    // Refresh must be bound to the same key that obtained it (RFC 9449 §5).
    // A mismatch is a rejected-but-untouched attempt, not a theft signal —
    // the opaque token secret was presented correctly, only the
    // proof-of-possession key differs, more plausibly a client bug than
    // evidence of token theft.
    if proof.jkt != record.jkt {
        return dpop_error_response(StatusCode::BAD_REQUEST, &DpopError::KeyMismatch);
    }

    let user = match store.find_by_email(&record.user_email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::error!(email = %record.user_email, "refresh token's user no longer exists");
            return internal_error();
        }
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error looking up refresh token's user");
            return internal_error();
        }
    };

    let new_refresh_token = generate_opaque_token(REFRESH_TOKEN_BYTE_LEN);
    let new_token_hash = hash_token(&new_refresh_token);

    match refresh_store
        .rotate(&token_hash, &new_token_hash, &proof.jkt)
        .await
    {
        Ok(_) => {}
        Err(StoreError::Reused) => return reused_refresh_token_response(),
        Err(StoreError::NotFound) | Err(StoreError::Expired) => {
            return invalid_refresh_token_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to rotate refresh token");
            return internal_error();
        }
    }

    let (access_token, _claims) = match jwt.issue_access_token(&user.user_id, &proof.jkt) {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(error = %err, "failed to issue access token");
            return internal_error();
        }
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: jwt.ttl().as_secs(),
        refresh_token: new_refresh_token,
    })
    .into_response()
}

fn internal_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "failed to process refresh",
    )
}

fn invalid_refresh_token_response() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "invalid_refresh_token",
        "invalid or expired refresh token",
    )
}

fn reused_refresh_token_response() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "refresh_token_reused",
        "this refresh token has already been used; your session has been revoked for security reasons, please log in again",
    )
}

fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({ "error": error, "message": message }))).into_response()
}

fn dpop_error_response(status: StatusCode, err: &DpopError) -> Response {
    error_response(status, "invalid_dpop_proof", err.message())
}
