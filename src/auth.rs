use std::sync::Arc;

use axum::Json;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::dpop::{self, DpopError, PublicBaseUrl};
use crate::store::DpopReplayStore;
use crate::token::JwtKeys;

/// Bearer-JWT auth extractor. Verifies the `Authorization: Bearer <token>`
/// header against the app's signing key and yields the token's identity.
/// Kept available in isolation (not folded into `DpopBoundUser`) for
/// anything that might not need DPoP later.
pub struct AuthUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    Arc<JwtKeys>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt = Arc::<JwtKeys>::from_ref(state);
        let token = extract_bearer_token(parts)?;
        let claims = jwt.verify_access_token(token).map_err(|_| unauthorized())?;

        Ok(AuthUser {
            user_id: claims.sub,
        })
    }
}

/// DPoP-bound auth extractor (Module 6). Verifies the bearer JWT (as
/// `AuthUser` does) *and* a `DPoP` proof presented alongside it: the
/// proof's `ath` must hash-match the actual bearer token, and the proof's
/// key thumbprint must match the token's `cnf.jkt` binding from issuance.
/// DPoP is mandatory — there is no bearer-only fallback.
pub struct DpopBoundUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for DpopBoundUser
where
    Arc<JwtKeys>: FromRef<S>,
    Arc<dyn DpopReplayStore>: FromRef<S>,
    PublicBaseUrl: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt = Arc::<JwtKeys>::from_ref(state);
        let replay_store = Arc::<dyn DpopReplayStore>::from_ref(state);
        let base_url = PublicBaseUrl::from_ref(state);

        let token = extract_bearer_token(parts)?;
        let claims = jwt.verify_access_token(token).map_err(|_| unauthorized())?;

        let dpop_header = parts
            .headers
            .get("DPoP")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| dpop_error_response(&DpopError::Missing))?;

        let method = parts.method.clone();
        let path = parts.uri.path().to_string();

        let proof = dpop::validate_dpop_proof(
            dpop_header,
            &method,
            &base_url,
            &path,
            Some(token),
            replay_store.as_ref(),
        )
        .await
        .map_err(|err| dpop_error_response(&err))?;

        if proof.jkt != claims.cnf.jkt {
            return Err(dpop_error_response(&DpopError::KeyMismatch));
        }

        Ok(DpopBoundUser {
            user_id: claims.sub,
        })
    }
}

// Response is a large Err type, but this is a once-per-request path, not
// a hot loop — boxing it would just add indirection at every call site.
#[allow(clippy::result_large_err)]
fn extract_bearer_token(parts: &Parts) -> Result<&str, Response> {
    let header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(unauthorized)?;

    header.strip_prefix("Bearer ").ok_or_else(unauthorized)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "message": "missing or invalid access token" })),
    )
        .into_response()
}

fn dpop_error_response(err: &DpopError) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid_dpop_proof", "message": err.message() })),
    )
        .into_response()
}

pub async fn me_handler(user: DpopBoundUser) -> Response {
    Json(json!({ "user_id": user.user_id })).into_response()
}
