use std::sync::Arc;

use axum::Json;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::token::JwtKeys;

/// Bearer-JWT auth extractor. Verifies the `Authorization: Bearer <token>`
/// header against the app's signing key and yields the token's identity.
/// Reused as-is by DPoP (Module 6), which layers proof-of-possession
/// validation on top rather than replacing this.
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

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(unauthorized)?;

        let token = header.strip_prefix("Bearer ").ok_or_else(unauthorized)?;

        let claims = jwt.verify_access_token(token).map_err(|_| unauthorized())?;

        Ok(AuthUser {
            user_id: claims.sub,
        })
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "message": "missing or invalid access token" })),
    )
        .into_response()
}

pub async fn me_handler(user: AuthUser) -> Response {
    Json(json!({ "user_id": user.user_id })).into_response()
}
