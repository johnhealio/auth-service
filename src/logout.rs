use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::error::AppJson;
use crate::random::hash_token;
use crate::store::RefreshTokenStore;

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub logged_out: bool,
}

/// Deliberately simple: no DPoP requirement, and always reports success
/// whether or not the token was found/valid — an unconditional response,
/// not just an identical error shape, so this endpoint can't be used to
/// probe token validity at all.
pub async fn logout_handler(
    State(refresh_store): State<Arc<dyn RefreshTokenStore>>,
    AppJson(request): AppJson<LogoutRequest>,
) -> Response {
    let token_hash = hash_token(&request.refresh_token);

    match refresh_store.find_by_hash(&token_hash).await {
        Ok(Some(record)) => {
            if let Err(err) = refresh_store.revoke_family(&record.family_id).await {
                tracing::error!(error = %err, "failed to revoke family during logout");
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "firestore backend error during logout lookup");
        }
    }

    Json(LogoutResponse { logged_out: true }).into_response()
}
