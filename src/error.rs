use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::dpop::DpopError;

/// This app's one JSON error shape: `{"error": .., "message": ..}`.
/// Callers choose their own status code, so different endpoints can keep
/// returning different codes for the same logical error (e.g.
/// `invalid_dpop_proof` is 400 at `/login`/`/refresh` but 401 on `/me`).
pub fn error_response(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({ "error": error, "message": message }))).into_response()
}

pub fn dpop_error_response(status: StatusCode, err: &DpopError) -> Response {
    error_response(status, "invalid_dpop_proof", err.message())
}

/// `401 unauthorized` — missing/invalid bearer token.
pub fn unauthorized() -> Response {
    error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or invalid access token",
    )
}

/// `500 internal_error` with a caller-supplied message, since each
/// handler's internal-error message is phrased per-endpoint.
pub fn internal_error(message: &str) -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
}

/// Drop-in replacement for `axum::Json<T>` as a request-body extractor.
/// Axum's own `JsonRejection` (malformed JSON, wrong/missing
/// content-type, body-read failure) otherwise escapes this app's error
/// shape entirely and falls back to axum's built-in plain-text rejection
/// body. Reuses `JsonRejection`'s own per-variant status (400 syntax
/// error, 415 wrong content-type, etc.) rather than hardcoding one.
pub struct AppJson<T>(pub T);

impl<S, T> FromRequest<S> for AppJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(AppJson(value)),
            Err(rejection) => Err(error_response(
                rejection.status(),
                "invalid_json",
                &rejection.body_text(),
            )),
        }
    }
}
