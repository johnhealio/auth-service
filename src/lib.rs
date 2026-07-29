use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post};
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod dpop;
pub mod error;
pub mod login;
pub mod password;
pub mod random;
pub mod rate_limit;
pub mod refresh;
pub mod refresh_token;
pub mod register;
pub mod security_headers;
pub mod store;
pub mod token;
pub mod user;

use dpop::PublicBaseUrl;
use store::{DpopReplayStore, LoginAttemptStore, RefreshTokenStore, UserStore};
use token::JwtKeys;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn UserStore>,
    pub refresh_store: Arc<dyn RefreshTokenStore>,
    pub dpop_replay: Arc<dyn DpopReplayStore>,
    pub login_attempts: Arc<dyn LoginAttemptStore>,
    pub jwt: Arc<JwtKeys>,
    pub public_base_url: PublicBaseUrl,
}

impl FromRef<AppState> for Arc<dyn UserStore> {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for Arc<dyn RefreshTokenStore> {
    fn from_ref(state: &AppState) -> Self {
        state.refresh_store.clone()
    }
}

impl FromRef<AppState> for Arc<dyn DpopReplayStore> {
    fn from_ref(state: &AppState) -> Self {
        state.dpop_replay.clone()
    }
}

impl FromRef<AppState> for Arc<dyn LoginAttemptStore> {
    fn from_ref(state: &AppState) -> Self {
        state.login_attempts.clone()
    }
}

impl FromRef<AppState> for Arc<JwtKeys> {
    fn from_ref(state: &AppState) -> Self {
        state.jwt.clone()
    }
}

impl FromRef<AppState> for PublicBaseUrl {
    fn from_ref(state: &AppState) -> Self {
        state.public_base_url.clone()
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// Built fresh on every call — critical for two reasons: (1) production
/// correctness (one shared in-memory rate limiter per Cloud Run instance
/// for the process's lifetime, matching this project's "in-memory,
/// per-instance" rate-limiting decision — NOT a module-level `static`,
/// which would be wrong here regardless), and (2) test isolation, since
/// every test in this crate rebuilds `app()` on every HTTP call, giving
/// each call an independent rate-limit bucket.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/register",
            post(register::register_handler).layer(
                GovernorLayer::new(rate_limit::register_config())
                    .error_handler(rate_limit::rate_limit_error_handler),
            ),
        )
        .route(
            "/login",
            post(login::login_handler).layer(
                GovernorLayer::new(rate_limit::login_config())
                    .error_handler(rate_limit::rate_limit_error_handler),
            ),
        )
        .route(
            "/refresh",
            post(refresh::refresh_handler).layer(
                GovernorLayer::new(rate_limit::refresh_config())
                    .error_handler(rate_limit::rate_limit_error_handler),
            ),
        )
        .route("/me", get(auth::me_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn(
            security_headers::security_headers,
        ))
        .layer(TraceLayer::new_for_http())
}
