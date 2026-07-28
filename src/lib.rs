use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod dpop;
pub mod login;
pub mod password;
pub mod random;
pub mod refresh;
pub mod refresh_token;
pub mod register;
pub mod store;
pub mod token;
pub mod user;

use dpop::PublicBaseUrl;
use store::{DpopReplayStore, RefreshTokenStore, UserStore};
use token::JwtKeys;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn UserStore>,
    pub refresh_store: Arc<dyn RefreshTokenStore>,
    pub dpop_replay: Arc<dyn DpopReplayStore>,
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

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/register", post(register::register_handler))
        .route("/login", post(login::login_handler))
        .route("/refresh", post(refresh::refresh_handler))
        .route("/me", get(auth::me_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
