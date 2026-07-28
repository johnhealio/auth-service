use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod login;
pub mod password;
pub mod random;
pub mod refresh_token;
pub mod register;
pub mod store;
pub mod token;
pub mod user;

use store::{RefreshTokenStore, UserStore};
use token::JwtKeys;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn UserStore>,
    pub refresh_store: Arc<dyn RefreshTokenStore>,
    pub jwt: Arc<JwtKeys>,
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

impl FromRef<AppState> for Arc<JwtKeys> {
    fn from_ref(state: &AppState) -> Self {
        state.jwt.clone()
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
        .route("/me", get(auth::me_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
