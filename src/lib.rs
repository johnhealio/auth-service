use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

pub mod password;
pub mod register;
pub mod store;
pub mod user;

use store::UserStore;

async fn healthz() -> &'static str {
    "ok"
}

pub fn app(store: Arc<dyn UserStore>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/register", post(register::register_handler))
        .with_state(store)
        .layer(TraceLayer::new_for_http())
}
