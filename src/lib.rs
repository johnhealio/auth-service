use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;

async fn healthz() -> &'static str {
    "ok"
}

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .layer(TraceLayer::new_for_http())
}
