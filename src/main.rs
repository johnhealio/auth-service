use std::net::SocketAddr;
use std::sync::Arc;

use firestore::{FirestoreDb, FirestoreDbOptions};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use auth_service::AppState;
use auth_service::dpop::PublicBaseUrl;
use auth_service::store::firestore::{
    FirestoreDpopReplayStore, FirestoreLoginAttemptStore, FirestoreRefreshTokenStore,
    FirestoreUserStore,
};
use auth_service::store::{DpopReplayStore, LoginAttemptStore, RefreshTokenStore, UserStore};
use auth_service::token::JwtKeys;

#[tokio::main]
async fn main() {
    // No-op if missing (e.g. the deployed container, which gets its env
    // from Cloud Run/Secret Manager, not a file). Real env vars always
    // win — dotenvy never overwrites an already-set var.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let project_id =
        std::env::var("FIRESTORE_PROJECT_ID").expect("FIRESTORE_PROJECT_ID must be set");
    let database_id = std::env::var("FIRESTORE_DATABASE_ID")
        .unwrap_or_else(|_| firestore::FIREBASE_DEFAULT_DATABASE_ID.to_string());

    let options = FirestoreDbOptions::new(project_id).with_database_id(database_id);
    let db = FirestoreDb::with_options(options)
        .await
        .expect("failed to connect to Firestore");

    let store: Arc<dyn UserStore> = Arc::new(FirestoreUserStore::new(db.clone()));
    let refresh_store: Arc<dyn RefreshTokenStore> =
        Arc::new(FirestoreRefreshTokenStore::new(db.clone()));
    let dpop_replay: Arc<dyn DpopReplayStore> = Arc::new(FirestoreDpopReplayStore::new(db.clone()));
    let login_attempts: Arc<dyn LoginAttemptStore> = Arc::new(FirestoreLoginAttemptStore::new(db));
    let jwt = Arc::new(JwtKeys::from_env());
    let public_base_url = PublicBaseUrl::from_env();

    let state = AppState {
        store,
        refresh_store,
        dpop_replay,
        login_attempts,
        jwt,
        public_base_url,
    };

    let addr = "0.0.0.0:8080";
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind address");
    tracing::info!(%addr, "auth-service listening");

    // into_make_service_with_connect_info is required for the rate
    // limiter's ConnectInfo fallback to ever populate (see
    // rate_limit::CloudRunKeyExtractor) — plain axum::serve never
    // injects ConnectInfo into request extensions.
    axum::serve(
        listener,
        auth_service::app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}
