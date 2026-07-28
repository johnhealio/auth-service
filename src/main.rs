use std::sync::Arc;

use firestore::{FirestoreDb, FirestoreDbOptions};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use auth_service::AppState;
use auth_service::store::firestore::{FirestoreRefreshTokenStore, FirestoreUserStore};
use auth_service::store::{RefreshTokenStore, UserStore};
use auth_service::token::JwtKeys;

#[tokio::main]
async fn main() {
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
    let refresh_store: Arc<dyn RefreshTokenStore> = Arc::new(FirestoreRefreshTokenStore::new(db));
    let jwt = Arc::new(JwtKeys::from_env());

    let state = AppState {
        store,
        refresh_store,
        jwt,
    };

    let addr = "0.0.0.0:8080";
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind address");
    tracing::info!(%addr, "auth-service listening");

    axum::serve(listener, auth_service::app(state))
        .await
        .expect("server error");
}
