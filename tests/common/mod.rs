use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use auth_service::store::UserStore;
use auth_service::store::firestore::FirestoreUserStore;
use firestore::{FirestoreDb, FirestoreDbOptions};

/// Builds a store backed by the real dev Firestore database. Requires
/// FIRESTORE_PROJECT_ID (and optionally FIRESTORE_DATABASE_ID) to be set —
/// see terraform/dev-bootstrap for provisioning.
pub async fn test_store() -> Arc<dyn UserStore> {
    let project_id = std::env::var("FIRESTORE_PROJECT_ID")
        .expect("FIRESTORE_PROJECT_ID must be set to run integration tests");
    let database_id = std::env::var("FIRESTORE_DATABASE_ID")
        .unwrap_or_else(|_| firestore::FIREBASE_DEFAULT_DATABASE_ID.to_string());

    let options = FirestoreDbOptions::new(project_id).with_database_id(database_id);
    let db = FirestoreDb::with_options(options)
        .await
        .expect("failed to connect to Firestore");

    Arc::new(FirestoreUserStore::new(db))
}

/// A unique email per call so concurrent/repeated test runs against the
/// live dev database don't collide on document IDs.
///
/// Not every test binary that includes this shared module uses this helper
/// (e.g. health.rs doesn't), hence `allow(dead_code)`.
#[allow(dead_code)]
pub fn unique_email(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{nanos}-{n}@example.com")
}
