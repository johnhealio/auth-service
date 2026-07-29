use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use auth_service::AppState;
use auth_service::dpop::PublicBaseUrl;
use auth_service::random::{generate_opaque_token, hash_token};
use auth_service::refresh_token::{RefreshTokenRecord, RefreshTokenStatus};
use auth_service::store::firestore::{
    FirestoreDpopReplayStore, FirestoreLoginAttemptStore, FirestoreRefreshTokenStore,
    FirestoreUserStore,
};
use auth_service::store::{DpopReplayStore, LoginAttemptStore, RefreshTokenStore, UserStore};
use auth_service::token::JwtKeys;
use auth_service::user::{NewUser, User};
use chrono::{Duration as ChronoDuration, Utc};
use firestore::{FirestoreDb, FirestoreDbOptions};

pub mod dpop;

// Fixed test-only secret, independent of whatever JWT_SIGNING_SECRET
// happens to be exported in the shell — keeps token verification in tests
// deterministic regardless of dev-server env state.
const TEST_JWT_SIGNING_SECRET: &[u8] = b"test-only signing secret, at least 32 bytes long!!";

/// Fixed test-only base URL, independent of PUBLIC_BASE_URL in the shell.
pub const TEST_PUBLIC_BASE_URL: &str = "https://auth.test.example";

const REFRESH_TOKENS_COLLECTION: &str = "refresh_tokens";

/// Connects to the real dev Firestore database. Requires
/// FIRESTORE_PROJECT_ID (and optionally FIRESTORE_DATABASE_ID) to be set —
/// see terraform/dev-bootstrap for provisioning.
async fn connect_firestore() -> FirestoreDb {
    let project_id = std::env::var("FIRESTORE_PROJECT_ID")
        .expect("FIRESTORE_PROJECT_ID must be set to run integration tests");
    let database_id = std::env::var("FIRESTORE_DATABASE_ID")
        .unwrap_or_else(|_| firestore::FIREBASE_DEFAULT_DATABASE_ID.to_string());

    let options = FirestoreDbOptions::new(project_id).with_database_id(database_id);
    FirestoreDb::with_options(options)
        .await
        .expect("failed to connect to Firestore")
}

/// Builds a full AppState backed by the real dev Firestore database.
pub async fn test_app_state() -> AppState {
    let db = connect_firestore().await;

    let store: Arc<dyn UserStore> = Arc::new(FirestoreUserStore::new(db.clone()));
    let refresh_store: Arc<dyn RefreshTokenStore> =
        Arc::new(FirestoreRefreshTokenStore::new(db.clone()));
    let dpop_replay: Arc<dyn DpopReplayStore> = Arc::new(FirestoreDpopReplayStore::new(db.clone()));
    let login_attempts: Arc<dyn LoginAttemptStore> = Arc::new(FirestoreLoginAttemptStore::new(db));
    let jwt = Arc::new(JwtKeys::new(
        TEST_JWT_SIGNING_SECRET,
        Duration::from_secs(600),
    ));
    let public_base_url = PublicBaseUrl::parse(TEST_PUBLIC_BASE_URL).expect("valid test base url");

    AppState {
        store,
        refresh_store,
        dpop_replay,
        login_attempts,
        jwt,
        public_base_url,
    }
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

/// Creates a user directly via the store (bypassing /register's breach
/// check + validation) for deterministic, fast test setup — same spirit as
/// register.rs's own tests calling `find_by_email` directly.
#[allow(dead_code)]
pub async fn create_test_user(state: &AppState, email: &str, password: &str) -> User {
    let password_hash = auth_service::password::hash_password(password).unwrap();
    state
        .store
        .create_user(NewUser {
            user_id: auth_service::random::generate_opaque_token(16),
            email: email.to_string(),
            password_hash,
        })
        .await
        .unwrap()
}

/// Inserts a refresh token record directly via Firestore (bypassing
/// `RefreshTokenStore::create`, which always sets a fresh `expires_at`) so
/// tests can exercise the "already expired" path without waiting 30 days.
/// Returns the raw token string to present to `/refresh`.
#[allow(dead_code)]
pub async fn insert_backdated_refresh_token(user_email: &str, jkt: &str) -> String {
    let db = connect_firestore().await;

    let token = generate_opaque_token(32);
    let token_hash = hash_token(&token);
    let created_at = Utc::now() - ChronoDuration::days(31);
    let record = RefreshTokenRecord {
        token_hash: token_hash.clone(),
        user_email: user_email.to_string(),
        jkt: jkt.to_string(),
        family_id: generate_opaque_token(16),
        status: RefreshTokenStatus::Active,
        replaced_by: None,
        created_at,
        expires_at: created_at + ChronoDuration::days(30), // already in the past
        family_created_at: created_at,
    };

    db.fluent()
        .insert()
        .into(REFRESH_TOKENS_COLLECTION)
        .document_id(&token_hash)
        .object(&record)
        .execute::<RefreshTokenRecord>()
        .await
        .expect("insert backdated refresh token");

    token
}
