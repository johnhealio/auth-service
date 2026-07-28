use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use ::firestore::FirestoreDb;
use ::firestore::errors::FirestoreError;

use crate::refresh_token::{NewRefreshToken, REFRESH_TOKEN_TTL_DAYS, RefreshTokenRecord};
use crate::store::{DpopReplayStore, RefreshTokenStore, StoreError, UserStore};
use crate::user::{NewUser, User};

const USERS_COLLECTION: &str = "users";
const REFRESH_TOKENS_COLLECTION: &str = "refresh_tokens";
const DPOP_JTI_COLLECTION: &str = "dpop_jti";

pub struct FirestoreUserStore {
    db: FirestoreDb,
}

impl FirestoreUserStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserStore for FirestoreUserStore {
    async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = User {
            user_id: new_user.user_id,
            email: new_user.email,
            password_hash: new_user.password_hash,
            created_at: Utc::now(),
        };

        self.db
            .fluent()
            .insert()
            .into(USERS_COLLECTION)
            .document_id(&user.email)
            .object(&user)
            .execute::<User>()
            .await
            .map_err(|err| match err {
                FirestoreError::DataConflictError(_) => StoreError::DuplicateEmail,
                other => StoreError::Backend(other.to_string()),
            })
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        self.db
            .fluent()
            .select()
            .by_id_in(USERS_COLLECTION)
            .obj::<User>()
            .one(email)
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }
}

/// Separate struct from `FirestoreUserStore` to keep single-responsibility;
/// `FirestoreDb` is cheap to clone (an internal connection handle), so
/// callers share one connection across both stores.
pub struct FirestoreRefreshTokenStore {
    db: FirestoreDb,
}

impl FirestoreRefreshTokenStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RefreshTokenStore for FirestoreRefreshTokenStore {
    async fn create(
        &self,
        new_token: NewRefreshToken,
        token_hash: &str,
    ) -> Result<RefreshTokenRecord, StoreError> {
        let now = Utc::now();
        let record = RefreshTokenRecord {
            user_email: new_token.user_email,
            jkt: new_token.jkt,
            created_at: now,
            expires_at: now + Duration::days(REFRESH_TOKEN_TTL_DAYS),
        };

        self.db
            .fluent()
            .insert()
            .into(REFRESH_TOKENS_COLLECTION)
            .document_id(token_hash)
            .object(&record)
            .execute::<RefreshTokenRecord>()
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }

    async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        self.db
            .fluent()
            .select()
            .by_id_in(REFRESH_TOKENS_COLLECTION)
            .obj::<RefreshTokenRecord>()
            .one(token_hash)
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }
}

/// Firestore document shape for `dpop_jti/{jti}` — the doc ID is the `jti`
/// itself (not hashed: it's a server-mandated-unique client nonce, not a
/// secret). No active cleanup yet, same posture as `RefreshTokenRecord`:
/// `expires_at` is stored but only checked incidentally by the fact that
/// stale jtis are already rejected on `iat` freshness before this is
/// consulted — a Firestore TTL policy on this field is the eventual real
/// fix, not urgent given the ~6-minute TTL keeps this collection tiny.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DpopJtiRecord {
    #[serde(with = "firestore::serialize_as_timestamp")]
    expires_at: DateTime<Utc>,
}

pub struct FirestoreDpopReplayStore {
    db: FirestoreDb,
}

impl FirestoreDpopReplayStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl DpopReplayStore for FirestoreDpopReplayStore {
    async fn insert_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<(), StoreError> {
        let record = DpopJtiRecord { expires_at };

        self.db
            .fluent()
            .insert()
            .into(DPOP_JTI_COLLECTION)
            .document_id(jti)
            .object(&record)
            .execute::<DpopJtiRecord>()
            .await
            .map_err(|err| match err {
                FirestoreError::DataConflictError(_) => StoreError::Replayed,
                other => StoreError::Backend(other.to_string()),
            })?;

        Ok(())
    }
}
