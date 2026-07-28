use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use ::firestore::FirestoreDb;
use ::firestore::FirestoreWritePrecondition;
use ::firestore::errors::FirestoreError;

use crate::random::generate_opaque_token;
use crate::refresh_token::{
    ABSOLUTE_SESSION_CAP_DAYS, NewRefreshToken, REFRESH_TOKEN_TTL_DAYS, RefreshTokenRecord,
    RefreshTokenStatus,
};
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

/// Outcome of a single rotation-transaction attempt. `NotActive` means the
/// old record existed but wasn't `Active` by the time the transaction read
/// it (either it was already rotated/revoked before we started, or a
/// concurrent rotation won the race) — the caller (`rotate`) turns this
/// into family revocation + `StoreError::Reused`, outside the transaction.
enum RotateAttempt {
    Rotated(RefreshTokenRecord),
    NotActive,
}

fn capped_expiry(now: DateTime<Utc>, family_created_at: DateTime<Utc>) -> DateTime<Utc> {
    let sliding = now + Duration::days(REFRESH_TOKEN_TTL_DAYS);
    let absolute_cap = family_created_at + Duration::days(ABSOLUTE_SESSION_CAP_DAYS);
    sliding.min(absolute_cap)
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
            token_hash: token_hash.to_string(),
            user_email: new_token.user_email,
            jkt: new_token.jkt,
            family_id: generate_opaque_token(16),
            status: RefreshTokenStatus::Active,
            replaced_by: None,
            created_at: now,
            expires_at: capped_expiry(now, now),
            family_created_at: now,
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

    async fn rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        new_jkt: &str,
    ) -> Result<RefreshTokenRecord, StoreError> {
        // Non-transactional pre-check: fast-path NotFound/Expired/Reused
        // without paying for a transaction when nothing needs to race.
        let old = self
            .find_by_hash(old_token_hash)
            .await?
            .ok_or(StoreError::NotFound)?;

        if old.status != RefreshTokenStatus::Active {
            self.revoke_family(&old.family_id).await?;
            return Err(StoreError::Reused);
        }
        if old.expires_at < Utc::now() {
            return Err(StoreError::Expired);
        }

        let family_id = old.family_id.clone();
        let family_id_for_closure = family_id.clone();
        let family_created_at = old.family_created_at;
        let user_email = old.user_email.clone();
        let old_hash = old_token_hash.to_string();
        let new_hash = new_token_hash.to_string();
        let new_jkt = new_jkt.to_string();

        let outcome = self
            .db
            .run_transaction(move |tx_db, tx| {
                let family_id = family_id_for_closure.clone();
                let user_email = user_email.clone();
                let old_hash = old_hash.clone();
                let new_hash = new_hash.clone();
                let new_jkt = new_jkt.clone();
                Box::pin(async move {
                    let current = tx_db
                        .fluent()
                        .select()
                        .by_id_in(REFRESH_TOKENS_COLLECTION)
                        .obj::<RefreshTokenRecord>()
                        .one(&old_hash)
                        .await?;

                    let Some(current) = current else {
                        return Ok(RotateAttempt::NotActive);
                    };
                    if current.status != RefreshTokenStatus::Active {
                        return Ok(RotateAttempt::NotActive);
                    }

                    let mut rotated_old = current;
                    rotated_old.status = RefreshTokenStatus::Rotated;
                    rotated_old.replaced_by = Some(new_hash.clone());

                    let now = Utc::now();
                    let new_record = RefreshTokenRecord {
                        token_hash: new_hash.clone(),
                        user_email,
                        jkt: new_jkt,
                        family_id,
                        status: RefreshTokenStatus::Active,
                        replaced_by: None,
                        created_at: now,
                        expires_at: capped_expiry(now, family_created_at),
                        family_created_at,
                    };

                    tx_db
                        .fluent()
                        .update()
                        .in_col(REFRESH_TOKENS_COLLECTION)
                        .precondition(FirestoreWritePrecondition::Exists(true))
                        .document_id(&old_hash)
                        .object(&rotated_old)
                        .add_to_transaction(tx)?;

                    tx_db
                        .fluent()
                        .update()
                        .in_col(REFRESH_TOKENS_COLLECTION)
                        .precondition(FirestoreWritePrecondition::Exists(false))
                        .document_id(&new_hash)
                        .object(&new_record)
                        .add_to_transaction(tx)?;

                    Ok(RotateAttempt::Rotated(new_record))
                })
            })
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))?;

        match outcome {
            RotateAttempt::Rotated(record) => Ok(record),
            RotateAttempt::NotActive => {
                self.revoke_family(&family_id).await?;
                Err(StoreError::Reused)
            }
        }
    }

    async fn revoke_family(&self, family_id: &str) -> Result<(), StoreError> {
        let family_id = family_id.to_string();

        self.db
            .run_transaction(move |tx_db, tx| {
                let family_id = family_id.clone();
                Box::pin(async move {
                    let members = tx_db
                        .fluent()
                        .select()
                        .from(REFRESH_TOKENS_COLLECTION)
                        .filter(|q| q.field("family_id").eq(family_id.clone()))
                        .obj::<RefreshTokenRecord>()
                        .query()
                        .await?;

                    for member in members {
                        if member.status == RefreshTokenStatus::Revoked {
                            continue;
                        }
                        let mut revoked = member.clone();
                        revoked.status = RefreshTokenStatus::Revoked;

                        tx_db
                            .fluent()
                            .update()
                            .in_col(REFRESH_TOKENS_COLLECTION)
                            .precondition(FirestoreWritePrecondition::Exists(true))
                            .document_id(&member.token_hash)
                            .object(&revoked)
                            .add_to_transaction(tx)?;
                    }

                    Ok(())
                })
            })
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
