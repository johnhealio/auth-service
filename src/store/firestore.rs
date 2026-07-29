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
use crate::store::{
    DpopReplayStore, LoginAttemptState, LoginAttemptStore, RecoveryCodeStore, RefreshTokenStore,
    StoreError, UserStore,
};
use crate::user::{NewUser, User};

const USERS_COLLECTION: &str = "users";
const REFRESH_TOKENS_COLLECTION: &str = "refresh_tokens";
const DPOP_JTI_COLLECTION: &str = "dpop_jti";
const LOGIN_ATTEMPTS_COLLECTION: &str = "login_attempts";
const RECOVERY_CODES_COLLECTION: &str = "recovery_codes";

// OWASP-baseline-style lockout, same framing as Module 3's Argon2
// baseline: lenient enough not to lock out a user hitting a few typos,
// tight enough to blunt sustained per-account guessing that the IP-based
// rate limiter alone doesn't cover (a distributed attacker spreads
// guesses across many source IPs against one target account).
pub const LOGIN_FAILURE_THRESHOLD: u32 = 10;
pub const LOGIN_ATTEMPT_WINDOW_MINUTES: i64 = 15;
pub const LOGIN_LOCKOUT_MINUTES: i64 = 15;

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
            mfa_secret: new_user.mfa_secret,
            mfa_enrolled: false,
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

    async fn confirm_mfa_enrollment(
        &self,
        email: &str,
        recovery_code_hashes: Vec<String>,
    ) -> Result<User, StoreError> {
        let email = email.to_string();

        let outcome = self
            .db
            .run_transaction(move |tx_db, tx| {
                let email = email.clone();
                let recovery_code_hashes = recovery_code_hashes.clone();
                Box::pin(async move {
                    let current = tx_db
                        .fluent()
                        .select()
                        .by_id_in(USERS_COLLECTION)
                        .obj::<User>()
                        .one(&email)
                        .await?;

                    let Some(mut user) = current else {
                        return Ok(ConfirmMfaOutcome::NotFound);
                    };
                    if user.mfa_enrolled {
                        return Ok(ConfirmMfaOutcome::AlreadyEnrolled);
                    }
                    user.mfa_enrolled = true;

                    tx_db
                        .fluent()
                        .update()
                        .in_col(USERS_COLLECTION)
                        .precondition(FirestoreWritePrecondition::Exists(true))
                        .document_id(&email)
                        .object(&user)
                        .add_to_transaction(tx)?;

                    for hash in &recovery_code_hashes {
                        let record = RecoveryCodeRecord {
                            user_email: email.clone(),
                            consumed: false,
                        };
                        tx_db
                            .fluent()
                            .update()
                            .in_col(RECOVERY_CODES_COLLECTION)
                            .precondition(FirestoreWritePrecondition::Exists(false))
                            .document_id(hash)
                            .object(&record)
                            .add_to_transaction(tx)?;
                    }

                    Ok(ConfirmMfaOutcome::Confirmed(user))
                })
            })
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))?;

        match outcome {
            ConfirmMfaOutcome::Confirmed(user) => Ok(user),
            ConfirmMfaOutcome::AlreadyEnrolled => Err(StoreError::MfaAlreadyEnrolled),
            ConfirmMfaOutcome::NotFound => Err(StoreError::NotFound),
        }
    }
}

/// Outcome of a single `confirm_mfa_enrollment` transaction attempt.
enum ConfirmMfaOutcome {
    Confirmed(User),
    AlreadyEnrolled,
    NotFound,
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

/// Firestore document shape for `login_attempts/{normalized_email}` — the
/// doc ID is the *submitted* normalized email, whether or not a `users`
/// document exists for it (see Module 10 notes on `LoginAttemptStore`:
/// this must stay symmetric between real and fake accounts, or lockout
/// state itself becomes an account-enumeration side channel). No active
/// TTL cleanup yet, same accepted posture as `DpopJtiRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginAttemptRecord {
    failure_count: u32,
    #[serde(with = "firestore::serialize_as_timestamp")]
    window_started_at: DateTime<Utc>,
    // `#[serde(default)]` matters here: the firestore crate's document
    // serializer omits `None`-valued fields entirely rather than writing
    // an explicit null, so a record created while `locked_until` is
    // `None` has no such field on read-back at all — without `default`,
    // that's a deserialization error, not a `None`.
    #[serde(default, with = "firestore::serialize_as_optional_timestamp")]
    locked_until: Option<DateTime<Utc>>,
}

fn login_attempt_state(record: &LoginAttemptRecord, now: DateTime<Utc>) -> LoginAttemptState {
    match record.locked_until {
        Some(until) if until > now => LoginAttemptState::Locked { retry_after: until },
        _ => LoginAttemptState::Allowed,
    }
}

pub struct FirestoreLoginAttemptStore {
    db: FirestoreDb,
}

impl FirestoreLoginAttemptStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl LoginAttemptStore for FirestoreLoginAttemptStore {
    async fn check(&self, normalized_email: &str) -> Result<LoginAttemptState, StoreError> {
        let record = self
            .db
            .fluent()
            .select()
            .by_id_in(LOGIN_ATTEMPTS_COLLECTION)
            .obj::<LoginAttemptRecord>()
            .one(normalized_email)
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))?;

        Ok(record.map_or(LoginAttemptState::Allowed, |r| {
            login_attempt_state(&r, Utc::now())
        }))
    }

    async fn record_failure(
        &self,
        normalized_email: &str,
    ) -> Result<LoginAttemptState, StoreError> {
        let key = normalized_email.to_string();

        let record = self
            .db
            .run_transaction(move |tx_db, tx| {
                let key = key.clone();
                Box::pin(async move {
                    let now = Utc::now();
                    let current = tx_db
                        .fluent()
                        .select()
                        .by_id_in(LOGIN_ATTEMPTS_COLLECTION)
                        .obj::<LoginAttemptRecord>()
                        .one(&key)
                        .await?;

                    let (next, precondition) = match current {
                        None => (
                            LoginAttemptRecord {
                                failure_count: 1,
                                window_started_at: now,
                                locked_until: None,
                            },
                            FirestoreWritePrecondition::Exists(false),
                        ),
                        Some(existing) => {
                            let still_locked =
                                existing.locked_until.is_some_and(|until| until > now);
                            let window_expired = now - existing.window_started_at
                                > Duration::minutes(LOGIN_ATTEMPT_WINDOW_MINUTES);

                            let next = if still_locked {
                                // Don't extend the lockout on every
                                // additional attempt during it — an
                                // attacker shouldn't be able to keep a
                                // real user locked out indefinitely just
                                // by continuing to guess.
                                existing
                            } else if window_expired {
                                LoginAttemptRecord {
                                    failure_count: 1,
                                    window_started_at: now,
                                    locked_until: None,
                                }
                            } else {
                                let failure_count = existing.failure_count + 1;
                                let locked_until = (failure_count >= LOGIN_FAILURE_THRESHOLD)
                                    .then(|| now + Duration::minutes(LOGIN_LOCKOUT_MINUTES));
                                LoginAttemptRecord {
                                    failure_count,
                                    window_started_at: existing.window_started_at,
                                    locked_until,
                                }
                            };
                            (next, FirestoreWritePrecondition::Exists(true))
                        }
                    };

                    tx_db
                        .fluent()
                        .update()
                        .in_col(LOGIN_ATTEMPTS_COLLECTION)
                        .precondition(precondition)
                        .document_id(&key)
                        .object(&next)
                        .add_to_transaction(tx)?;

                    Ok(next)
                })
            })
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))?;

        Ok(login_attempt_state(&record, Utc::now()))
    }

    async fn reset(&self, normalized_email: &str) -> Result<(), StoreError> {
        // Delete rather than update-to-zero: "no doc" is also correct
        // for an email that's never failed a login. Idempotent — no
        // error if no doc exists (mirrors a clean-history account).
        self.db
            .fluent()
            .delete()
            .from(LOGIN_ATTEMPTS_COLLECTION)
            .document_id(normalized_email)
            .execute()
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }
}

/// Firestore document shape for `recovery_codes/{sha256_hex(code)}` — doc
/// ID *is* the hash (mirrors `RefreshTokenRecord`'s "hash as doc ID"
/// pattern exactly). One document per code, not one doc per user with an
/// array, so redemption is a single-document transactional read-check-write
/// with no read-modify-write race over a shared array field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryCodeRecord {
    user_email: String,
    consumed: bool,
}

pub struct FirestoreRecoveryCodeStore {
    db: FirestoreDb,
}

impl FirestoreRecoveryCodeStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RecoveryCodeStore for FirestoreRecoveryCodeStore {
    async fn redeem(&self, user_email: &str, code_hash: &str) -> Result<bool, StoreError> {
        let user_email = user_email.to_string();
        let code_hash = code_hash.to_string();

        self.db
            .run_transaction(move |tx_db, tx| {
                let user_email = user_email.clone();
                let code_hash = code_hash.clone();
                Box::pin(async move {
                    let current = tx_db
                        .fluent()
                        .select()
                        .by_id_in(RECOVERY_CODES_COLLECTION)
                        .obj::<RecoveryCodeRecord>()
                        .one(&code_hash)
                        .await?;

                    let Some(record) = current else {
                        return Ok(false);
                    };
                    if record.consumed || record.user_email != user_email {
                        return Ok(false);
                    }

                    let consumed_record = RecoveryCodeRecord {
                        consumed: true,
                        ..record
                    };

                    tx_db
                        .fluent()
                        .update()
                        .in_col(RECOVERY_CODES_COLLECTION)
                        .precondition(FirestoreWritePrecondition::Exists(true))
                        .document_id(&code_hash)
                        .object(&consumed_record)
                        .add_to_transaction(tx)?;

                    Ok(true)
                })
            })
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }
}
