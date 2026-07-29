use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::refresh_token::{NewRefreshToken, RefreshTokenRecord};
use crate::user::{NewUser, User};

pub mod firestore;

#[derive(Debug)]
pub enum StoreError {
    DuplicateEmail,
    /// A DPoP proof `jti` that's already been seen — the proof is a replay.
    Replayed,
    /// No record exists for the presented identifier (e.g. an unknown
    /// refresh token).
    NotFound,
    /// The record exists but its TTL has passed.
    Expired,
    /// A refresh token that was already rotated away got presented again —
    /// the reuse signal. The whole token family has been revoked as a
    /// side effect of returning this variant.
    Reused,
    /// A `/register/confirm` attempt for an account whose `mfa_enrolled`
    /// was already `true` — a replayed/duplicate confirm, not a normal
    /// error path. Named specifically (not folded into `DuplicateEmail`,
    /// which is about the *email*, not the *enrollment state*) to match
    /// this project's existing specific-variant style (`Replayed`, `Reused`).
    MfaAlreadyEnrolled,
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::DuplicateEmail => write!(f, "email already registered"),
            StoreError::Replayed => write!(f, "DPoP proof jti already used"),
            StoreError::NotFound => write!(f, "record not found"),
            StoreError::Expired => write!(f, "record expired"),
            StoreError::Reused => write!(f, "refresh token reused; family revoked"),
            StoreError::MfaAlreadyEnrolled => write!(f, "MFA already enrolled for this account"),
            StoreError::Backend(message) => write!(f, "backend error: {message}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError>;

    /// Looks up a user by normalized email. Not used by registration itself,
    /// but needed to verify what got stored (this test suite) and by login
    /// (Module 4) to check a submitted password against the stored hash.
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, StoreError>;

    /// Atomically flips `mfa_enrolled` to `true` and creates one
    /// recovery-code record per hash in `recovery_code_hashes`, in a
    /// single transaction — a confirmed account with no recovery codes
    /// (or vice versa) would be a partially-migrated, unrecoverable
    /// state. `recovery_code_hashes` are pre-hashed (SHA-256,
    /// `random::hash_token`) by the caller; only hashes are ever
    /// persisted. Returns `StoreError::NotFound` if no such account
    /// exists, or `StoreError::MfaAlreadyEnrolled` if it's already
    /// confirmed (a replayed/duplicate confirm attempt).
    async fn confirm_mfa_enrollment(
        &self,
        email: &str,
        recovery_code_hashes: Vec<String>,
    ) -> Result<User, StoreError>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn create(
        &self,
        new_token: NewRefreshToken,
        token_hash: &str,
    ) -> Result<RefreshTokenRecord, StoreError>;

    /// Looks up a refresh-token record by the SHA-256 hash of the
    /// presented token (never the plaintext token itself).
    async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, StoreError>;

    /// Atomically exchanges `old_token_hash` for a new `Active` record
    /// continuing the same family, marking the old one `Rotated`. If
    /// `old_token_hash` isn't found: `StoreError::NotFound`. If found but
    /// not `Active` (already rotated or revoked) — reuse — the whole
    /// family is revoked as a side effect and `StoreError::Reused` is
    /// returned. If found, `Active`, but past `expires_at`:
    /// `StoreError::Expired` (not reuse — no revocation).
    async fn rotate(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        new_jkt: &str,
    ) -> Result<RefreshTokenRecord, StoreError>;

    /// Marks every non-`Revoked` record sharing `family_id` as `Revoked`.
    async fn revoke_family(&self, family_id: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait DpopReplayStore: Send + Sync {
    /// Atomically records a DPoP proof's `jti` as seen. Returns
    /// `StoreError::Replayed` if this `jti` was already recorded — an
    /// insert-if-absent check, not a find-then-insert, to avoid a TOCTOU
    /// race under concurrent requests.
    async fn insert_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<(), StoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginAttemptState {
    Allowed,
    Locked { retry_after: DateTime<Utc> },
}

#[async_trait]
pub trait LoginAttemptStore: Send + Sync {
    /// Read-only lockout check, called before credential verification.
    async fn check(&self, normalized_email: &str) -> Result<LoginAttemptState, StoreError>;

    /// Records a failed login attempt for `normalized_email`, whatever
    /// was submitted — regardless of whether a `users` document exists
    /// for it. Must stay symmetric with `login::DUMMY_HASH`'s "same
    /// cost/same code path either way" posture, or lockout state itself
    /// becomes an account-enumeration side channel. Returns the
    /// resulting lockout state.
    async fn record_failure(&self, normalized_email: &str)
    -> Result<LoginAttemptState, StoreError>;

    /// Clears accumulated failure history after a successful login, so
    /// occasional typos don't eventually lock out a legitimate user.
    async fn reset(&self, normalized_email: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait RecoveryCodeStore: Send + Sync {
    /// Atomically checks whether `code_hash` is an *unconsumed* recovery
    /// code belonging to `user_email` and, if so, marks it consumed in
    /// the same transaction — concurrent double-spend of one code (e.g.
    /// two simultaneous login attempts racing) must not both succeed.
    /// `Ok(true)` = valid and now consumed; `Ok(false)` = no such
    /// unconsumed code for this user — wrong code, already used, or
    /// belongs to someone else, deliberately not distinguished, same
    /// collapse-point spirit as `login::DUMMY_HASH`.
    async fn redeem(&self, user_email: &str, code_hash: &str) -> Result<bool, StoreError>;
}
