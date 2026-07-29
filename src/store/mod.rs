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
