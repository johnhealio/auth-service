use std::fmt;

use async_trait::async_trait;

use crate::refresh_token::{NewRefreshToken, RefreshTokenRecord};
use crate::user::{NewUser, User};

pub mod firestore;

#[derive(Debug)]
pub enum StoreError {
    DuplicateEmail,
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::DuplicateEmail => write!(f, "email already registered"),
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
}
