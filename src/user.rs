use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Firestore document shape for `users/{normalized_email}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub password_hash: String,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Data needed to create a user; `created_at` is assigned by the store at
/// write time rather than by the caller.
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
}
