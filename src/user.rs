use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Firestore document shape for `users/{normalized_email}`.
///
/// `user_id` is a separate opaque identifier (not the email) used as the
/// JWT `sub` claim, so the token never carries PII — per Module 1's
/// "no PII in the JWT" decision. The Firestore doc ID stays the email
/// (Module 3's atomic-uniqueness design); `user_id` is just a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub password_hash: String,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub created_at: DateTime<Utc>,
    /// Raw TOTP secret bytes, generated at `/register` time (Module 11).
    /// Present even before enrollment is confirmed — `mfa_enrolled` is
    /// the field that gates login, not this one's presence.
    pub mfa_secret: Vec<u8>,
    /// False until `/register/confirm` verifies a real code. `/login`
    /// refuses any account with `mfa_enrolled: false` the same way
    /// Module 6 made DPoP mandatory — no bypass path.
    pub mfa_enrolled: bool,
}

/// Data needed to create a user; `created_at` is assigned by the store at
/// write time rather than by the caller. `mfa_enrolled` isn't settable
/// here — it always starts `false`; only the store's
/// `confirm_mfa_enrollment` ever flips it.
#[derive(Clone)]
pub struct NewUser {
    pub user_id: String,
    pub email: String,
    pub password_hash: String,
    pub mfa_secret: Vec<u8>,
}
