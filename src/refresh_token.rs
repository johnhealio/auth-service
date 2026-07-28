use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Refresh tokens live 30 days from issuance, checked at redemption time
/// (not yet enforced via a Firestore TTL policy — that's an infra nicety,
/// not required for Module 4's functional scope).
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 30;

/// Firestore document shape for `refresh_tokens/{sha256_hex(token)}`. The
/// doc ID *is* the hash of the token (see `random::hash_token`) —
/// content-addressed, atomic lookup, no plaintext token ever stored.
///
/// `jkt` (Module 6) is the DPoP key thumbprint bound at issuance — stored
/// now but not yet enforced anywhere; Module 7's rotation/redemption logic
/// is what actually checks a refresh request's DPoP proof against it.
/// Deliberately otherwise minimal: no `used`/`replaced_by`/`family_id`
/// fields yet — those belong to Module 7, not added speculatively here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub user_email: String,
    pub jkt: String,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub expires_at: DateTime<Utc>,
}

pub struct NewRefreshToken {
    pub user_email: String,
    pub jkt: String,
}
