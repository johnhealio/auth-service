use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Sliding per-token TTL — each rotation gets a fresh window this long,
/// checked at redemption time (not yet enforced via a Firestore TTL policy
/// — that's an infra nicety, not required for this module's functional
/// scope).
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 30;

/// Absolute cap on a session's lifetime regardless of how many times it's
/// rotated, applied on top of the sliding TTL above (Module 7). Reuse
/// detection is a *detective* control — it only catches theft when the
/// legitimate holder and an attacker collide on presenting the same stale
/// token. If that never happens (the legitimate client never retries a
/// stolen-and-since-rotated-away token), sliding TTL alone would let a
/// silent theft persist indefinitely; this cap bounds that worst case.
pub const ABSOLUTE_SESSION_CAP_DAYS: i64 = 90;

/// A refresh token's lifecycle within its rotation family. `Active` is the
/// current, usable token. `Rotated` means it was legitimately exchanged for
/// a newer one — presenting it again is the reuse signal. `Revoked` means
/// the whole family was invalidated (either because reuse was detected on
/// this token or a sibling in the same family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenStatus {
    Active,
    Rotated,
    Revoked,
}

/// Firestore document shape for `refresh_tokens/{sha256_hex(token)}`. The
/// doc ID *is* the hash of the token (see `random::hash_token`) —
/// content-addressed, atomic lookup, no plaintext token ever stored.
/// `token_hash` duplicates the doc ID as a real field: family-revocation
/// queries return records by `family_id`, not by ID, and a query result
/// doesn't otherwise carry its own document ID.
///
/// `jkt` (Module 6) is the DPoP key thumbprint bound at issuance —
/// enforced starting Module 7 (a refresh must present a proof for the same
/// key). `family_id` is generated fresh at login and copied unchanged onto
/// every record produced by every subsequent rotation in that chain —
/// effectively a session id, and the unit family revocation acts on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub token_hash: String,
    pub user_email: String,
    pub jkt: String,
    pub family_id: String,
    pub status: RefreshTokenStatus,
    pub replaced_by: Option<String>,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "firestore::serialize_as_timestamp")]
    pub family_created_at: DateTime<Utc>,
}

/// Login-only: always establishes a brand-new family. Rotation is a
/// separate store operation (`RefreshTokenStore::rotate`) since "create a
/// new family" and "continue an existing family with a status transition
/// on the old doc" are different-enough operations to deserve their own
/// method rather than an ambiguous shared constructor.
pub struct NewRefreshToken {
    pub user_email: String,
    pub jkt: String,
}
