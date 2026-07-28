use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::random::generate_opaque_token;

// No revocation path exists for access tokens until DPoP (Module 6, raises
// the bar for *using* a stolen token) and refresh rotation (Module 7).
// TTL is the only current lever against leaked-token exposure — leaning
// short. Fixed security policy, not deployment config, per the Module 3
// Argon2-params precedent.
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);

/// RFC 7800/9449 §6.1 confirmation claim — nested per spec, not flattened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    pub jkt: String,
}

/// Minimal claims per Module 1's decision: identity + expiry only, no
/// PII/permissions. `sub` is the opaque `user_id`, not the email. `cnf.jkt`
/// (Module 6) is non-optional — DPoP is mandatory, so every access token is
/// key-bound from the moment it's issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub cnf: ConfirmationClaim,
}

/// Deliberately no `Debug`/`Clone` derive — holds signing key material.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
}

impl JwtKeys {
    pub fn new(secret: &[u8], ttl: Duration) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            ttl,
        }
    }

    /// Mirrors the FIRESTORE_PROJECT_ID convention already used in
    /// main.rs: a required env var, never committed or hardcoded.
    /// Generate one with `openssl rand -hex 32`.
    pub fn from_env() -> Self {
        let secret = std::env::var("JWT_SIGNING_SECRET").expect("JWT_SIGNING_SECRET must be set");
        assert!(
            secret.len() >= 32,
            "JWT_SIGNING_SECRET should be at least 32 bytes"
        );
        Self::new(secret.as_bytes(), ACCESS_TOKEN_TTL)
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// `jkt` is the DPoP key thumbprint (RFC 7638) computed from the
    /// client's proof at issuance — see `dpop::validate_dpop_proof`.
    pub fn issue_access_token(
        &self,
        user_id: &str,
        jkt: &str,
    ) -> jsonwebtoken::errors::Result<(String, JwtClaims)> {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = JwtClaims {
            sub: user_id.to_string(),
            iat: now,
            exp: now + self.ttl.as_secs() as i64,
            jti: generate_opaque_token(16),
            cnf: ConfirmationClaim {
                jkt: jkt.to_string(),
            },
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)?;
        Ok((token, claims))
    }

    pub fn verify_access_token(&self, token: &str) -> jsonwebtoken::errors::Result<JwtClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["exp", "sub"]);
        let data = decode::<JwtClaims>(token, &self.decoding, &validation)?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> JwtKeys {
        JwtKeys::new(
            b"a test signing secret at least 32 bytes long!!",
            ACCESS_TOKEN_TTL,
        )
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let keys = test_keys();
        let (token, issued_claims) = keys.issue_access_token("user-123", "test-jkt").unwrap();
        let verified_claims = keys.verify_access_token(&token).unwrap();

        assert_eq!(verified_claims.sub, "user-123");
        assert_eq!(verified_claims.jti, issued_claims.jti);
        assert_eq!(verified_claims.exp - verified_claims.iat, 600);
        assert_eq!(verified_claims.cnf.jkt, "test-jkt");
    }

    #[test]
    fn tampered_token_fails_verification() {
        let keys = test_keys();
        let (token, _) = keys.issue_access_token("user-123", "test-jkt").unwrap();
        let mut tampered = token.clone();
        tampered.push('x');

        assert!(keys.verify_access_token(&tampered).is_err());
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let keys_a = test_keys();
        let keys_b = JwtKeys::new(
            b"a different signing secret, also 32+ bytes!",
            ACCESS_TOKEN_TTL,
        );
        let (token, _) = keys_a.issue_access_token("user-123", "test-jkt").unwrap();

        assert!(keys_b.verify_access_token(&token).is_err());
    }

    #[test]
    fn two_tokens_for_same_user_have_different_jti() {
        let keys = test_keys();
        let (_, claims_a) = keys.issue_access_token("user-123", "test-jkt").unwrap();
        let (_, claims_b) = keys.issue_access_token("user-123", "test-jkt").unwrap();

        assert_ne!(claims_a.jti, claims_b.jti);
    }
}
