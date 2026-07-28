// Shared test-utility module — not every consuming test binary uses every
// item here (e.g. sign_without_jwk isn't currently exercised by any test
// but is kept available for testing "no embedded key" rejection).
#![allow(dead_code)]

use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use auth_service::random::generate_opaque_token;

/// A real P-256 keypair for constructing spec-shaped DPoP proofs in tests
/// — not a mock. The server only ever verifies proofs, so key generation
/// lives entirely in test code.
pub struct DpopKeypair {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

impl DpopKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let der = signing_key
            .to_pkcs8_der()
            .expect("pkcs8-encode test signing key");
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)
            .expect("derive jwk from test encoding key");

        Self { encoding_key, jwk }
    }

    pub fn thumbprint(&self) -> String {
        self.jwk
            .thumbprint(ThumbprintHash::SHA256)
            .expect("compute test jwk thumbprint")
    }
}

#[derive(Serialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

/// Method-chaining builder so each negative test can override exactly one
/// field from an otherwise-valid baseline proof.
pub struct DpopProofBuilder {
    htm: String,
    htu: String,
    iat_offset: i64,
    jti: String,
    ath: Option<String>,
}

impl DpopProofBuilder {
    pub fn new(htm: &str, htu: &str) -> Self {
        Self {
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat_offset: 0,
            jti: generate_opaque_token(16),
            ath: None,
        }
    }

    pub fn htm(mut self, htm: &str) -> Self {
        self.htm = htm.to_string();
        self
    }

    pub fn htu(mut self, htu: &str) -> Self {
        self.htu = htu.to_string();
        self
    }

    pub fn iat_offset(mut self, offset_secs: i64) -> Self {
        self.iat_offset = offset_secs;
        self
    }

    pub fn jti(mut self, jti: &str) -> Self {
        self.jti = jti.to_string();
        self
    }

    pub fn ath_for_token(mut self, token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        self.ath = Some(URL_SAFE_NO_PAD.encode(digest));
        self
    }

    pub fn ath_raw(mut self, ath: &str) -> Self {
        self.ath = Some(ath.to_string());
        self
    }

    pub fn sign(self, keypair: &DpopKeypair) -> String {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = DpopClaims {
            htm: self.htm,
            htu: self.htu,
            iat: now + self.iat_offset,
            jti: self.jti,
            ath: self.ath,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(keypair.jwk.clone());

        encode(&header, &claims, &keypair.encoding_key).expect("sign test dpop proof")
    }

    /// Signs with a header lacking a `jwk` — for testing that a proof
    /// without an embedded key is rejected.
    pub fn sign_without_jwk(self, keypair: &DpopKeypair) -> String {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = DpopClaims {
            htm: self.htm,
            htu: self.htu,
            iat: now + self.iat_offset,
            jti: self.jti,
            ath: self.ath,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());

        encode(&header, &claims, &keypair.encoding_key).expect("sign test dpop proof")
    }
}
