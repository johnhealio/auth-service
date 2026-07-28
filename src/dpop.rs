use std::collections::HashSet;

use axum::http::Method;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::store::{DpopReplayStore, StoreError};

/// How long a proof remains acceptable after its `iat`. Bounds the replay
/// cache's required retention (`window + skew`) and how long a captured
/// proof stays dangerous if leaked before use.
pub const REPLAY_WINDOW_SECS: i64 = 300;
/// Tolerance for client clock drift — the conventional OAuth/OIDC default,
/// matching `jsonwebtoken`'s own `Validation::leeway`.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// The DPoP proof's own signature is restricted to ES256 — the RFC's cited
/// example algorithm, most interoperable for spec-compliance testing later,
/// and keeps verification to one `Validation` config with no
/// algorithm-confusion surface to reason about.
const DPOP_ALGORITHM: Algorithm = Algorithm::ES256;
const DPOP_TYP: &str = "dpop+jwt";

/// The server's own canonical base URL, used to validate a proof's `htu`
/// claim. Not derived from request headers — this codebase has no
/// forwarded-header trust logic, and Cloud Run's TLS-terminated-at-the-
/// front-end setup makes a request's own view of its scheme unreliable.
#[derive(Clone)]
pub struct PublicBaseUrl(url::Url);

impl PublicBaseUrl {
    pub fn from_env() -> Self {
        let raw = std::env::var("PUBLIC_BASE_URL").expect("PUBLIC_BASE_URL must be set");
        Self::parse(&raw).expect("PUBLIC_BASE_URL must be a valid URL")
    }

    pub fn parse(raw: &str) -> Result<Self, url::ParseError> {
        Ok(Self(url::Url::parse(raw)?))
    }

    /// Compares scheme/host/port (default-port-normalized) and exact path.
    /// RFC 9449 §4.3 only calls out scheme/host case-insensitivity and
    /// default-port omission as expected leniency — no trailing-slash
    /// leniency is added speculatively.
    fn matches_htu(&self, claimed_htu: &str, path: &str) -> bool {
        let Ok(presented) = url::Url::parse(claimed_htu) else {
            return false;
        };
        let mut expected = self.0.clone();
        expected.set_path(path);

        presented.scheme() == expected.scheme()
            && presented.host_str() == expected.host_str()
            && presented.port_or_known_default() == expected.port_or_known_default()
            && presented.path() == expected.path()
    }
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
}

/// What a successfully validated proof yields: the thumbprint of its
/// embedded key (used both to bind `cnf.jkt` at issuance and to check it
/// on protected routes) and the `jti` it was validated under.
pub struct DpopProof {
    pub jkt: String,
    pub jti: String,
}

#[derive(Debug)]
pub enum DpopError {
    Missing,
    Malformed,
    WrongAlgorithm,
    WrongType,
    MethodMismatch,
    UriMismatch,
    Stale,
    FutureIat,
    AthMismatch,
    KeyMismatch,
    Replayed,
    Backend(String),
}

impl DpopError {
    /// Caller-facing message. Status code is chosen by each call site
    /// (e.g. 400 at login vs. 401 on protected routes), so it isn't baked
    /// in here.
    pub fn message(&self) -> &'static str {
        match self {
            DpopError::Missing => "a DPoP proof is required",
            DpopError::Malformed => "the DPoP proof is malformed",
            DpopError::WrongAlgorithm => "unsupported DPoP proof algorithm",
            DpopError::WrongType => "DPoP proof has the wrong typ",
            DpopError::MethodMismatch => "DPoP proof htm does not match the request",
            DpopError::UriMismatch => "DPoP proof htu does not match the request",
            DpopError::Stale => "DPoP proof is too old",
            DpopError::FutureIat => "DPoP proof iat is too far in the future",
            DpopError::AthMismatch => "DPoP proof does not match the presented access token",
            DpopError::KeyMismatch => "DPoP proof key does not match the token binding",
            DpopError::Replayed => "DPoP proof has already been used",
            DpopError::Backend(_) => "failed to process DPoP proof",
        }
    }
}

/// Validates a DPoP proof JWT against the current request. `bearer_token`
/// is `None` at login (no access token exists yet to bind `ath` against)
/// and `Some` on protected routes (where `ath` is mandatory per RFC 9449).
///
/// Does NOT check the proof's key thumbprint against any `cnf.jkt` — that
/// binding comparison is the caller's job (see `auth::DpopBoundUser`),
/// since this function alone can't know what token, if any, the proof is
/// meant to be bound to.
pub async fn validate_dpop_proof(
    proof: &str,
    method: &Method,
    base_url: &PublicBaseUrl,
    path: &str,
    bearer_token: Option<&str>,
    replay_store: &dyn DpopReplayStore,
) -> Result<DpopProof, DpopError> {
    let header = decode_header(proof).map_err(|_| DpopError::Malformed)?;

    if header.typ.as_deref() != Some(DPOP_TYP) {
        return Err(DpopError::WrongType);
    }
    if header.alg != DPOP_ALGORITHM {
        return Err(DpopError::WrongAlgorithm);
    }

    let jwk = header.jwk.ok_or(DpopError::Malformed)?;
    if !jwk.is_supported() {
        return Err(DpopError::Malformed);
    }

    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| DpopError::Malformed)?;

    // Proofs carry iat/jti, not exp — freshness is checked manually below,
    // so the library's default exp requirement is turned off.
    let mut validation = Validation::new(DPOP_ALGORITHM);
    validation.required_spec_claims = HashSet::new();
    validation.validate_exp = false;

    let data = decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(|_| DpopError::Malformed)?;
    let claims = data.claims;

    if claims.htm != method.as_str() {
        return Err(DpopError::MethodMismatch);
    }
    if !base_url.matches_htu(&claims.htu, path) {
        return Err(DpopError::UriMismatch);
    }

    let now = jsonwebtoken::get_current_timestamp() as i64;
    if now - claims.iat > REPLAY_WINDOW_SECS {
        return Err(DpopError::Stale);
    }
    if claims.iat - now > CLOCK_SKEW_SECS {
        return Err(DpopError::FutureIat);
    }

    if let Some(token) = bearer_token {
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(DpopError::AthMismatch);
        }
    }

    let jkt = jwk
        .thumbprint(ThumbprintHash::SHA256)
        .map_err(|_| DpopError::Malformed)?;

    let expires_at = Utc::now() + ChronoDuration::seconds(REPLAY_WINDOW_SECS + CLOCK_SKEW_SECS);
    replay_store
        .insert_jti(&claims.jti, expires_at)
        .await
        .map_err(|err| match err {
            StoreError::Replayed => DpopError::Replayed,
            StoreError::Backend(message) => DpopError::Backend(message),
            StoreError::DuplicateEmail => {
                DpopError::Backend("unexpected DuplicateEmail from replay store".to_string())
            }
        })?;

    Ok(DpopProof {
        jkt,
        jti: claims.jti,
    })
}
