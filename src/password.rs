use std::sync::LazyLock;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha1::{Digest, Sha1};

// Argon2id, OWASP baseline tier: 19 MiB / 2 iterations / 1 lane. Chosen over
// heavier tiers because Cloud Run's memory pressure scales with
// m_cost * concurrent requests, and no rate limiting exists yet to bound
// concurrency. Fixed security policy, not deployment config — change via
// code review, not an env var.
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

fn argon2() -> Argon2<'static> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("static argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(argon2()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const HIBP_TIMEOUT: Duration = Duration::from_secs(3);

static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// Checks the candidate password against the Have I Been Pwned Pwned
/// Passwords k-anonymity API: only a 5-character SHA-1 prefix ever leaves
/// this process, never the password itself. Callers should treat network
/// errors as fail-open (log and allow registration) rather than blocking
/// signup on a third party's uptime.
pub async fn check_breached(password: &str) -> Result<bool, reqwest::Error> {
    let digest = Sha1::digest(password.as_bytes());
    let hex = to_hex_upper(&digest);
    let (prefix, suffix) = hex.split_at(5);

    let response = HTTP_CLIENT
        .get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("User-Agent", "auth-service-learning-project")
        .timeout(HIBP_TIMEOUT)
        .send()
        .await?
        .error_for_status()?;

    let body = response.text().await?;

    Ok(body.lines().any(|line| {
        line.split_once(':')
            .map(|(returned_suffix, _count)| returned_suffix.eq_ignore_ascii_case(suffix))
            .unwrap_or(false)
    }))
}

fn to_hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password entirely", &hash).unwrap());
    }

    #[test]
    fn hash_is_not_plaintext_and_uses_argon2id() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert_ne!(hash, "correct horse battery staple");
        assert!(hash.starts_with("$argon2id$"));
    }
}
