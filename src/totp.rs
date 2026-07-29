//! Module 11: TOTP (RFC 6238) generation/verification, kept out of the
//! store layer — mirrors how `dpop.rs`'s proof verification is separate
//! from `DpopReplayStore`'s pure jti-dedup persistence.

use totp_rs::{Algorithm, Secret, TOTP};

pub const ISSUER: &str = "auth-service";
const DIGITS: usize = 6;
// ±1 step (±30s) — RFC 6238's own recommended tolerance, same spirit as
// this project's DPoP ±60s clock-skew constant (src/dpop.rs).
const SKEW: u8 = 1;
const STEP_SECONDS: u64 = 30;

/// A freshly generated secret for a not-yet-confirmed account, plus
/// everything needed to show the user an enrollment challenge.
pub struct EnrollmentSecret {
    secret_bytes: Vec<u8>,
    totp: TOTP,
}

pub fn generate_enrollment_secret(account_email: &str) -> EnrollmentSecret {
    let secret_bytes = Secret::generate_secret()
        .to_bytes()
        .expect("Secret::generate_secret() always yields valid bytes");
    let totp = build_totp(&secret_bytes, account_email);
    EnrollmentSecret { secret_bytes, totp }
}

impl EnrollmentSecret {
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret_bytes.clone()
    }

    /// `otpauth://` URL for an authenticator app (or a client-rendered QR
    /// code — this service never renders images itself).
    pub fn otpauth_url(&self) -> String {
        self.totp.get_url()
    }

    /// Base32, for manual entry when the user can't scan a QR code.
    pub fn base32_secret(&self) -> String {
        self.totp.get_secret_base32()
    }

    /// Test/example-CLI convenience: the current valid code for this
    /// secret. A real client never has this — the TOTP secret only ever
    /// lives in the user's own authenticator app after enrollment.
    #[allow(dead_code)]
    pub fn generate_current(&self) -> String {
        self.totp
            .generate_current()
            .expect("system clock is after UNIX_EPOCH")
    }
}

fn build_totp(secret_bytes: &[u8], account_email: &str) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP_SECONDS,
        secret_bytes.to_vec(),
        Some(ISSUER.to_string()),
        account_email.to_string(),
    )
    .expect("fixed algorithm/digits/step/secret-length parameters are always valid")
}

/// Test/example-CLI convenience: reconstructs a verifier from a base32
/// secret (as returned by `/register`'s `mfa_secret_base32`) and computes
/// the current valid code — simulating what a real authenticator app
/// would show, independent of any stored `EnrollmentSecret`.
#[allow(dead_code)]
pub fn generate_current_for_base32(base32_secret: &str, account_email: &str) -> String {
    let secret_bytes = Secret::Encoded(base32_secret.to_string())
        .to_bytes()
        .expect("valid base32 secret");
    build_totp(&secret_bytes, account_email)
        .generate_current()
        .expect("system clock is after UNIX_EPOCH")
}

/// Checks `code` against `secret_bytes` at the current time (±1 step). A
/// `SystemTimeError` (clock before UNIX_EPOCH — not a real-world case)
/// collapses to `false`, same fail-closed posture as every other
/// credential check in this codebase.
pub fn check_code(secret_bytes: &[u8], account_email: &str, code: &str) -> bool {
    build_totp(secret_bytes, account_email)
        .check_current(code)
        .unwrap_or(false)
}
