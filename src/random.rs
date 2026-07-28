use argon2::password_hash::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// A random, high-entropy, hex-encoded token — used for user ids, refresh
/// tokens, and JWT `jti` values. Not for passwords (see `password.rs`):
/// these values are never human-chosen, so no slow KDF is needed.
pub fn generate_opaque_token(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// SHA-256 is sufficient here (not Argon2): the input is already a random,
/// high-entropy token, not a human-guessable password, so there's no
/// dictionary-attack surface a slow KDF would defend against.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    to_hex(&digest)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_opaque_token_is_unique_and_correct_length() {
        let a = generate_opaque_token(16);
        let b = generate_opaque_token(16);
        assert_ne!(a, b);
        assert_eq!(a.len(), 32); // 16 bytes -> 32 hex chars
    }

    #[test]
    fn hash_token_is_deterministic_and_not_the_input() {
        let token = "some-opaque-token";
        let hash_a = hash_token(token);
        let hash_b = hash_token(token);
        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, token);
        assert_eq!(hash_a.len(), 64); // SHA-256 -> 32 bytes -> 64 hex chars
    }
}
