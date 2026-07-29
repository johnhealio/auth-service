//! Example CLI client for auth-service: mandatory-MFA registration,
//! DPoP-bound login, refresh-token rotation, logout, and calling the
//! protected `/me` endpoint.
//!
//! Run against a locally running server (`cargo run`, or `docker compose
//! up`):
//!   cargo run --example cli -- register <email> <password>
//!   cargo run --example cli -- confirm <email> <mfa-code>
//!   cargo run --example cli -- login <email> <password> <mfa-code>
//!   cargo run --example cli -- refresh
//!   cargo run --example cli -- me
//!   cargo run --example cli -- logout
//!
//! `register` prints an `otpauth://` URL and base32 secret — add it to a
//! real authenticator app (or any TOTP-compatible tool), then run
//! `confirm` with the 6-digit code it shows. The account isn't usable for
//! `login` until `confirm` succeeds. `confirm` prints 10 single-use
//! recovery codes exactly once — save them; either a TOTP code or one of
//! these codes works as `login`'s `<mfa-code>` argument, since the
//! server-side TOTP secret only ever lives in your authenticator app, not
//! in anything this CLI persists.
//!
//! `login` generates a fresh DPoP keypair and persists it (with the
//! access/refresh tokens it's bound to) to `.auth-cli-state.json` in the
//! current directory, so later `refresh`/`me` calls can reuse the same
//! key — DPoP proofs must be signed by the key a token was issued to.
//! `logout` revokes the saved refresh token's family and clears that
//! state file. Target base URL: `AUTH_SERVICE_URL` env var, default
//! `http://localhost:8080` (must match the server's own `PUBLIC_BASE_URL`
//! exactly, since DPoP proofs are validated against it).

use std::fs;
use std::path::Path;

use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const STATE_FILE: &str = ".auth-cli-state.json";

#[derive(Serialize, Deserialize, Default)]
struct CliState {
    email: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    /// PKCS8 DER-encoded EC private key, base64-standard-encoded.
    dpop_private_key_der_b64: Option<String>,
}

impl CliState {
    fn load() -> Self {
        match fs::read_to_string(STATE_FILE) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    fn save(&self) {
        let contents = serde_json::to_string_pretty(self).expect("serialize cli state");
        fs::write(STATE_FILE, contents).expect("write cli state file");
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

fn generate_keypair() -> (Vec<u8>, EncodingKey, Jwk) {
    let signing_key = SigningKey::random(&mut OsRng);
    let der = signing_key
        .to_pkcs8_der()
        .expect("pkcs8-encode generated key")
        .as_bytes()
        .to_vec();
    let (encoding_key, jwk) = keypair_from_der(&der);
    (der, encoding_key, jwk)
}

fn keypair_from_der(der: &[u8]) -> (EncodingKey, Jwk) {
    let encoding_key = EncodingKey::from_ec_der(der);
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256).expect("derive jwk");
    (encoding_key, jwk)
}

fn build_dpop_proof(
    encoding_key: &EncodingKey,
    jwk: &Jwk,
    htm: &str,
    htu: &str,
    ath: Option<String>,
) -> String {
    let claims = DpopClaims {
        htm: htm.to_string(),
        htu: htu.to_string(),
        iat: jsonwebtoken::get_current_timestamp() as i64,
        jti: format!("{:x}", rand_jti()),
        ath,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());

    encode(&header, &claims, encoding_key).expect("sign dpop proof")
}

/// A random 128-bit `jti` — doesn't need to be cryptographically secure,
/// just unique per proof, so a simple time+counter mix is enough here.
fn rand_jti() -> u128 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos ^ (n as u128)
}

fn access_token_ath(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn base_url() -> String {
    std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str);

    match command {
        Some("register") => {
            let (email, password) = require_email_password(&args);
            register(&email, &password).await;
        }
        Some("confirm") => {
            let (email, code) = require_two_args(&args, "<email> <mfa-code>");
            confirm(&email, &code).await;
        }
        Some("login") => {
            let (email, password, mfa_code) = require_email_password_code(&args);
            login(&email, &password, &mfa_code).await;
        }
        Some("refresh") => refresh().await,
        Some("me") => me().await,
        Some("logout") => logout().await,
        _ => {
            eprintln!(
                "usage:\n  cargo run --example cli -- register <email> <password>\n  cargo run --example cli -- confirm <email> <mfa-code>\n  cargo run --example cli -- login <email> <password> <mfa-code>\n  cargo run --example cli -- refresh\n  cargo run --example cli -- me\n  cargo run --example cli -- logout"
            );
            std::process::exit(1);
        }
    }
}

fn require_two_args(args: &[String], usage: &str) -> (String, String) {
    match (args.get(2), args.get(3)) {
        (Some(a), Some(b)) => (a.clone(), b.clone()),
        _ => {
            eprintln!("expected {usage} arguments");
            std::process::exit(1);
        }
    }
}

fn require_email_password(args: &[String]) -> (String, String) {
    require_two_args(args, "<email> <password>")
}

fn require_email_password_code(args: &[String]) -> (String, String, String) {
    match (args.get(2), args.get(3), args.get(4)) {
        (Some(email), Some(password), Some(mfa_code)) => {
            (email.clone(), password.clone(), mfa_code.clone())
        }
        _ => {
            eprintln!("expected <email> <password> <mfa-code> arguments");
            std::process::exit(1);
        }
    }
}

async fn register(email: &str, password: &str) {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/register", base_url()))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("send register request");

    if !response.status().is_success() {
        print_response("register", response).await;
        return;
    }

    let body: serde_json::Value = response.json().await.expect("parse register response");
    println!("registered {email} — account not usable for login yet.");
    println!(
        "add this to an authenticator app: {}",
        body["mfa_enrollment_url"].as_str().unwrap_or("")
    );
    println!(
        "or enter this secret manually: {}",
        body["mfa_secret_base32"].as_str().unwrap_or("")
    );
    println!("then run: cargo run --example cli -- confirm {email} <code-from-app>");
}

async fn confirm(email: &str, mfa_code: &str) {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/register/confirm", base_url()))
        .json(&serde_json::json!({ "email": email, "mfa_code": mfa_code }))
        .send()
        .await
        .expect("send confirm request");

    if !response.status().is_success() {
        print_response("confirm", response).await;
        return;
    }

    let body: serde_json::Value = response.json().await.expect("parse confirm response");
    println!("MFA enrollment confirmed for {email}.");
    println!("SAVE THESE RECOVERY CODES NOW — shown exactly once, never retrievable again:");
    if let Some(codes) = body["recovery_codes"].as_array() {
        for code in codes {
            println!("  {}", code.as_str().unwrap_or(""));
        }
    }
}

async fn login(email: &str, password: &str, mfa_code: &str) {
    let client = reqwest::Client::new();
    let (der, encoding_key, jwk) = generate_keypair();
    let htu = format!("{}/login", base_url());
    let proof = build_dpop_proof(&encoding_key, &jwk, "POST", &htu, None);

    let response = client
        .post(&htu)
        .header("DPoP", proof)
        .json(&serde_json::json!({ "email": email, "password": password, "mfa_code": mfa_code }))
        .send()
        .await
        .expect("send login request");

    if !response.status().is_success() {
        print_response("login", response).await;
        return;
    }

    let body: serde_json::Value = response.json().await.expect("parse login response");
    let state = CliState {
        email: Some(email.to_string()),
        access_token: body["access_token"].as_str().map(String::from),
        refresh_token: body["refresh_token"].as_str().map(String::from),
        dpop_private_key_der_b64: Some(STANDARD.encode(der)),
    };
    state.save();
    println!("logged in as {email}, state saved to {STATE_FILE}");
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

async fn refresh() {
    let state = CliState::load();
    let (Some(refresh_token), Some(der_b64)) = (
        state.refresh_token.clone(),
        state.dpop_private_key_der_b64.clone(),
    ) else {
        eprintln!("no saved session — run `login` first");
        std::process::exit(1);
    };
    let der = STANDARD.decode(der_b64).expect("decode saved dpop key");
    let (encoding_key, jwk) = keypair_from_der(&der);

    let client = reqwest::Client::new();
    let htu = format!("{}/refresh", base_url());
    let proof = build_dpop_proof(&encoding_key, &jwk, "POST", &htu, None);

    let response = client
        .post(&htu)
        .header("DPoP", proof)
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("send refresh request");

    if !response.status().is_success() {
        print_response("refresh", response).await;
        return;
    }

    let body: serde_json::Value = response.json().await.expect("parse refresh response");
    let new_state = CliState {
        email: state.email,
        access_token: body["access_token"].as_str().map(String::from),
        refresh_token: body["refresh_token"].as_str().map(String::from),
        dpop_private_key_der_b64: Some(STANDARD.encode(der)),
    };
    new_state.save();
    println!("refreshed, state saved to {STATE_FILE}");
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

async fn me() {
    let state = CliState::load();
    let (Some(access_token), Some(der_b64)) = (
        state.access_token.clone(),
        state.dpop_private_key_der_b64.clone(),
    ) else {
        eprintln!("no saved session — run `login` first");
        std::process::exit(1);
    };
    let der = STANDARD.decode(der_b64).expect("decode saved dpop key");
    let (encoding_key, jwk) = keypair_from_der(&der);

    let client = reqwest::Client::new();
    let htu = format!("{}/me", base_url());
    let ath = access_token_ath(&access_token);
    let proof = build_dpop_proof(&encoding_key, &jwk, "GET", &htu, Some(ath));

    let response = client
        .get(&htu)
        .header("DPoP", proof)
        .bearer_auth(access_token)
        .send()
        .await
        .expect("send me request");

    print_response("me", response).await;
}

async fn logout() {
    let state = CliState::load();
    let Some(refresh_token) = state.refresh_token.clone() else {
        eprintln!("no saved session — nothing to log out of");
        return;
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/logout", base_url()))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .expect("send logout request");

    print_response("logout", response).await;

    if let Err(err) = fs::remove_file(STATE_FILE)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("warning: failed to remove {STATE_FILE}: {err}");
    }
}

async fn print_response(label: &str, response: reqwest::Response) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    println!("{label}: {status}");
    println!("{body}");
    if !Path::new(STATE_FILE).exists() && !status.is_success() {
        eprintln!("note: no saved session found at {STATE_FILE}");
    }
}
