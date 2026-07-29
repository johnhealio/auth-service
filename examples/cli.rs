//! Example CLI client for auth-service: registration, DPoP-bound login,
//! refresh-token rotation, and calling the protected `/me` endpoint.
//!
//! Run against a locally running server (`cargo run`, or `docker compose
//! up`):
//!   cargo run --example cli -- register <email> <password>
//!   cargo run --example cli -- login <email> <password>
//!   cargo run --example cli -- refresh
//!   cargo run --example cli -- me
//!
//! `login` generates a fresh DPoP keypair and persists it (with the
//! access/refresh tokens it's bound to) to `.auth-cli-state.json` in the
//! current directory, so later `refresh`/`me` calls can reuse the same
//! key — DPoP proofs must be signed by the key a token was issued to.
//! Target base URL: `AUTH_SERVICE_URL` env var, default
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
        Some("login") => {
            let (email, password) = require_email_password(&args);
            login(&email, &password).await;
        }
        Some("refresh") => refresh().await,
        Some("me") => me().await,
        _ => {
            eprintln!(
                "usage:\n  cargo run --example cli -- register <email> <password>\n  cargo run --example cli -- login <email> <password>\n  cargo run --example cli -- refresh\n  cargo run --example cli -- me"
            );
            std::process::exit(1);
        }
    }
}

fn require_email_password(args: &[String]) -> (String, String) {
    match (args.get(2), args.get(3)) {
        (Some(email), Some(password)) => (email.clone(), password.clone()),
        _ => {
            eprintln!("expected <email> <password> arguments");
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

    print_response("register", response).await;
}

async fn login(email: &str, password: &str) {
    let client = reqwest::Client::new();
    let (der, encoding_key, jwk) = generate_keypair();
    let htu = format!("{}/login", base_url());
    let proof = build_dpop_proof(&encoding_key, &jwk, "POST", &htu, None);

    let response = client
        .post(&htu)
        .header("DPoP", proof)
        .json(&serde_json::json!({ "email": email, "password": password }))
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

async fn print_response(label: &str, response: reqwest::Response) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    println!("{label}: {status}");
    println!("{body}");
    if !Path::new(STATE_FILE).exists() && !status.is_success() {
        eprintln!("note: no saved session found at {STATE_FILE}");
    }
}
