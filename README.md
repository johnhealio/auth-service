# auth-service

A learning-project authentication service in Rust (Axum + Firestore),
implementing minimal-claims JWT access tokens with mandatory DPoP
(RFC 9449) proof-of-possession binding, rotating opaque refresh tokens,
and mandatory TOTP-based MFA with single-use recovery codes.

## Requirements

- Rust (edition 2024 toolchain)
- A GCP project with a Firestore database and `gcloud` application-default
  credentials configured locally — or Docker + Docker Compose
- `openssl` (to generate a JWT signing secret)

## Quick start (no Docker)

1. `cp .env.example .env` and fill in `JWT_SIGNING_SECRET` (via
   `openssl rand -hex 32`) and your Firestore project details.
2. `cargo run`
3. Server listens on `http://localhost:8080` — try
   `curl localhost:8080/healthz`.

## Quick start (Docker)

1. `cp .env.example .env` and fill in real values as above.
2. `docker compose up --build`
3. Same endpoints on `http://localhost:8080`.

`.env` only needs the four app config vars above — GCP credentials for
Firestore access aren't one of them. On a GCE VM with an attached service
account (like this project's dev sandbox), both `cargo run` and a
container started via `docker compose` resolve credentials automatically
through the instance metadata server (`169.254.169.254`), which is
reachable from inside a default-bridge-network container on the same VM
— no credentials file or `GOOGLE_APPLICATION_CREDENTIALS` needed. Running
this elsewhere (a laptop, a non-GCE host) needs `gcloud auth
application-default login` first, same as any other Firestore client.

## Example CLI client

`examples/cli.rs` is a small standalone client demonstrating the full
mandatory-MFA registration ceremony, DPoP-bound login, refresh-token
rotation, logout, and calling the protected `/me` endpoint — a real
client-side DPoP and TOTP implementation, not a mock:

```sh
cargo run --example cli -- register you@example.com "a genuinely long passphrase"
# add the printed otpauth:// URL / secret to a real authenticator app, then:
cargo run --example cli -- confirm you@example.com <code-from-app>
# save the printed recovery codes — shown exactly once

cargo run --example cli -- login you@example.com "a genuinely long passphrase" <code-from-app>
cargo run --example cli -- me
cargo run --example cli -- refresh
cargo run --example cli -- logout
```

`login` generates a fresh DPoP keypair and saves it, with the issued
tokens, to `.auth-cli-state.json` in the current directory (gitignored) so
later `refresh`/`me` calls can reuse the same key — DPoP proofs must be
signed by the key a token was bound to at issuance. `logout` revokes the
saved refresh token and clears that state file. `login`'s `<code-from-app>`
accepts either a live TOTP code or one of the one-time recovery codes.
Target server: `AUTH_SERVICE_URL` env var, default `http://localhost:8080`
(must match the server's own `PUBLIC_BASE_URL` exactly).

## Commands

- Build: `cargo build`
- Test: `cargo test` (needs `FIRESTORE_PROJECT_ID` / `FIRESTORE_DATABASE_ID`
  set against a real Firestore database — see CLAUDE.md)
- Lint: `cargo clippy`
- Format: `cargo fmt`

## API

| Endpoint | Description |
|---|---|
| `POST /register` | Start account creation; returns a TOTP enrollment challenge |
| `POST /register/confirm` | Verify the first TOTP code; activates the account and returns 10 recovery codes |
| `POST /login` | DPoP-bound login; requires password + a TOTP or recovery code; returns an access + refresh token pair |
| `POST /refresh` | Rotate a refresh token |
| `POST /logout` | Revoke a refresh token's session |
| `GET /me` | Protected route — requires a bearer access token + DPoP proof |
| `GET /healthz` | Plain-text liveness check |

All error responses are `{"error": "<code>", "message": "<human text>"}`
JSON (except `/healthz`, which returns plain text).

## Project docs

See `CLAUDE.md` for architecture decisions and security rationale, and
`terraform/` for infrastructure-as-code (dev bootstrap + production
deployment).
