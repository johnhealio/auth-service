# Project: Auth Service (Rust, Cloud Run, Firestore)

## Goal
A learning project to build a production-shaped authentication service:
registration, login, session/token-based auth, and protected routes.
Deployed as a containerized service on Google Cloud Run, using Firestore
as the user data store.

## Purpose of this project
This is explicitly a learning project for practicing a real Claude Code
development workflow (planning, incremental building, code review, testing,
hooks, infra-as-code) — not just a code output exercise. Favor explaining
tradeoffs and asking clarifying questions over silently picking defaults,
especially for security-relevant decisions. 

DPoP support is a stated goal, not an afterthought — when discussing the
auth model in Module 1, evaluate session vs JWT specifically through the
lens of "how does DPoP binding work with this choice," not as two
separate decisions made in sequence.

## Tech stack
- Language: Rust
- Web framework: Axum (decided in Module 1)
- Database: Firestore (via the `firestore` crate, fluent API, v0.12+)
- Auth model: minimal-claims JWT access tokens + DPoP-bound opaque refresh
  tokens (decided in Module 1). See Decisions below for rationale.
- Client type: backend/CLI and native app client
- Password hashing: Argon2id, `m_cost=19456` KiB / `t_cost=2` / `p_cost=1`
  (decided in Module 3, see Decisions below)
- Deployment target: Google Cloud Run
- IaC: Terraform
- Local dev: real dev Firestore database (see Decisions below) — not the
  emulator; this sandbox has no Java to run it

## Status
Modules 1–3 complete (tag `v0.1.0` covers Modules 1–2; Module 3 not yet
tagged). Next: Module 4, login + token issuance.

## Decisions made so far

### Module 1: Framework — Axum
Chosen over Actix-web. Shares `tower`/`hyper` primitives with the `firestore`
crate's `tonic` foundation, so DPoP middleware, auth middleware, and the
Firestore client all compose via the same `tower::Layer`/`Service` machinery.
Its `FromRequestParts` extractor model is a clean fit for DPoP proof
validation (needs method/URI/headers before the handler runs). Also better
current teaching value than Actix-web's `Transform`/`Service` traits for a
learning project.

### Module 1: Auth model — minimal-claims JWT + DPoP-bound refresh tokens
- Access token: short-lived JWT (target ~5–15 min TTL) carrying only `sub`
  (user id), `iat`, `exp`, `jti`, and `cnf.jkt` (DPoP key-thumbprint binding
  per RFC 9449). No email, org id, role, or permission data in the token —
  those are looked up live from Firestore by `sub` when a handler needs them.
- Refresh token: opaque, Firestore-tracked, also DPoP-bound (`jkt` stored on
  the record), single-use with rotation; reuse triggers revocation of the
  whole token family (theft signal).
- DPoP replay protection (`jti` uniqueness within the `iat` freshness window)
  uses a shared Firestore-backed TTL'd cache for both access and refresh
  requests.

Rationale: RFC 9449's `cnf.jkt` claim is purpose-built for JWTs, giving
stateless DPoP validation on ordinary requests (signature + expiry + `jkt`
match, no DB read). Pure opaque sessions would work too, but bolt DPoP
binding onto storage rather than using the RFC's native mechanism.
Rejected the naive "put profile data in the JWT" version specifically
because JWTs are signed, not encrypted — any claim in the payload is
readable by anyone holding the token (the client, or anything that captures
it in transit/logs), so email/org id/permissions were kept out of the token
and are only ever read from Firestore server-side. This also avoids staleness
(a JWT's claims are frozen at issuance; permission changes wouldn't take
effect until the token expired).
Refresh tokens are opaque rather than JWTs regardless of access-token shape,
since they're long-lived and need to be revocable and rotation/reuse
detectable.

### Module 3: Dev Firestore access — real database, not the emulator
This dev VM has `gcloud` but no Java/Docker, so the real Firestore emulator
can't run here. Rather than emulate or fake it, a real dev Firestore
database was provisioned via Terraform (`terraform/dev-bootstrap/`, applied
from a laptop with sufficient privileges — the VM's own service account
cannot self-grant IAM roles): a named database `auth-service-dev` in
`us-central1`, with `roles/datastore.owner` granted to the VM's service
account (`claude-code-vm@johnhealio-claude-code.iam.gserviceaccount.com`).
This is deliberately broader than what the *deployed* Cloud Run service will
get in Module 8 — this grant is for a dev/test identity that also needs to
create/delete the database itself, not the production service, so it doesn't
violate the least-privilege constraint below for the actual deployment.
`cargo test` runs against this live database (`FIRESTORE_PROJECT_ID`,
`FIRESTORE_DATABASE_ID` env vars) rather than a fake or emulator.

### Module 3: Password hashing — Argon2id, 19 MiB / t=2 / p=1
OWASP baseline tier, chosen over heavier tiers (e.g. 64 MiB/t=3) because
Cloud Run's memory pressure scales with `m_cost × concurrent requests`, and
no rate limiting exists yet (that's Module 10) to bound concurrency. This
choice is backed by password-strength enforcement rather than standing
alone: for high-entropy passwords the ~5x brute-force-cost gap vs. a heavier
config is immaterial, since both are already computationally infeasible —
the entropy of the password matters far more than this parameter choice.
Hardcoded as Rust constants in `src/password.rs`, not env-configurable —
a fixed security policy, not deployment config.

### Module 3: Password validation
- Minimum 12 characters (raised from NIST 800-63B's 8-char floor — the
  standard stronger default when MFA isn't in place yet), max 256, reject
  empty/whitespace-only. No forced complexity rules (NIST 800-63B discourages
  them — they push toward predictable patterns without reliably raising
  entropy).
- Breached-password check via the Have I Been Pwned Pwned Passwords
  k-anonymity API (`api.pwnedpasswords.com/range/{sha1-prefix}`) — only a
  5-char SHA-1 prefix ever leaves the process, no API key needed (confirmed
  free/keyless with no hard rate limit for this endpoint). Runs on the
  plaintext password before Argon2 hashing. **Fail-open**: if the API is
  slow/unreachable, log a warning and allow registration through rather than
  coupling signup availability to a third party's uptime.

### Module 3: Firestore schema — email as document ID
`users/{normalized_email}` (trimmed, lowercased email as the doc ID).
Firestore's create-if-not-exists write is atomic at the single-document
level, so duplicate-email protection comes for free with zero race window —
no transaction needed. Tradeoff: email is effectively the primary key;
changing it later means creating a new doc, not an in-place update —
accepted for this project.

## Constraints
- No secrets or credentials ever committed to the repo or written into code.
- Firestore access from the deployed service should use a dedicated service
  account with least-privilege IAM roles, not broad project-level roles.
- Prefer small, independently testable increments over large multi-feature
  changes in a single session.

## Commands
- Build: `cargo build`
- Test: `cargo test`
- Lint: `cargo clippy`
- Format: `cargo fmt`
- Run locally: `FIRESTORE_PROJECT_ID=johnhealio-claude-code FIRESTORE_DATABASE_ID=auth-service-dev cargo run`
  (same env vars needed for `cargo test`, since tests run against the real
  dev Firestore database — see Module 3 decisions)
