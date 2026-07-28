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
  tokens (decided in Module 1). DPoP (RFC 9449) is mandatory as of Module 6 —
  see Decisions below for rationale.
- Client type: backend/CLI and native app client
- Password hashing: Argon2id, `m_cost=19456` KiB / `t_cost=2` / `p_cost=1`
  (decided in Module 3, see Decisions below)
- Deployment target: Google Cloud Run
- IaC: Terraform
- Local dev: real dev Firestore database (see Decisions below) — not the
  emulator; this sandbox has no Java to run it

## Status
Modules 1–6 complete (tags `v0.1.0` = Modules 1–2, `v0.2.0` = Module 3,
`v0.3.0` = Module 4; Module 6 not yet tagged). Module 4 absorbed the
original Module 5 scope ("protected route middleware, bearer-only,
pre-DPoP") — `GET /me` and the `AuthUser` bearer extractor were built then
rather than deferred. Module 6 (DPoP proof-of-possession) is done — DPoP is
now mandatory at login and on `/me`. Next: Module 7, DPoP-bound refresh
token rotation.

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

### Module 4: Access-token TTL — 10 minutes
No revocation path exists for access tokens until DPoP (Module 6, raises the
bar for *using* a stolen token, doesn't revoke it) and refresh rotation
(Module 7, only protects the refresh token). TTL is the only current lever
against leaked-token exposure, so leaning toward the short end of Module 1's
original "5–15 min" target. `token::ACCESS_TOKEN_TTL`, hardcoded like the
Argon2 params — fixed security policy, not deployment config.

### Module 4: JWT `sub` claim — opaque `user_id`, not email
Added a `user_id` field to `User` (Module 3's schema), generated at
registration via `random::generate_opaque_token(16)`, used as the JWT `sub`.
Using email as `sub` would have quietly contradicted Module 1's "no PII in
the JWT" decision — email is PII. The Firestore doc ID for `users` stays the
normalized email (Module 3's atomic-uniqueness design is unaffected);
`user_id` is just an added field, used only as the JWT identity.

### Module 4: JWT signing — HS256, secret via required env var
HS256 chosen over RS256/ES256: this service both issues and verifies its own
tokens, and nothing on the roadmap (including Cloud Run horizontal scaling in
Module 8, which is same-service replicas, not a split issuer/verifier)
introduces an independent verifier that would benefit from asymmetric
signing. Signing secret comes from a required `JWT_SIGNING_SECRET` env var
(`token::JwtKeys::from_env()`), mirroring the existing `FIRESTORE_PROJECT_ID`
convention — generate with `openssl rand -hex 32`, never committed. Tradeoff:
restarting without re-exporting the same value invalidates prior tokens —
acceptable for dev; Module 8/10 replace this with Secret Manager.
Dependency note: `jsonwebtoken` needed the `rust_crypto` feature enabled to
get any signing backend at all (no crypto provider is on by default).

### Module 4: Refresh tokens — hashed at rest, 30-day TTL
Refresh tokens are stored as their SHA-256 hash, not plaintext — the hash
itself is the Firestore doc ID in a new `refresh_tokens` collection (mirrors
Module 3's "email as doc ID" pattern: content-addressed, atomic lookup, no
separate compare step). Unlike passwords, refresh tokens are already
random/high-entropy, so a fast hash is sufficient — no dictionary-attack
surface, and hashing protects against a Firestore read/backup leak turning
into immediately-usable bearer credentials. 30-day TTL, checked at
redemption time (not yet a Firestore TTL policy — Module 4 doesn't implement
`/refresh` redemption itself, that's Module 7's rotation work).

### Module 4: Timing-safe login
An unknown email used to short-circuit before Argon2 ran, while a wrong
password against a real email paid ~20–40ms — an observable,
account-existence-leaking timing gap even with identical error text.
Fixed by verifying against a precomputed dummy Argon2 hash
(`login::DUMMY_HASH`) when the user doesn't exist, so both paths pay the
same cost. Tested by asserting the wrong-password and unknown-email
responses are field-for-field identical, not just "also generic."

### Module 6: DPoP mandatory, not optional
Enforced at both login and on `/me`. An optional bearer-only fallback would
let an attacker just omit the `DPoP` header and use a stolen token exactly
as before, defeating the point of Module 1's whole DPoP-bound design. Broke
the existing login/`/me` tests in the expected way (they now need a valid
proof); no bearer-only path exists anywhere in the app.

### Module 6: `htu` validated against a required `PUBLIC_BASE_URL`
Not derived from request headers. This codebase has no forwarded-header
trust logic, and Cloud Run terminates TLS at the front end, so a request's
own view of its scheme is unreliable in production. Expected `htu` =
`PUBLIC_BASE_URL` + the request path; comparison normalizes scheme/host
case and default-port omission (via the `url` crate), exact path match, no
trailing-slash leniency added speculatively.

### Module 6: Freshness — 300s replay window, ±60s clock skew
±60s skew is the conventional OAuth/OIDC default (matches `jsonwebtoken`'s
own `Validation::leeway`). 300s window balances a small/cheap `jti` replay
cache against not spuriously rejecting slow/retried legitimate requests —
the cache only needs to remember entries for `window + skew` (~6 min),
since staler proofs are already rejected on `iat` freshness alone.
Firestore collection `dpop_jti`, doc ID = the `jti` itself (not hashed —
it's a server-mandated-unique client nonce, not a secret); insert-if-absent
via the same `DataConflictError` pattern used for email/refresh-token
uniqueness, so replay detection is atomic with no transaction needed.

### Module 6: DPoP-Nonce (RFC 9449's optional server-challenge) — deferred
Defends against *offline pre-generation* of proofs (e.g. from a transient
client key compromise) by forcing every proof to be minted after a live
round-trip with the server — not against real-time interception, which is
TLS's job. That threat is narrow and sophisticated for a project with no
adversarial production traffic yet; the added complexity (extra round trip,
nonce state/rotation, more test surface) isn't proportional to the learning
value here. Fully additive later — doesn't foreclose adding it. Documented
as future work, not implemented.

### Module 6: DPoP proof signature — ES256 only
The RFC's cited example algorithm, most interoperable for future
spec-compliance testing, and keeps verification to one `Validation` config
with no algorithm-confusion surface. `alg: none` and symmetric algs
(`HS*`) are rejected by construction — tested explicitly.

### Module 6: `cnf.jkt` binding and `jkt` storage
`JwtClaims.cnf` (RFC 7800/9449 §6.1's nested `{"jkt": "..."}` shape, not
flattened) is non-optional, since DPoP is mandatory — every access token is
key-bound from issuance. `RefreshTokenRecord` also gets a `jkt` field now
(storage only, no enforcement — that's Module 7's redemption/rotation
logic), written from the same thumbprint bound into the access token at
login. Avoids a schema migration or permanently-unbound early tokens later.

### Module 6: `DpopBoundUser` composes `AuthUser`, doesn't replace it
`AuthUser` (Module 4, bearer-JWT-only) stays available in isolation for
anything that might not need DPoP later. `DpopBoundUser` (used by `/me`)
re-verifies the bearer JWT itself plus the accompanying `DPoP` proof: the
proof's `ath` must hash-match the actual bearer token, and its key
thumbprint must equal the token's `cnf.jkt`. Implementation finding:
`jsonwebtoken` 11 already has RFC 7638 thumbprint support built in
(`Jwk::thumbprint`), embedded-JWK header support, and
`DecodingKey::from_jwk` — no hand-rolled canonical-JSON thumbprint code
needed.

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
- Run locally: `FIRESTORE_PROJECT_ID=johnhealio-claude-code FIRESTORE_DATABASE_ID=auth-service-dev JWT_SIGNING_SECRET=$(openssl rand -hex 32) PUBLIC_BASE_URL=http://localhost:8080 cargo run`
  (`cargo test` only needs the two `FIRESTORE_*` vars — tests use a fixed
  test-only signing secret and base URL, see `tests/common/mod.rs`)
