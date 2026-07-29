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
Modules 1–9 complete (tags `v0.1.0` = Modules 1–2, `v0.2.0` = Module 3,
`v0.3.0` = Module 4, `v0.4.0` = Module 6, `v0.5.0` = Module 7, `v0.6.0` =
Module 8). Module 4 absorbed the original Module 5 scope ("protected
route middleware, bearer-only, pre-DPoP") — `GET /me` and the `AuthUser`
bearer extractor were built then rather than deferred. Module 6 (DPoP
proof-of-possession) made DPoP mandatory at login and on `/me`. Module 7
(DPoP-bound refresh rotation) enforced the `jkt` binding stored since
Module 6, rotating on every use and detecting/revoking reused tokens —
the last module with a roadmap-flagged pause point. Module 8 (Terraform +
Cloud Run) provides the Dockerfile and `terraform/production/` IaC;
Docker and Terraform were subsequently installed on this VM for local
image builds/testing, but `docker push`/`terraform apply` against GCP are
still deliberately laptop-only (the VM's own identity has zero IAM
permissions by design — see Module 3's dev-bootstrap decision), so actual
deployment still hasn't happened as of this commit. Module 9 (local dev
polish) consolidated the four handlers' duplicated JSON error-building
into one shared module (closing a real gap: malformed JSON bodies now get
this app's error shape instead of axum's default), added `.env` support,
a single-service `docker-compose.yml`, real `README.md` setup docs, and
an `examples/cli.rs` reference client. Next: Module 10 (hardening pass),
or actually executing Module 8's deployment from a privileged laptop.

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

### Module 7: 90-day absolute session cap alongside sliding rotation
Each rotation still gets a fresh 30-day `REFRESH_TOKEN_TTL_DAYS` window, but
`RefreshTokenRecord.expires_at` is capped at `family_created_at + 90 days`
(`ABSOLUTE_SESSION_CAP_DAYS`). Reuse detection is a *detective* control — it
only fires when the legitimate holder and an attacker collide on presenting
the same stale token. If the legitimate client never again presents a
stolen-and-since-rotated-away token, there's no collision to detect, and
pure sliding renewal would let a silent theft persist indefinitely. The cap
bounds that worst case as defense-in-depth, consistent with this project's
existing posture that TTL is a preventive lever, not just detection.

### Module 7: `/refresh` distinguishes reuse from invalid/expired
`not-found` and `expired` collapse into one generic `invalid_refresh_token`
response; `reused` (family revoked) gets its own `refresh_token_reused`
response, so a legitimate client can show "your session was reset for
security reasons, please log in again" instead of a generic error. Specific
cause is always logged server-side regardless of which response the client
sees.

### Module 7: Soft-delete via a `status` field, not hard-delete + ledger
`RefreshTokenRecord` gained `status` (`Active | Rotated | Revoked`),
`family_id`, `family_created_at`, `replaced_by`, and `token_hash` (a query
result doesn't otherwise carry its own document ID, needed for
`revoke_family`'s query-then-update flow). One record type, consistent with
how `refresh_tokens`/`dpop_jti` already accept some unpurged growth as a
deferred infra nicety, not a blocker.

### Module 7: Rotation and family revocation run inside Firestore transactions, not the batch-write API
Firestore write preconditions only support `Exists(bool)` — there's no way
to express "only update if status == Active" as a precondition, so the
atomic check-and-transition needs a real transaction, not the
insert-collision trick used elsewhere in this codebase. `rotate()` is
two-phase: a non-transactional pre-check (fast-path `NotFound`/`Expired`,
and `Reused` if the token's already non-`Active`), then a small
transaction re-reading the old record (handling the race where a
concurrent rotation committed in between) that atomically marks the old
record `Rotated` and creates the new `Active` one. `revoke_family` queries
by `family_id` and flips every non-`Revoked` member inside its own
transaction — not the batch-write API, since batch writes apply
independently and a partial failure could leave a sibling token silently
still valid.

### Module 7: `/refresh` DPoP handling
Reuses `dpop::validate_dpop_proof` unchanged (`ath: None`, same as login) —
RFC 9449 §4.2/§7 only requires `ath` alongside a presented bearer *access*
token, which a refresh redemption never has. Token lookup happens before
DPoP validation, mirroring login's password-before-DPoP ordering. A `jkt`
mismatch against the stored record — the first place `jkt` is actually
*enforced*, not just stored (RFC 9449 §5) — is treated as a
rejected-but-untouched attempt, not a theft signal: the opaque token secret
was presented correctly, only the proof-of-possession key differs, more
plausibly a client bug than evidence of token theft. Doesn't trigger family
revocation.

### Module 8: Same GCP project as dev, isolated via database + service account, not a second project
Production lives in `johnhealio-claude-code` (the same project as dev),
isolated via a separate Firestore database (`auth-service-prod`), a
dedicated least-privilege service account, a database-scoped IAM
condition, and a separate Terraform root/state (`terraform/production/`,
independent of `terraform/dev-bootstrap/`). Gets most of the practical
blast-radius reduction of a separate project without new
project/billing/cross-project-IAM overhead — right-sized for a solo
learning project with no live users yet. The counter-case (a separate
project is a hard trust boundary a same-project IAM misconfiguration can't
cross) is real but not proportionate here.

### Module 8: Firestore IAM least-privilege scoping (roadmap's flagged pause point, resolved)
`roles/datastore.user` (entity CRUD only — excludes the database
create/delete permissions dev-bootstrap's VM identity needs but this
deployed service doesn't), bound with an IAM condition restricting it to
the production database specifically
(`resource.name == "projects/{project}/databases/{prod-database-id}"`).
Collection-level IAM scoping doesn't exist for Firestore — the IAM
resource hierarchy stops at the database. Firestore Security Rules can
scope to collections/documents, but aren't enforced for server-side
service-account/gRPC access (only Firebase client-SDK access with
end-user auth) — which is how this app talks to Firestore, so Security
Rules don't apply here. Database-scoped IAM conditioning is the finest
grain actually available, and a real improvement over dev-bootstrap's
project-wide `datastore.owner`.

### Module 8: `firestore` crate — `tls-webpki-roots`, not the default `tls-roots`
`firestore = { default-features = false, features = ["tls-webpki-roots"] }`
removes `native-tls`/OpenSSL from the dependency tree entirely (confirmed
via `Cargo.lock` — the OpenSSL dependency came from `firestore`'s default
feature via `gcloud-sdk`, not from this project's own `reqwest` usage,
which was already rustls by default). One pure-Rust crypto stack across
the whole binary now (rustls + RustCrypto, matching `jsonwebtoken`'s
`rust_crypto` feature and `argon2` per Module 6's precedent). Note:
`ca-certificates` *files* are still needed in the runtime container
regardless — `rustls-platform-verifier` reads the OS CA bundle from disk
for the HIBP HTTPS call; the Firestore gRPC channel is unaffected, since
`tls-webpki-roots` compiles a root bundle directly into the binary.

### Module 8: Secret Manager + Cloud Run's own URL both need a phased apply
`JWT_SIGNING_SECRET` is sourced from Secret Manager (`value_source.secret_key_ref`,
`version = "latest"`), and the service account gets `roles/secretmanager.secretAccessor`
scoped to just that one secret — but Terraform only ever creates the empty
secret *container*; the value is populated out-of-band via `gcloud secrets
versions add` (never a literal in code/state, per the no-secrets-committed
constraint). Separately, `PUBLIC_BASE_URL` (needed for DPoP `htu`
validation) has to be the Cloud Run service's own assigned URL, which
isn't known until after Cloud Run creates the service — a real circular
dependency. Both are resolved the same way: apply once (secret container /
Cloud Run with a placeholder URL), populate/observe out-of-band, apply
again. See `terraform/production/README.md` for the exact sequence — not
a single `terraform apply`.

### Module 8: Cloud Run concurrency capped at 10, min instances = 0
`max_instance_request_concurrency = 10` (down from Cloud Run's default 80)
directly from the existing Argon2-memory-pressure reasoning (`m_cost ×
concurrency`, Module 3) — 80 concurrent requests would mean ~1.5 GiB of
Argon2 pressure alone on one instance, with no rate limiting yet (Module
10) to bound it otherwise. `min_instance_count = 0` (scale-to-zero,
confirmed with the user): near-zero cost while idle, cold-start penalty
softened by Rust/Axum's fast startup vs. most other stacks. `cpu = "1"`,
`memory = "512Mi"`, `max_instance_count = 3` (bounded, not unlimited, to
cap runaway-scaling cost). `us-central1`, matching Firestore's region.

### Module 8: Manual image build/push, not Cloud Build; debian-slim runtime image
Neither Claude nor this sandbox can build/push a Docker image or run
`terraform apply` (no Docker here; the VM's service account has zero IAM
permissions on the project) — the user does both from their laptop, same
pattern as `terraform/dev-bootstrap/`. Deferred Cloud Build/CI automation
to a later module rather than adding its IAM/Terraform surface now for no
benefit on this module specifically. Runtime container is
`debian:bookworm-slim` + `ca-certificates`, not distroless, for this first
deployment — debuggable (shell, `curl`) if the first rollout breaks;
~60-80MB vs. distroless's ~20MB doesn't matter for this project's
cost/cold-start profile. Public invoker access (`allUsers`) is
intentional — this is an auth service, registration/login must be
reachable without pre-existing credentials.

### Module 9: Shared error module, not a `StoreError → Response` mapping
`src/error.rs` centralizes the JSON error shape (`{"error":..,"message":..}`)
that `register.rs`/`login.rs`/`refresh.rs` had each independently
duplicated (three copies of the same `error_response` helper) and
`auth.rs` had hand-inlined twice. Callers still choose their own status
code per call site — deliberately not unified — so the existing
`invalid_dpop_proof` split (400 at `/login`/`/refresh`, 401 on `/me`,
Module 6's timing-signal reasoning) survives untouched, and no test's
`body["error"]` assertion changed. Did **not** add `impl IntoResponse for
StoreError`: `register.rs` and `refresh.rs` map the same variants (e.g.
a not-found-shaped case) to different codes/statuses in different
contexts, so a shared mapping would be either lossy or just as much
per-handler code as today — not worth it for a pure-polish module.

### Module 9: `AppJson<T>` closes a real gap — malformed JSON bodies
Before this, a malformed request body or wrong `Content-Type` on
`/register`, `/login`, or `/refresh` skipped all app error-handling
entirely and fell through to axum's own default `JsonRejection` response
(plain text, not this app's shape) — untested, undiscovered until this
module's duplication survey. `AppJson<T>` (`src/error.rs`) wraps
`axum::Json<T>` as a drop-in `FromRequest` replacement, reusing
`JsonRejection`'s own per-variant `.status()` (400 for a syntax error,
415 for a wrong content-type, etc.) rather than hardcoding one status,
under a new `invalid_json` error code. Axum 0.8's `FromRequest` is a
native `async fn`-in-trait, so no `async_trait` macro needed (unlike this
project's `dyn`-compatible store traits, which need it for object
safety).

### Module 9: `.env` via `dotenvy`, loaded before any `env::var` read
`dotenvy::dotenv()` runs as the first line of `main()`, `.ok()`'d away
(never fatal) since a missing `.env` is expected in the deployed
container (env comes from Cloud Run/Secret Manager there, not a file) —
and it never overwrites a var already set in the real environment, so
shell exports still win. `tests/common/mod.rs` needed no change:
`JWT_SIGNING_SECRET`/`PUBLIC_BASE_URL` were already fixed test-only
constants there, bypassing `from_env()`, and `cargo test` never runs
`main()`. `.env`/`.env.*` are covered by this repo's own
`.claude/settings.json` deny rules (Read/Edit/Write all blocked) as a
hardening measure — even `.env.example`, which holds only placeholders,
had to be created by the user by hand rather than by Claude, since that
policy makes no content-based exception.

### Module 9: `docker-compose.yml` — single service, no healthcheck
One service (the app container), `env_file: .env`; Firestore stays a
real remote dependency reached over the network exactly as in plain
`cargo run` — there's no local Firestore container to `depends_on`
(Module 3's real-database-not-emulator decision). No `healthcheck:`
block: the runtime image (Module 8's `debian:bookworm-slim` +
`ca-certificates` only) has no `curl`/`wget`, and every Compose
`healthcheck.test` variant execs a command inside the container — adding
one would mean editing the Dockerfile, out of scope for this module.

### Module 9: `examples/cli.rs` — reference DPoP client
User-requested mid-module. A real client-side DPoP implementation (ES256
keypair generation, JWK thumbprint, proof signing for `/login`,
`/refresh`, and `/me`'s `ath`-bound proof), not a mock — demonstrating
the protocol this project spent Modules 1/6/7 designing. Lives under
`examples/`, not `src/bin/`, specifically so it can use `p256`/`pkcs8` as
dev-dependencies (already pinned there for `tests/common/dpop.rs`'s
proof-building) without adding them to the deployed service binary —
Cargo only links dev-dependencies for tests/examples/benches, never a
regular `[[bin]]` target. Run via `cargo run --example cli -- <command>`.
Session state (tokens + the DPoP private key, which must stay the same
key across `login`→`refresh`/`me` since proofs are bound to it) persists
to `.auth-cli-state.json` in the working directory, gitignored.

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
  test-only signing secret and base URL, see `tests/common/mod.rs`). As of
  Module 9, `cp .env.example .env` + fill in values is equivalent — `cargo
  run` loads `.env` automatically — or `docker compose up --build`.
- Example CLI client: `cargo run --example cli -- register|login|refresh|me`
  (see README.md)
