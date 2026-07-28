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
- Password hashing: argon2 (assumed default — confirm/revisit in Module 3)
- Deployment target: Google Cloud Run
- IaC: Terraform
- Local dev: Firestore emulator

## Status
Module 1 (architecture decisions) complete. Next: Module 2, project
scaffolding + health check endpoint.

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
- Run locally: TBD once framework is chosen
