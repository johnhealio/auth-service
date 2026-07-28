# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# Cache dependencies separately from app code: build with dummy source
# files first (this crate has both a lib and a bin target, so both need a
# stub) so the dependency graph compiles into a cached layer. Only the
# `COPY src` step onward re-runs when app code changes, not this whole
# dependency build — the manifests (and lockfile) are what actually gate
# the cache, not the app source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release

# ---- Runtime stage ----
# Same Debian codename (bookworm) as the build stage's base image, to avoid
# a glibc version mismatch between the compiled binary and the runtime.
FROM debian:bookworm-slim

# rustls-platform-verifier reads the OS CA bundle from disk for outbound
# HTTPS calls (the Have I Been Pwned breach check) even though the
# Firestore gRPC channel itself needs no runtime cert files (tls-webpki-roots
# compiles its root bundle directly into the binary).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
USER appuser

EXPOSE 8080
CMD ["/usr/local/bin/auth-service"]
