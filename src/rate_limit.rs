//! Module 10: IP-based rate limiting for /register, /login, /refresh.
//!
//! Cloud Run's front end (the same infra as the External Application
//! Load Balancer) always *appends* exactly two entries to
//! `X-Forwarded-For`: `<...untrusted client-supplied prefix...>,
//! <real-client-ip>,<load-balancer-ip>`. Trusting the *first* entry
//! (what `tower_governor::SmartIpKeyExtractor` does) lets any client
//! bypass IP-based rate limiting by sending an arbitrary fake first
//! entry. The real client IP is always the second-to-last entry when
//! at least two are present.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use governor::middleware::NoOpMiddleware;
use tower_governor::GovernorError;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::KeyExtractor;

use crate::error::error_response;

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Rate-limit bucket key. `Unknown` is a single shared fallback bucket,
/// used only when neither a Cloud-Run-shaped `X-Forwarded-For` nor a
/// `ConnectInfo` peer address is available — this project's test suite
/// (which drives the router via `tower::ServiceExt::oneshot` with no
/// real TCP listener and, by default, no `X-Forwarded-For` header) hits
/// this path on every call. See `CloudRunKeyExtractor::extract` for why
/// this fails *open* into one bucket instead of erroring the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    Ip(IpAddr),
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CloudRunKeyExtractor;

impl KeyExtractor for CloudRunKeyExtractor {
    type Key = RateLimitKey;

    fn name(&self) -> &'static str {
        "cloud-run client ip"
    }

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(ip) = real_client_ip_from_xff(req) {
            return Ok(RateLimitKey::Ip(ip));
        }

        // Only populated when served via `into_make_service_with_connect_info`
        // (real `axum::serve`; see src/main.rs). Covers local/non-Cloud-Run
        // deployment contexts that have no XFF header at all.
        if let Some(ip) = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
        {
            return Ok(RateLimitKey::Ip(ip));
        }

        // Neither present: fail *open* into one shared bucket rather
        // than erroring (`GovernorError::UnableToExtractKey` maps to a
        // 500). A hard failure here would make rate limiting itself an
        // availability bug in any context this extractor doesn't
        // recognize — including this crate's own test suite, which
        // exercises the router with no listener and no XFF header.
        Ok(RateLimitKey::Unknown)
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(format!("{key:?}"))
    }
}

fn real_client_ip_from_xff<T>(req: &Request<T>) -> Option<IpAddr> {
    let value = req.headers().get(X_FORWARDED_FOR)?.to_str().ok()?;
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    // Cloud Run guarantees >=2 entries (<client-ip>,<lb-ip>) on every
    // request that reaches this service. Fewer than 2 means this isn't
    // shaped like real Cloud Run traffic (e.g. a client sending a
    // single fake entry directly) — don't trust it.
    if parts.len() < 2 {
        return None;
    }
    parts[parts.len() - 2].parse::<IpAddr>().ok()
}

type Config = GovernorConfig<CloudRunKeyExtractor, NoOpMiddleware>;

fn build(burst_size: u32, per_second: u64) -> Config {
    GovernorConfigBuilder::default()
        .key_extractor(CloudRunKeyExtractor)
        .burst_size(burst_size)
        .per_second(per_second)
        .finish()
        .expect("rate limit config: burst_size and period must be nonzero")
}

// Fixed security policy, not deployment config — same posture as this
// project's Argon2 params (src/password.rs) and token TTLs
// (src/token.rs): hardcoded Rust constants, not env-configurable.
//
// /register: account-creation abuse should be rare; tight sustained
// rate, small burst.
pub fn register_config() -> Config {
    build(5, 60)
}

// /login: complements (doesn't replace) the per-account lockout in
// src/store — this IP-layer limit exists mainly to bound Argon2 CPU
// cost per source IP and blunt single-IP guessing; the lockout counter
// (LOGIN_FAILURE_THRESHOLD = 10, src/store/firestore.rs) is the precise
// per-account brute-force defense. Burst kept meaningfully above that
// threshold (not just above it) so a single IP genuinely reaches
// account-lockout's own response before the coarser IP limiter would
// ever preempt it — if the two were equal, the IP limiter would always
// intercept the request that should have triggered lockout, since the
// governor middleware runs before the handler.
pub fn login_config() -> Config {
    build(20, 30)
}

// /refresh: legitimate clients rotate roughly every access-token TTL
// (10 min, src/token.rs), but multiple devices/tabs behind one NAT'd
// IP can refresh more often — higher ceiling than /login to avoid
// false positives for shared-IP legitimate traffic.
pub fn refresh_config() -> Config {
    build(20, 12)
}

/// Normalizes tower_governor's own plain-text rejection body into this
/// app's `{"error","message"}` shape (see src/error.rs).
/// `GovernorError::UnableToExtractKey` never actually happens with
/// `CloudRunKeyExtractor` (it fails open instead), so that arm is
/// unreachable in practice but handled defensively.
pub fn rate_limit_error_handler(err: GovernorError) -> axum::response::Response {
    match err {
        GovernorError::TooManyRequests { wait_time, .. } => {
            let mut response = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                &format!("too many requests; retry in {wait_time}s"),
            );
            if let Ok(value) = axum::http::HeaderValue::from_str(&wait_time.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
            response
        }
        _ => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to process rate limiting",
        ),
    }
}
