use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Applied globally (all routes, including `/healthz` and `/me` — unlike
/// the per-route rate limiter, headers don't need scoping). See
/// CLAUDE.md: client type is backend/CLI + native app, not a browser —
/// `Strict-Transport-Security` is browser-enforced and so has lower
/// value here, but it's free and harmless for non-browser clients, so
/// it's included as cheap defense-in-depth for any future browser client.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    // /login and /refresh responses carry bearer tokens in the JSON
    // body — no-store is the strongest cache directive, ensuring no
    // browser cache/CDN/corporate proxy ever persists them.
    headers.insert("cache-control", HeaderValue::from_static("no-store"));

    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );

    response
}
