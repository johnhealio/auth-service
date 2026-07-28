use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let addr = "0.0.0.0:8080";
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind address");
    tracing::info!(%addr, "auth-service listening");

    axum::serve(listener, auth_service::app())
        .await
        .expect("server error");
}
