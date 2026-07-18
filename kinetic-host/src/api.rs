use anyhow::Result;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing::info;

pub async fn start_health_api(host_peer_id: libp2p::PeerId) -> Result<()> {
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peer_id",
            get(move || async move { host_peer_id.to_string() }),
        );

    let api_port = 16004;
    let addr = SocketAddr::from(([127, 0, 0, 1], api_port));
    info!(
        "Host Health-check API listening on http://127.0.0.1:{}",
        api_port
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(kinetic_core::shutdown::shutdown_signal())
        .await?;

    Ok(())
}
