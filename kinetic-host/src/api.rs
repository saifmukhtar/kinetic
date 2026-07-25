//! Host health-check and static Peer ID REST API listener.

use anyhow::Result;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing::info;

/// Starts the Axum REST API server for host health checks and static Peer ID queries.
///
/// # Errors
/// Returns a `Result::Err` if the TCP listener fails to bind to port 16004 or if the HTTP server crashes.
pub async fn start_health_api(
    host_peer_id: libp2p::PeerId,
    bind_ip: std::net::IpAddr,
) -> Result<()> {
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peer_id",
            get(move || async move { host_peer_id.to_string() }),
        );

    let api_port = 16004;
    let addr = SocketAddr::from((bind_ip, api_port));
    info!(
        "Host Health-check API listening on http://{}:{}",
        bind_ip, api_port
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(kinetic_core::shutdown::shutdown_signal())
        .await?;

    Ok(())
}
