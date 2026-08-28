//! Host health-check and static Peer ID REST API listener.

use anyhow::Result;
use axum::{Router, routing::get, extract::Path, http::StatusCode};
use std::net::SocketAddr;
use tracing::info;

/// Starts the Axum REST API server for host health checks and static Peer ID queries.
/// Supports a File-Drop architecture where a single Master API handles routes for multiple worker instances.
pub async fn start_health_api(
    host_peer_id: libp2p::PeerId,
    bind_ip: std::net::IpAddr,
) -> Result<()> {
    let instance_name = std::env::var("KINETIC_INSTANCE_NAME").unwrap_or_else(|_| "default".to_string());
    
    // 1. The File-Drop (Worker State)
    let global_instances_dir = std::env::temp_dir().join("kinetic_host_instances");
    let _ = std::fs::create_dir_all(&global_instances_dir);
    let instance_file = global_instances_dir.join(format!("{}.txt", instance_name));
    let _ = std::fs::write(&instance_file, host_peer_id.to_string());

    // 2. The Master API
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peer_id",
            get({
                let pid = host_peer_id;
                move || async move { pid.to_string() }
            }),
        )
        .route(
            "/:name/peer_id",
            get(move |Path(name): Path<String>| async move {
                let file_path = std::env::temp_dir()
                    .join("kinetic_host_instances")
                    .join(format!("{}.txt", name));
                match std::fs::read_to_string(file_path) {
                    Ok(peer_id) => (StatusCode::OK, peer_id),
                    Err(_) => (StatusCode::NOT_FOUND, "Instance not found".to_string()),
                }
            }),
        );

    let api_port = 16004;
    let addr = SocketAddr::from((bind_ip, api_port));
    
    // 3. Graceful Fallback
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            info!("Host Health-check API (Master) listening on http://{}:{}", bind_ip, api_port);
            axum::serve(listener, app)
                .with_graceful_shutdown(kinetic_core::shutdown::shutdown_signal())
                .await
                .map_err(|e| anyhow::anyhow!("KIN-HST-014: Health API server crashed: {}", e))?;
        }
        Err(_) => {
            tracing::info!("KIN-HST-015: Port {} is in use. Gracefully degrading to Worker mode for instance '{}'.", api_port, instance_name);
            // Block forever until shutdown signal so the main daemon loop stays alive
            kinetic_core::shutdown::shutdown_signal().await;
        }
    }

    let _ = std::fs::remove_file(instance_file);
    Ok(())
}
