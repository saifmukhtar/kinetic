//! Local HTTP/HTTPS MITM proxy server and P2P routing engine for `.kin` domain resolution.

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::ca::{CaError, LeafCertCache, RootCa};
use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};

/// HTTP proxy request handling.
pub mod http;
/// P2P proxy networking
pub mod p2p;
/// Proxy security and certificates
pub mod security;
/// Network tunneling for proxy requests
pub mod tunnel;
/// Web2 CNAME bridge and SSRF safe resolution
pub mod web2_bridge;
/// Router for forwarding proxy requests to standard IP targets.
pub mod route_ip;
/// Router for translating IPFS targets into local gateway requests.
pub mod route_ipfs;
/// Router for securely forwarding HTTP proxy requests over libp2p.
pub mod route_p2p;

pub use http::*;
pub use p2p::*;
pub use route_ip::*;
pub use route_ipfs::*;
pub use route_p2p::*;
#[cfg(test)]
pub(crate) use security::*;
pub use tunnel::*;
pub use web2_bridge::*;

/// Errors that can occur during proxy operations.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// DNS name could not be found.
    #[error("Name not found: {0}")]
    NameNotFound(String),
    /// The payload format is invalid.
    #[error("Invalid payload")]
    InvalidPayload,
    /// Hyper HTTP library error.
    #[error("Proxy failed to negotiate HTTP layer: {0}")]
    Hyper(#[from] hyper::Error),
    /// Reqwest HTTP client error.
    #[error("Proxy failed to execute backend request: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Standard IO error.
    #[error("Proxy failed to read system sockets: {0}")]
    Io(#[from] std::io::Error),
    /// Certificate authority error.
    #[error("Proxy TLS Certificate failure: {0}")]
    Ca(#[from] CaError),
    /// Generic HTTP error.
    #[error("Proxy encountered malformed HTTP packet: {0}")]
    Http(#[from] hyper::http::Error),
    /// Peer is offline or network timed out.
    #[error("Peer unreachable or request timed out: {0}")]
    PeerUnreachable(String),
    /// Security policy violation (e.g., SSRF).
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    /// Unclassified or internal proxy error.
    #[error("Other Error: {0}")]
    Other(String),
}

/// Starts the local HTTP proxy server to intercept and route `.kin` traffic.
///
/// # Errors
/// Returns an error if the server fails to bind to the specified port.
pub async fn start_proxy_server(
    client: NetworkClient,
    port: u16,
    root_ca: Arc<RootCa>,
    leaf_cache: Arc<Mutex<LeafCertCache>>,
    config: Arc<kinetic_core::config::KineticConfig>,
    node_peer_id: String,
) -> anyhow::Result<()> {
    // Case 198: IPv6 Only Network Support
    let bind_ip = &config.daemon.pac_bind_ip;
    let addr = format!("{}:{}", bind_ip, port);
    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = TcpListener::bind(&addr).await {
            listener = Some(l);
            break;
        } else if let Ok(l) = TcpListener::bind(format!("[::1]:{}", port)).await {
            tracing::warn!(
                "KIN-PRX-002: Failed to bind Proxy to {}, successfully bound to IPv6 loopback [::1] (Case 198)",
                bind_ip
            );
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| {
        tracing::error!("KIN-PRX-001: TCP Listener failed to bind proxy to {} or [::1] on port {}", bind_ip, port);
        anyhow::anyhow!(
            "KIN-PRX-001: Failed to bind Proxy to {} or [::1] on port {}",
            bind_ip,
            port
        )
    })?;

    let actual_addr = listener.local_addr()?;
    info!(
        "Local HTTP Proxy Server successfully bound and listening on http://{}",
        actual_addr
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let client_clone = client.clone();
        let ca_clone = Arc::clone(&root_ca);
        let cache_clone = Arc::clone(&leaf_cache);
        let config_clone = Arc::clone(&config);
        let peer_id_for_task = node_peer_id.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let peer_id_clone = peer_id_for_task.clone();
                        handle_proxy_request(
                            req,
                            client_clone.clone(),
                            Arc::clone(&ca_clone),
                            Arc::clone(&cache_clone),
                            Arc::clone(&config_clone),
                            peer_id_clone,
                        )
                    }),
                )
                .with_upgrades()
                .await
            {
                warn!("KIN-PRX-003: Proxy connection dropped unexpectedly: {}", err);
            }
        });
    }
}

#[cfg(test)]
mod proxy_tests;
