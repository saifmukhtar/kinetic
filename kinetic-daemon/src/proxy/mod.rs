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
pub use http::*;
pub use p2p::*;
use security::*;
pub use tunnel::*;

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
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    /// Reqwest HTTP client error.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Standard IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Certificate authority error.
    #[error("CA error: {0}")]
    Ca(#[from] CaError),
    /// Generic HTTP error.
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),
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
) -> anyhow::Result<()> {
    // Case 198: IPv6 Only Network Support
    let addr = format!("127.0.0.1:{}", port);
    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = TcpListener::bind(&addr).await {
            listener = Some(l);
            break;
        } else if let Ok(l) = TcpListener::bind(format!("[::1]:{}", port)).await {
            tracing::warn!("Failed to bind Proxy to 127.0.0.1, successfully bound to IPv6 loopback [::1] (Case 198)");
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to bind Proxy to 127.0.0.1 or [::1] on port {}",
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

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_proxy_request(
                            req,
                            client_clone.clone(),
                            Arc::clone(&ca_clone),
                            Arc::clone(&cache_clone),
                            Arc::clone(&config_clone),
                        )
                    }),
                )
                .with_upgrades()
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
}

#[cfg(test)]
mod proxy_tests;
