use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use kinetic_network::{NetworkClient, ProxyRequest, ProxyResponse};
use crate::ca::{CaError, LeafCertCache, RootCa};

pub mod security;
pub mod http;
pub mod tunnel;
pub mod p2p;

pub use security::*;
pub use http::*;
pub use tunnel::*;
pub use p2p::*;
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Name Not Found: {0}")]
    NameNotFound(String),
    #[error("Invalid Payload")]
    InvalidPayload,
    #[error("Hyper Error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Reqwest Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CA Error: {0}")]
    Ca(#[from] CaError),
    #[error("HTTP Error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("Other Error: {0}")]
    Other(String),
}

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
