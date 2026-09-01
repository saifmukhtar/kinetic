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
/// Router for forwarding proxy requests to standard IP targets.
pub mod route_ip;
/// Router for translating IPFS targets into local gateway requests.
pub mod route_ipfs;
/// Router for securely forwarding HTTP proxy requests over libp2p.
pub mod route_p2p;
/// Proxy security and certificates
pub mod security;
/// Network tunneling for proxy requests
pub mod tunnel;
/// Web2 CNAME bridge and SSRF safe resolution
pub mod web2_bridge;

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
    /// The proxy TCP listener failed to bind to the requested port.
    /// Another service might be using the port. Stop the conflicting service.
    #[error("TCP Listener failed to bind proxy to {0} or [::1] on port {1}")]
    BindFailed(String, u16),

    /// The proxy successfully bound to IPv6 loopback but failed on IPv4.
    /// IPv4 loopback might be disabled or in use. Proxy is partially functional.
    #[error("Failed to bind Proxy to {0}, successfully bound to IPv6 loopback [::1] (Case 198)")]
    BindIpv6Only(String),

    /// An active proxy connection was dropped unexpectedly by the client or tunnel.
    /// Check the client browser or the tunnel stability.
    #[error("Proxy connection dropped unexpectedly: {0}")]
    ConnectionDropped(String),

    /// A proxy request was received for a domain that does not end in `.kin`.
    /// The proxy is strictly for `.kin` names. The request was dropped.
    #[error("Rejected proxy request for non-.kin name: {0}")]
    NonKinName(String),

    /// An error occurred while establishing a CONNECT tunnel for HTTPS traffic.
    /// The backend target might be down or unreachable.
    #[error("CONNECT tunnel error: {0}")]
    ConnectTunnelError(String),

    /// The proxy failed to upgrade the HTTP connection (e.g. for WebSockets or CONNECT).
    /// Ensure the client supports standard HTTP upgrades.
    #[error("Upgrade error: {0}")]
    UpgradeError(String),

    /// A generic proxy request failed at the HTTP layer.
    /// The target server might have returned an invalid HTTP response.
    #[error("Proxy request failed: {0}")]
    RequestFailed(String),

    /// The DHT failed to resolve the `.kin` apex name.
    /// The name might not exist or the network is partitioned.
    #[error("DHT resolution failed for apex name '{0}': {1}")]
    DhtResolutionFailed(String, String),

    /// The resolved DHT record failed cryptographic signature verification.
    /// A malicious peer attempted to spoof the DNS response. The record was dropped.
    #[error(
        "Security violation! NameRecord signature verification failed (Spoofed DHT response): {0}"
    )]
    SignatureVerificationFailed(String),

    /// The proxy failed to deserialize the NameRecord JSON payload from the DHT.
    /// The record publisher used an invalid schema version.
    #[error("Failed to deserialize NameRecord JSON from DHT for '{0}': {1}")]
    NameRecordDeserializationFailed(String, String),

    /// The NRS Zone payload within the NameRecord was invalid or corrupt.
    /// The record publisher uploaded malformed zone data.
    #[error("Invalid NrsZone payload: {0}")]
    InvalidNrsZonePayload(String),

    /// The requested subname was not found in the resolved NRS Zone.
    /// Ensure the subname is correctly configured in the zone file.
    #[error("Subname '{0}' not found in zone")]
    SubnameNotFound(String),

    /// The NRS Zone contained no routable targets for the requested name.
    /// The name exists but does not point to an IP or PeerID.
    #[error("No routable targets found in NrsZone for name '{0}'")]
    NoRoutableTargets(String),

    /// The DHT payload contained an unrecognized target format.
    /// Ensure the target is a valid IPv4, IPv6, or Libp2p PeerID.
    #[error("Unrecognized target format in DHT payload for '{0}': {1}")]
    UnrecognizedTargetFormat(String, String),

    /// The configured IP target in the NRS Zone had an invalid format.
    /// Check the zone configuration for syntax errors.
    #[error("Invalid IP format for name '{0}': {1}")]
    InvalidIpFormat(String, String),

    /// The proxy failed to reach the IP gateway specified in the zone.
    /// The target server is offline or blocking traffic.
    #[error("Failed to reach IP gateway: {0}")]
    IpGatewayUnreachable(String),

    /// The HostRoutingRecord returned an invalid Libp2p PeerId.
    /// Ensure the base58 encoded PeerId in the zone is correct.
    #[error("HostRoutingRecord returned invalid PeerId: {0}")]
    InvalidPeerId(String),

    /// The proxy failed to read the body stream of the incoming P2P request.
    /// The client dropped the connection prematurely.
    #[error("Failed to read P2P request body stream: {0}")]
    P2pRequestBodyReadFailed(String),

    /// The Libp2p tunnel failed to reach the target peer.
    /// The peer might be offline or NAT traversal failed.
    #[error("Libp2p tunnel failed to reach target peer: {0}")]
    Libp2pTunnelFailed(String),

    /// The proxy failed to construct an HTTP response from the P2P tunnel data.
    /// The target peer returned malformed HTTP data.
    #[error("Failed to construct HTTP response from P2P tunnel data: {0}")]
    HttpResponseConstructionFailed(String),

    /// A failure occurred while forwarding data through the proxy tunnel.
    /// The stream was abruptly closed.
    #[error("Tunnel Forwarding error: {0}")]
    TunnelForwardingError(String),

    /// Failed to forward a P2P request to the local backend web server.
    /// The host's local web server is offline or rejecting connections.
    #[error("Bad Gateway: Local web server not responding on port {0}\nError: {1}")]
    LocalWebServerForwardingFailed(u16, String),

    /// DNS name could not be found.
    #[error("Name not found: {0}")]
    NameNotFound(String),

    /// The payload format is invalid.
    #[error("{0}")]
    InvalidPayload(String),

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

impl ProxyError {
    /// Returns the stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BindFailed(..) => "KIN-PRX-001",
            Self::BindIpv6Only(_) => "KIN-PRX-002",
            Self::ConnectionDropped(_) => "KIN-PRX-003",
            Self::NonKinName(_) => "KIN-PRX-004",
            Self::ConnectTunnelError(_) => "KIN-PRX-005",
            Self::UpgradeError(_) => "KIN-PRX-006",
            Self::RequestFailed(_) => "KIN-PRX-007",
            Self::DhtResolutionFailed(..) => "KIN-PRX-008",
            Self::SignatureVerificationFailed(_) => "KIN-PRX-009",
            Self::NameRecordDeserializationFailed(..) => "KIN-PRX-010",
            Self::InvalidNrsZonePayload(_) => "KIN-PRX-011",
            Self::SubnameNotFound(_) => "KIN-PRX-012",
            Self::NoRoutableTargets(_) => "KIN-PRX-013",
            Self::UnrecognizedTargetFormat(..) => "KIN-PRX-014",
            Self::InvalidIpFormat(..) => "KIN-PRX-015",
            Self::IpGatewayUnreachable(_) => "KIN-PRX-016",
            Self::InvalidPeerId(_) => "KIN-PRX-017",
            Self::P2pRequestBodyReadFailed(_) => "KIN-PRX-018",
            Self::Libp2pTunnelFailed(_) => "KIN-PRX-019",
            Self::HttpResponseConstructionFailed(_) => "KIN-PRX-020",
            Self::TunnelForwardingError(_) => "KIN-PRX-021",
            Self::LocalWebServerForwardingFailed(..) => "KIN-PRX-022",
            Self::NameNotFound(_) => "KIN-PRX-023",
            Self::InvalidPayload(_) => "KIN-PRX-024",
            Self::Hyper(_) => "KIN-PRX-025",
            Self::Reqwest(_) => "KIN-PRX-026",
            Self::Io(_) => "KIN-PRX-027",
            Self::Ca(_) => "KIN-PRX-028",
            Self::Http(_) => "KIN-PRX-029",
            Self::PeerUnreachable(_) => "KIN-PRX-030",
            Self::SecurityViolation(_) => "KIN-PRX-031",
            Self::Other(_) => "KIN-PRX-032",
        }
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
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
            let err = ProxyError::BindIpv6Only(bind_ip.to_string());
            tracing::warn!(error_code = err.code(), "{}", err);
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| {
        let err = ProxyError::BindFailed(bind_ip.to_string(), port);
        tracing::error!(error_code = err.code(), "{}", err);
        anyhow::anyhow!(err)
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
                let err = ProxyError::ConnectionDropped(err.to_string());
                warn!(error_code = err.code(), "{}", err);
            }
        });
    }
}

#[cfg(test)]
mod proxy_tests;
