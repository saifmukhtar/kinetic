//! Type definitions and configuration structures for network client operations and P2P proxying.

use thiserror::Error;

/// Errors that can occur during proxy request/response handling.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Request timed out before receiving a response.
    #[error("Request timed out")]
    Timeout,
    /// The target peer is offline or cannot be routed to.
    #[error("Peer is offline or unreachable")]
    Offline,
    /// The underlying stream or connection was closed prematurely.
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
    /// The peer does not support the proxy protocol.
    #[error("Unsupported protocol")]
    UnsupportedProtocols,
    /// Internal channel error between the client task and event loop.
    #[error("Internal channel error")]
    ChannelClosed,
    /// Miscellaneous or unclassified error.
    #[error("Other error: {0}")]
    Other(std::borrow::Cow<'static, str>),
}

pub use kinetic_types::proxy::{ProxyRequest, ProxyResponse, serde_bytes_wrapper};

/// The mode in which the network daemon operates.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkMode {
    /// Fully participates in the DHT and gossip protocols.
    FullNode,
    /// Client-only mode; issues requests but does not store DHT records.
    LightClient,
}

/// Configuration settings for instantiating the network swarm.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Operating mode (FullNode or LightClient).
    pub mode: NetworkMode,
    /// The multiaddrs to listen on for TCP/IP traffic.
    pub listen_addrs: Vec<libp2p::Multiaddr>,
    /// The multiaddrs to listen on over QUIC transport.
    pub quic_listen_addrs: Vec<libp2p::Multiaddr>,
    /// Known bootstrap nodes to connect to at startup.
    pub bootstrap_nodes: Vec<libp2p::Multiaddr>,
    /// Pre-known domain seeds for DNS tree resolution.
    pub seed_domain: Vec<std::sync::Arc<str>>,
    /// Whether to enable local mDNS discovery.
    pub enable_mdns: bool,
    /// The initial drand pulse round to use for VDF verification.
    pub initial_drand_pulse: u64,
    /// An optional externally reachable IP or domain to announce.
    pub external_address: Option<libp2p::Multiaddr>,
    /// Bypass PoW verification for tests.
    pub disable_pow: bool,
    /// The maximum number of reveals a node will accept into the cache per hour (Rate Limiting).
    pub max_reveals_per_hour: usize,
    /// The maximum number of reveals to store in memory.
    pub lru_cache_size: std::num::NonZeroUsize,
}


