use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    Other(String),
}

/// A request to be proxied to a remote node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// The HTTP method (e.g. GET, POST).
    pub method: String,
    /// The request path.
    pub path: String,
    /// Key-value headers.
    pub headers: HashMap<String, String>,
    /// Request body payload.
    pub body: Vec<u8>,
}

/// A response received from a proxy request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Key-value headers.
    pub headers: HashMap<String, String>,
    /// Response body payload.
    pub body: Vec<u8>,
}

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
    /// The multiaddr string to listen on.
    pub listen_addr: String,
    /// Known bootstrap nodes to connect to at startup.
    pub bootstrap_nodes: Vec<String>,
    /// Pre-known domain seeds.
    pub seed_domains: Vec<String>,
    /// Whether to enable local mDNS discovery.
    pub enable_mdns: bool,
    /// The initial drand pulse round to use for VDF verification.
    pub initial_drand_pulse: u64,
    /// An optional externally reachable IP or domain to announce.
    pub external_address: Option<String>,
}
