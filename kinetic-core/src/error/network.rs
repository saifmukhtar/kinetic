//! libp2p P2P network client error types (`KIN-RPC-NNN`).
//!
//! [`NetworkClientError`] is emitted by `KineticNetworkClient` operations. It transparently wraps
//! libp2p Kademlia, GossipSub, or the internal mpsc command channel fails.
//!
//! ## Namespace Note
//!
//! To avoid overlaps, network errors are strictly partitioned:
//! - `KIN-RPC-001+`: This type (client-side P2P failures like GossipSub)
//! - `KIN-DHT-001..099`: `KineticStoreError` (store-layer validations and rejections)
//!
//! Note that query-related failures (like timeouts or empty routing tables)
//! correctly return `KIN-QRY` codes, matching the global taxonomy.
//! This type is used internally within the event loop for command dispatch failures.

use super::Severity;
use thiserror::Error;

/// Errors originating from the Network Client (DHT, proxy, gossipsub)
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NetworkClientError {
    /// A DHT query or stream operation exceeded its deadline.
    #[error("Request timed out")]
    Timeout,
    /// The local node has no reachable peers.
    #[error("Node is offline or unreachable")]
    Offline,
    /// The Kademlia routing table contains no known peers.
    #[error("Routing table is empty")]
    RoutingTableEmpty,
    /// The internal mpsc/oneshot channel between the caller and the network loop was closed.
    #[error("Internal channel closed")]
    ChannelClosed,
    /// A GossipSub publish or subscribe operation failed.
    #[error("Gossipsub error: {0}")]
    GossipSubError(String),
    /// A catch-all for miscellaneous network errors.
    #[error("Other network error: {0}")]
    Other(String),
}

impl NetworkClientError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "KIN-QRY-005",
            Self::Offline => "KIN-QRY-001",
            Self::RoutingTableEmpty => "KIN-QRY-001",
            Self::ChannelClosed => "KIN-QRY-006",
            Self::GossipSubError(_) => "KIN-RPC-001",
            Self::Other(_) => "KIN-RPC-002",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Timeout
            | Self::Offline
            | Self::RoutingTableEmpty
            | Self::ChannelClosed
            | Self::GossipSubError(_) => Severity::Warning,
            Self::Other(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Offline | Self::RoutingTableEmpty
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Timeout => "The network request timed out.".to_string(),
            Self::Offline => "The node is offline or unreachable.".to_string(),
            Self::RoutingTableEmpty => "The Kademlia routing table is empty.".to_string(),
            Self::ChannelClosed => "Internal channel closed.".to_string(),
            Self::GossipSubError(_) => "A GossipSub operation failed.".to_string(),
            Self::Other(_) => "A network error occurred.".to_string(),
        }
    }
}
