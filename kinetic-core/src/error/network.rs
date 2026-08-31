//! libp2p P2P network client error types (`KIN-RPC-NNN`).
//!
//! [`NetworkClientError`] is emitted by `KineticNetworkClient` operations. It transparently wraps
//! P2P network client error types (`KIN-RPC-NNN`).
//!
//! Emitted when interacting with the network overlay (`kinetic-network`).
//! This includes failures when Kademlia, GossipSub, or the internal mpsc command channel fails.
//!
//! # Note
//! - `KIN-RPC-001+`: This type (client-side P2P failures like GossipSub)
//! - `KIN-P2P-001+`: P2P connection and swarm management errors.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Errors originating from the Network Client (DHT, proxy, gossipsub)
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NetworkClientError {
    /// A DHT query or stream operation exceeded its deadline.
    /// The network is severely congested or the target peers are deliberately tarpitting connections.
    /// Check your internet connection or increase the timeout limit.
    #[error("Request timed out")]
    Timeout,
    /// The local node has no reachable peers.
    /// The P2P swarm is disconnected from the mesh and cannot route messages.
    /// Verify your internet connection and ensure bootstrap nodes are reachable.
    #[error("Node is offline or unreachable")]
    Offline,
    /// The Kademlia routing table contains no known peers.
    /// The node is online but hasn't successfully discovered any peers yet.
    /// Wait for the initial bootstrap process to complete.
    #[error("Routing table is empty")]
    RoutingTableEmpty,
    /// The internal mpsc/oneshot channel between the caller and the network loop was closed.
    /// The network loop crashed or the daemon is in the middle of a shutdown sequence.
    /// Check the daemon logs for panic traces in the P2P subsystem.
    #[error("Internal channel closed")]
    ChannelClosed,
    /// A GossipSub publish or subscribe operation failed.
    /// The node attempted to broadcast a message to a topic but failed, potentially due to missing peers.
    /// Wait for the mesh to fully form before broadcasting to GossipSub topics.
    #[error("Gossipsub error: {0}")]
    GossipSubError(String),
    /// A catch-all for miscellaneous network errors.
    /// An unexpected low-level P2P or TCP/QUIC stream error occurred.
    /// Examine the appended error string for more details.
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
