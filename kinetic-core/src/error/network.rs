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
    /// The remote peer closed the stream before the response was fully delivered.
    #[error("Stream dropped by peer")]
    StreamDropped,
    /// The remote peer does not speak the requested Kinetic protocol version.
    #[error("Unsupported protocol")]
    UnsupportedProtocol,
    /// A GossipSub publish or subscribe operation failed.
    #[error("Gossipsub error: {0}")]
    GossipSubError(String),
    /// The Kademlia record store rejected a `PUT` or returned an error for a `GET`.
    #[error("Kademlia store error: {0}")]
    StoreError(String),
    /// A catch-all for miscellaneous network errors.
    #[error("Other network error: {0}")]
    Other(String),
}

impl NetworkClientError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "KIN-NET-001",
            Self::Offline => "KIN-NET-002",
            Self::RoutingTableEmpty => "KIN-NET-003",
            Self::ChannelClosed => "KIN-NET-004",
            Self::StreamDropped => "KIN-NET-005",
            Self::UnsupportedProtocol => "KIN-NET-006",
            Self::GossipSubError(_) => "KIN-NET-007",
            Self::StoreError(_) => "KIN-NET-008",
            Self::Other(_) => "KIN-NET-009",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Timeout
            | Self::Offline
            | Self::RoutingTableEmpty
            | Self::ChannelClosed
            | Self::StreamDropped
            | Self::GossipSubError(_) => Severity::Warning,
            Self::UnsupportedProtocol | Self::StoreError(_) | Self::Other(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Offline | Self::RoutingTableEmpty | Self::StreamDropped
        )
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
