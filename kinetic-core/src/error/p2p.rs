//! P2P Swarm and Mesh connection error types (`KIN-P2P-NNN`).
//!
//! Errors produced by the event loop regarding peer connections, bans, routing,
//! limits, and mesh stability. These are typically logged as warnings during normal
//! P2P operation and are not returned to end-users via APIs.

use super::Severity;
use thiserror::Error;

/// P2P Swarm and Mesh connection error types.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum P2pError {
    /// A DNS seed returned a multiaddr that is unroutable.
    /// Ensure DNS seeds only return valid, publicly routable multiaddrs.
    #[error("Rejected unroutable DNS seed multiaddr: {0}")]
    UnroutableSeedMultiaddr(String),

    /// The node lost all peer connections and is isolated.
    /// Check internet connection. The node will aggressively redial bootstrap nodes.
    #[error("0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...")]
    ZeroPeersDetected,

    /// A peer spammed the node with invalid gossip messages.
    /// The peer is operating maliciously or on an incompatible protocol version. It has been banned.
    #[error("Peer {0} sent 3 invalid gossip messages within 60s — disconnecting and banning")]
    GossipSpamBan(String),

    /// A peer spammed the node with invalid DHT records.
    /// The peer is operating maliciously. It has been banned.
    #[error("Peer {0} sent 3 invalid records within 60s — disconnecting and banning")]
    RecordSpamBan(String),

    /// A light node failed the proof-of-work handshake when the node was at capacity.
    /// The node disconnected the light node to preserve connection slots for full nodes.
    #[error("Light Node limit reached. Peer {0} failed PoW, disconnecting them to prevent connection slot exhaustion")]
    LightNodePowFailureLimit(String),

    /// A single identifier attempted to multiplex too many light client connections.
    /// The node enforces a maximum of 3 light clients per identity to prevent Sybil exhaustion.
    #[error("Identifier {0} exceeded limit of 3 light clients. Disconnecting peer {1}.")]
    LightNodeIdentityLimit(String, String),

    /// A quorum verification was attempted while the node had no peers.
    /// The operation failed fast. The node must discover peers before verifying quorums.
    #[error("Offline mode: Failing fast for VerifyQuorum (0 peers)")]
    OfflineVerifyQuorum,

    /// The node failed to bind to the mDNS port for local peer discovery.
    /// Ensure port 5353 is available. Local peer discovery will remain disabled.
    #[error("Failed to bind mDNS: {0}. Local peer discovery disabled.")]
    MdnsBindFailed(String),

    /// The gossipsub message semaphore is saturated due to extreme load.
    /// Messages are being aggressively dropped to prevent memory exhaustion.
    #[error("Gossip semaphore saturated — dropping message from {0} on topic {1}")]
    GossipSemaphoreSaturated(String, String),

    /// A light node incorrectly attempted a DHT Write operation.
    /// Light nodes do not have Write privileges. The peer was disconnected.
    #[error("Light node {0} attempted to PutRecord (Write). Rejecting and disconnecting.")]
    LightNodeWriteRejected(String),

    /// A peer spammed Kademlia with invalid routing records.
    /// The peer is attempting to pollute the routing table. It has been banned.
    #[error("Peer {0} sent 3 invalid records within 60s — disconnecting and banning")]
    KademliaRecordSpamBan(String),

    /// An outgoing connection to a peer failed.
    /// The peer may be offline, behind a NAT, or blocking traffic.
    #[error("Outgoing connection error to peer {0}: {1}")]
    OutgoingConnectionError(String, String),

    /// The node failed to dial a critical bootstrap node.
    /// Ensure the bootstrap node is online and its multiaddr is correct.
    #[error("Failed to dial bootstrap node {0}: {1}")]
    BootstrapDialFailed(String, String),

    /// A previously banned peer attempted to reconnect.
    /// The connection was aggressively dropped at the transport layer.
    #[error("Banned peer {0} attempted to connect, disconnecting immediately.")]
    BannedPeerConnectionAttempt(String),

    /// A bootstrap peer failed to provide a valid Proof of Work handshake.
    /// The connection was kept alive for 24 hours but is now being reaped.
    #[error("Bootstrap peer {0} failed to provide valid PoW after 24 hours. Disconnecting.")]
    BootstrapPowTimeout(String),
}

impl P2pError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnroutableSeedMultiaddr(_) => "KIN-P2P-001",
            Self::ZeroPeersDetected => "KIN-P2P-002",
            Self::GossipSpamBan(_) => "KIN-P2P-003",
            Self::RecordSpamBan(_) => "KIN-P2P-004",
            Self::LightNodePowFailureLimit(_) => "KIN-P2P-005",
            Self::LightNodeIdentityLimit(..) => "KIN-P2P-006",
            Self::OfflineVerifyQuorum => "KIN-P2P-007",
            Self::MdnsBindFailed(_) => "KIN-P2P-008",
            Self::GossipSemaphoreSaturated(..) => "KIN-P2P-009",
            Self::LightNodeWriteRejected(_) => "KIN-P2P-010",
            Self::KademliaRecordSpamBan(_) => "KIN-P2P-011",
            Self::OutgoingConnectionError(..) => "KIN-P2P-012",
            Self::BootstrapDialFailed(..) => "KIN-P2P-013",
            Self::BannedPeerConnectionAttempt(_) => "KIN-P2P-014",
            Self::BootstrapPowTimeout(_) => "KIN-P2P-015",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::ZeroPeersDetected | Self::OfflineVerifyQuorum | Self::GossipSemaphoreSaturated(..) => Severity::Error,
            _ => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::UnroutableSeedMultiaddr(_) => "Rejected unroutable DNS seed multiaddr.".to_string(),
            Self::ZeroPeersDetected => "0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...".to_string(),
            Self::GossipSpamBan(_) => "Peer sent too many invalid gossip messages and was banned.".to_string(),
            Self::RecordSpamBan(_) | Self::KademliaRecordSpamBan(_) => "Peer sent too many invalid records and was banned.".to_string(),
            Self::LightNodePowFailureLimit(_) => "Light Node limit reached; disconnected peer without valid PoW.".to_string(),
            Self::LightNodeIdentityLimit(..) => "Identifier exceeded limit of 3 light clients; disconnected peer.".to_string(),
            Self::OfflineVerifyQuorum => "Offline mode: Failing fast for VerifyQuorum (0 peers).".to_string(),
            Self::MdnsBindFailed(_) => "Failed to bind mDNS. Local peer discovery disabled.".to_string(),
            Self::GossipSemaphoreSaturated(..) => "Gossip semaphore saturated — dropping message.".to_string(),
            Self::LightNodeWriteRejected(_) => "Light node attempted to Write. Rejecting and disconnecting.".to_string(),
            Self::OutgoingConnectionError(..) => "Outgoing connection error to peer.".to_string(),
            Self::BootstrapDialFailed(..) => "Failed to dial bootstrap node.".to_string(),
            Self::BannedPeerConnectionAttempt(_) => "Banned peer attempted to connect; disconnected immediately.".to_string(),
            Self::BootstrapPowTimeout(_) => "Bootstrap peer failed to provide valid PoW after 24 hours. Disconnecting.".to_string(),
        }
    }
}
