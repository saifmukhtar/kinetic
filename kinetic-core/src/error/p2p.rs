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
    /// A DNS seed returned a multiaddr that is unroutable (e.g., localhost, private IP).
    /// The node queries bootstrap DNS seeds to find peers, but the seed provided an address that cannot be dialed over the public internet.
    /// Ensure DNS seeds only return valid, publicly routable multiaddrs or update your config to ignore bad seeds.
    #[error("Rejected unroutable DNS seed multiaddr: {0}")]
    UnroutableSeedMultiaddr(String),

    /// The node lost all peer connections and is isolated from the P2P mesh.
    /// The local internet connection dropped, or all connected peers went offline simultaneously.
    /// Check your internet connection. The node will aggressively redial bootstrap nodes in the background to automatically recover.
    #[error("0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...")]
    ZeroPeersDetected,

    /// A peer spammed the node with invalid GossipSub messages.
    /// The peer is operating maliciously, running an incompatible protocol version, or has severe clock drift.
    /// The offending peer has been banned. No action is required unless this happens constantly, which may indicate a network-wide attack.
    #[error("Peer {0} sent 3 invalid gossip messages within 60s — disconnecting and banning")]
    GossipSpamBan(String),

    /// A peer spammed the node with invalid DHT records.
    /// The peer is attempting to pollute the network with bad data or is operating maliciously.
    /// The offending peer has been banned. No action is required.
    #[error("Peer {0} sent 3 invalid records within 60s — disconnecting and banning")]
    RecordSpamBan(String),

    /// A light node failed the proof-of-work handshake when the node was at maximum connection capacity.
    /// To prevent connection slot exhaustion during high load, the node disconnects unauthenticated light nodes.
    /// If you run a light client, ensure it correctly computes the PoW handshake before dialing full nodes.
    #[error(
        "Light Node limit reached. Peer {0} failed PoW, disconnecting them to prevent connection slot exhaustion"
    )]
    LightNodePowFailureLimit(String),

    /// A single cryptographic identifier attempted to multiplex too many light client connections.
    /// The node enforces a strict limit of 3 light clients per identity to prevent Sybil resource exhaustion.
    /// Disconnect redundant light clients using the same identity key, or generate distinct identities for each client.
    #[error("Identifier {0} exceeded limit of 3 light clients. Disconnecting peer {1}.")]
    LightNodeIdentityLimit(String, String),

    /// A quorum verification was attempted while the node had no peers.
    /// The node cannot verify network state or resolve conflicts if it is completely isolated from the mesh.
    /// Wait for the node to discover peers and sync the network state before attempting quorum operations.
    #[error("Offline mode: Failing fast for VerifyQuorum (0 peers)")]
    OfflineVerifyQuorum,

    /// The node failed to bind to the UDP port required for local mDNS peer discovery.
    /// Port 5353 is already in use by another application (like Avahi or Bonjour) on the host machine.
    /// Ensure port 5353 is available, or safely ignore this error if you do not need to discover peers on your local LAN.
    #[error("Failed to bind mDNS: {0}. Local peer discovery disabled.")]
    MdnsBindFailed(String),

    /// The internal GossipSub message semaphore is saturated due to extreme load.
    /// The node is receiving gossip messages faster than the event loop can process them, indicating severe network congestion.
    /// Messages are being aggressively dropped to prevent memory exhaustion. Consider allocating more CPU resources to the daemon.
    #[error("Gossip semaphore saturated — dropping message from {0} on topic {1}")]
    GossipSemaphoreSaturated(String, String),

    /// A light node incorrectly attempted a DHT Write (`PutRecord`) operation.
    /// By protocol design, light nodes do not have Write privileges and can only perform Read operations.
    /// The offending peer was immediately disconnected. Ensure your light client applications only emit Read queries.
    #[error("Light node {0} attempted to PutRecord (Write). Rejecting and disconnecting.")]
    LightNodeWriteRejected(String),

    /// A peer spammed the Kademlia routing table with invalid routing records.
    /// The peer is attempting an Eclipse attack or routing table pollution.
    /// The offending peer has been banned. No action is required.
    #[error("Peer {0} sent 3 invalid records within 60s — disconnecting and banning")]
    KademliaRecordSpamBan(String),

    /// An outgoing connection to a peer failed at the transport layer.
    /// The peer may have gone offline, is behind a restrictive NAT, or dropped the TCP connection.
    /// The network will automatically route around the failed peer. No action is required.
    #[error("Outgoing connection error to peer {0}: {1}")]
    OutgoingConnectionError(String, String),

    /// The node failed to dial a critical hardcoded bootstrap node.
    /// The bootstrap node is offline, its IP changed, or its multiaddr configuration is incorrect.
    /// Ensure your node has internet access. If the problem persists, check the official Kinetic docs for updated bootstrap addresses.
    #[error("Failed to dial bootstrap node {0}: {1}")]
    BootstrapDialFailed(String, String),

    /// A previously banned peer attempted to reconnect to the node.
    /// The malicious or incompatible peer is aggressively retrying the connection.
    /// The connection was dropped instantly at the transport layer to save resources. No action is required.
    #[error("Banned peer {0} attempted to connect, disconnecting immediately.")]
    BannedPeerConnectionAttempt(String),

    /// A bootstrap peer failed to provide a valid Proof of Work handshake.
    /// The connection was kept alive for 24 hours (a grace period for bootstrap nodes) but the peer never authenticated.
    /// The connection is now being reaped. No action is required.
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
            Self::ZeroPeersDetected
            | Self::OfflineVerifyQuorum
            | Self::GossipSemaphoreSaturated(..) => Severity::Error,
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
            Self::UnroutableSeedMultiaddr(_) => {
                "Rejected unroutable DNS seed multiaddr.".to_string()
            }
            Self::ZeroPeersDetected => {
                "0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh..."
                    .to_string()
            }
            Self::GossipSpamBan(_) => {
                "Peer sent too many invalid gossip messages and was banned.".to_string()
            }
            Self::RecordSpamBan(_) | Self::KademliaRecordSpamBan(_) => {
                "Peer sent too many invalid records and was banned.".to_string()
            }
            Self::LightNodePowFailureLimit(_) => {
                "Light Node limit reached; disconnected peer without valid PoW.".to_string()
            }
            Self::LightNodeIdentityLimit(..) => {
                "Identifier exceeded limit of 3 light clients; disconnected peer.".to_string()
            }
            Self::OfflineVerifyQuorum => {
                "Offline mode: Failing fast for VerifyQuorum (0 peers).".to_string()
            }
            Self::MdnsBindFailed(_) => {
                "Failed to bind mDNS. Local peer discovery disabled.".to_string()
            }
            Self::GossipSemaphoreSaturated(..) => {
                "Gossip semaphore saturated — dropping message.".to_string()
            }
            Self::LightNodeWriteRejected(_) => {
                "Light node attempted to Write. Rejecting and disconnecting.".to_string()
            }
            Self::OutgoingConnectionError(..) => "Outgoing connection error to peer.".to_string(),
            Self::BootstrapDialFailed(..) => "Failed to dial bootstrap node.".to_string(),
            Self::BannedPeerConnectionAttempt(_) => {
                "Banned peer attempted to connect; disconnected immediately.".to_string()
            }
            Self::BootstrapPowTimeout(_) => {
                "Bootstrap peer failed to provide valid PoW after 24 hours. Disconnecting."
                    .to_string()
            }
        }
    }
}
