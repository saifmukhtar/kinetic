//! Asynchronous commands sent from client tasks to the background network event loop.

use crate::client::types::{ProxyError, ProxyRequest, ProxyResponse};
use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Represents commands sent from the client task to the network event loop.
#[derive(Debug)]
pub enum Command {
    /// Get the current drand kyn kyn from the event loop state.
    GetCurrentKyn {
        /// Channel to return the kyn.
        responder: oneshot::Sender<u64>,
    },
    /// Publish a record to the DHT redundantly.
    PublishRedundant {
        /// The name under which to publish.
        name: Arc<str>,
        /// The serialized payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    /// Initiate a Kademlia bootstrap to join the network.
    Bootstrap {
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), NetworkClientError>>,
    },
    /// Publish a heartbeat to maintain apex ownership.
    PublishHeartbeat {
        /// The apex name.
        name: Arc<str>,
        /// The heartbeat payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    /// Resolve an apex name from the DHT redundantly.
    ResolveRedundant {
        /// The apex name.
        name: Arc<str>,
        /// Channel to return the resolved payload.
        responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    },
    /// Resolve a heartbeat payload from the DHT redundantly.
    ResolveHeartbeat {
        /// The apex name.
        name: Arc<str>,
        /// Channel to return the resolved heartbeat payload.
        responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    },
    /// Verify that a record has been replicated to a quorum of nodes.
    VerifyQuorum {
        /// The apex name.
        name: Arc<str>,
        /// The expected payload to verify.
        payload: Vec<u8>,
        /// Channel to return the number of nodes reporting the correct payload.
        responder: oneshot::Sender<std::result::Result<usize, NetworkClientError>>,
    },
    /// Send a request to a remote proxy node.
    SendProxyRequest {
        /// The remote peer ID.
        peer: libp2p::PeerId,
        /// The proxy request payload.
        req: Box<ProxyRequest>,
        /// Channel to return the proxy response.
        responder: oneshot::Sender<std::result::Result<ProxyResponse, ProxyError>>,
    },
    /// Send a response back to a requesting proxy client.
    SendProxyResponse {
        /// The channel associated with the incoming request.
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        /// The proxy response payload.
        res: Box<ProxyResponse>,
    },
    /// Retrieve diagnostic network status information.
    GetNetworkStatus {
        /// Channel to return the status JSON.
        responder: oneshot::Sender<std::result::Result<serde_json::Value, NetworkClientError>>,
    },
    /// Subscribe to a Gossipsub topic.
    SubscribeGossip {
        /// The topic string.
        topic: Arc<str>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), NetworkClientError>>,
    },
    /// Broadcast a message to a Gossipsub topic.
    BroadcastGossip {
        /// The topic string.
        topic: Arc<str>,
        /// The serialized payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), NetworkClientError>>,
    },
    /// Report the result of application-level validation for a gossipsub message.
    ReportGossipValidation {
        /// The message ID.
        message_id: libp2p::gossipsub::MessageId,
        /// The source peer who sent the message.
        propagation_source: libp2p::PeerId,
        /// Whether the message should be accepted or rejected.
        acceptance: libp2p::gossipsub::MessageAcceptance,
    },
    /// Retrieve a list of all currently connected Peer IDs.
    GetConnectedPeers {
        /// Channel to return the list of Peer IDs.
        responder: oneshot::Sender<std::result::Result<Vec<String>, NetworkClientError>>,
    },
    /// Retrieve a list of active Gossipsub topics.
    GetGossipTopics {
        /// Channel to return the list of topics.
        responder: oneshot::Sender<std::result::Result<Vec<String>, NetworkClientError>>,
    },
    /// Retrieve a list of all currently banned Peer IDs.
    GetBannedPeers {
        /// Channel to return a list of (PeerId, ExpirationKyn).
        responder: oneshot::Sender<std::result::Result<Vec<(String, u64)>, NetworkClientError>>,
    },
    /// Send a request to a remote node to sync governance state.
    SendActionSyncRequest {
        /// The remote peer ID.
        peer: libp2p::PeerId,
        /// The gov sync request payload.
        req: Box<kinetic_types::action::ActionSyncRequest>,
        /// Channel to return the gov sync response.
        responder: oneshot::Sender<std::result::Result<kinetic_types::action::ActionSyncResponse, ProxyError>>,
    },
    /// Update the local cache of the governance action log.
    UpdateActionLog {
        /// The latest list of executed governance actions.
        actions: Vec<kinetic_types::action::SignedGovernanceMessage>,
    },
}
