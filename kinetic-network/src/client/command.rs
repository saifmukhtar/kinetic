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
    /// Publish a heartbeat to maintain domain ownership.
    PublishHeartbeat {
        /// The domain name.
        name: Arc<str>,
        /// The heartbeat payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    /// Resolve a domain name from the DHT redundantly.
    ResolveRedundant {
        /// The domain name.
        name: Arc<str>,
        /// Channel to return the resolved payload.
        responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    },
    /// Verify that a record has been replicated to a quorum of nodes.
    VerifyQuorum {
        /// The domain name.
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
        request: Box<ProxyRequest>,
        /// Channel to return the proxy response.
        responder: oneshot::Sender<std::result::Result<ProxyResponse, ProxyError>>,
    },
    /// Send a response back to a requesting proxy client.
    SendProxyResponse {
        /// The channel associated with the incoming request.
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        /// The proxy response payload.
        response: Box<ProxyResponse>,
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
}
