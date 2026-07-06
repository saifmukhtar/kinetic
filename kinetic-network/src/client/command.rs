use crate::client::types::{ProxyError, ProxyRequest, ProxyResponse};
use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use tokio::sync::oneshot;

/// Represents commands sent from the client task to the network event loop.
#[derive(Debug)]
pub enum Command {
    /// Publish a record to the DHT redundantly.
    PublishRedundant {
        /// The name under which to publish.
        name: String,
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
        name: String,
        /// The heartbeat payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    /// Resolve a domain name from the DHT redundantly.
    ResolveRedundant {
        /// The domain name.
        name: String,
        /// Channel to return the resolved payload.
        responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    },
    /// Verify that a record has been replicated to a quorum of nodes.
    VerifyQuorum {
        /// The domain name.
        name: String,
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
        request: ProxyRequest,
        /// Channel to return the proxy response.
        responder: oneshot::Sender<std::result::Result<ProxyResponse, ProxyError>>,
    },
    /// Send a response back to a requesting proxy client.
    SendProxyResponse {
        /// The channel associated with the incoming request.
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        /// The proxy response payload.
        response: ProxyResponse,
    },
    /// Retrieve diagnostic network status information.
    GetNetworkStatus {
        /// Channel to return the status JSON.
        responder: oneshot::Sender<std::result::Result<serde_json::Value, NetworkClientError>>,
    },
    /// Subscribe to a Gossipsub topic.
    SubscribeGossip {
        /// The topic string.
        topic: String,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), NetworkClientError>>,
    },
    /// Broadcast a message to a Gossipsub topic.
    BroadcastGossip {
        /// The topic string.
        topic: String,
        /// The serialized payload.
        payload: Vec<u8>,
        /// Channel to return the result.
        responder: oneshot::Sender<std::result::Result<(), NetworkClientError>>,
    },
}
