use crate::client::command::Command;
use crate::client::types::{ProxyError, ProxyRequest, ProxyResponse};
use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use tokio::sync::{mpsc, oneshot};

/// The primary handle used to interact with the background network event loop.
#[derive(Clone)]
pub struct NetworkClient {
    sender: std::sync::Arc<std::sync::RwLock<mpsc::Sender<Command>>>,
    stream_control: std::sync::Arc<std::sync::RwLock<Option<libp2p_stream::Control>>>,
}

impl NetworkClient {
    /// Creates a new network client handle.
    pub fn new(sender: mpsc::Sender<Command>, stream_control: libp2p_stream::Control) -> Self {
        Self {
            sender: std::sync::Arc::new(std::sync::RwLock::new(sender)),
            stream_control: std::sync::Arc::new(std::sync::RwLock::new(Some(stream_control))),
        }
    }

    /// Creates a mock network client for testing.
    pub fn new_mock(sender: mpsc::Sender<Command>) -> Self {
        Self {
            sender: std::sync::Arc::new(std::sync::RwLock::new(sender)),
            stream_control: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Hot-swaps the underlying channel sender, used during network resets.
    pub fn update_backend(
        &self,
        sender: mpsc::Sender<Command>,
        stream_control: Option<libp2p_stream::Control>,
    ) {
        if let Ok(mut s) = self.sender.write() {
            *s = sender;
        }
        if let Ok(mut c) = self.stream_control.write() {
            *c = stream_control;
        }
    }

    /// Gets a cloned copy of the command sender.
    pub fn get_sender(&self) -> mpsc::Sender<Command> {
        self.sender.read().unwrap().clone()
    }

    /// Gets a cloned copy of the stream control handle, if available.
    pub fn stream_control(&self) -> Option<libp2p_stream::Control> {
        if let Ok(guard) = self.stream_control.read() {
            guard.clone()
        } else {
            None
        }
    }

    /// Sends a proxy request to a remote peer and awaits the response.
    pub async fn send_proxy_request(
        &self,
        peer: libp2p::PeerId,
        request: ProxyRequest,
    ) -> std::result::Result<ProxyResponse, ProxyError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::SendProxyRequest {
                peer,
                request,
                responder: tx,
            })
            .await
            .map_err(|_| ProxyError::ChannelClosed)?;
        rx.await.unwrap_or(Err(ProxyError::ChannelClosed))
    }

    /// Sends a response back to an incoming proxy request.
    pub async fn send_proxy_response(
        &self,
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        response: ProxyResponse,
    ) -> std::result::Result<(), NetworkClientError> {
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::SendProxyResponse { channel, response })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        Ok(())
    }

    /// Publishes a payload redundantly to the DHT.
    pub async fn publish_redundant_payload(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), PublishError> {
        if payload_bytes.len() > 8000 {
            return Err(PublishError::Internal {
                message: format!("Payload size ({} bytes) exceeds the 8000-byte P2P network limit. Please compress or link to external storage.", payload_bytes.len()),
                source: None,
            });
        }
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::PublishRedundant {
                name: name.to_string(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| PublishError::Internal {
                message: "Network channel closed unexpectedly".to_string(),
                source: None,
            })?;
        rx.await.map_err(|_| PublishError::Internal {
            message: "Network channel closed unexpectedly".to_string(),
            source: None,
        })?
    }

    /// Publish a heartbeat liveness signal to the dedicated heartbeat keyspace.
    /// This must NOT be used for Reveals or other resolution data.
    pub async fn publish_heartbeat(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), PublishError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::PublishHeartbeat {
                name: name.to_string(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| PublishError::Internal {
                message: "Network channel closed unexpectedly".to_string(),
                source: None,
            })?;
        rx.await.map_err(|_| PublishError::Internal {
            message: "Network channel closed unexpectedly".to_string(),
            source: None,
        })?
    }

    /// Resolves a payload redundantly from the DHT.
    pub async fn resolve_redundant_payload(
        &self,
        name: &str,
    ) -> std::result::Result<Vec<u8>, ResolutionError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::ResolveRedundant {
                name: name.to_string(),
                responder: tx,
            })
            .await
            .map_err(|_| ResolutionError::Internal {
                message: "Network channel closed unexpectedly".to_string(),
                source: None,
            })?;
        rx.await.map_err(|_| ResolutionError::Internal {
            message: "Network channel closed unexpectedly".to_string(),
            source: None,
        })?
    }

    /// Verifies that a published record has reached a quorum of nodes.
    pub async fn verify_quorum(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<usize, NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::VerifyQuorum {
                name: name.to_string(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Retrieves diagnostic JSON status of the network.
    pub async fn get_network_status(
        &self,
    ) -> std::result::Result<serde_json::Value, NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::GetNetworkStatus { responder: tx })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Initiates a bootstrap sequence to rejoin the network.
    pub async fn rebootstrap_network(&self) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::Bootstrap { responder: tx })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Publishes a host routing record to the DHT.
    pub async fn publish_host_routing_record(
        &self,
        record: kinetic_core::types::HostRoutingRecord,
    ) -> std::result::Result<(), NetworkClientError> {
        let key = format!("host_route_{}", record.host_id);
        let bytes =
            serde_json::to_vec(&record).map_err(|e| NetworkClientError::Other(e.to_string()))?;
        self.publish_redundant_payload(&key, bytes)
            .await
            .map_err(|e| NetworkClientError::Other(e.to_string()))?;
        Ok(())
    }

    /// Resolves a host routing record from the DHT.
    pub async fn resolve_host_routing_record(
        &self,
        host_id: &str,
    ) -> std::result::Result<Option<kinetic_core::types::HostRoutingRecord>, NetworkClientError>
    {
        let key = format!("host_route_{}", host_id);
        match self.resolve_redundant_payload(&key).await {
            Ok(bytes) => {
                let record = serde_json::from_slice(&bytes)
                    .map_err(|e| NetworkClientError::Other(e.to_string()))?;
                Ok(Some(record))
            }
            Err(ResolutionError::NotFound { .. }) => Ok(None),
            Err(e) => Err(NetworkClientError::Other(e.to_string())),
        }
    }

    /// Subscribes to a Gossipsub topic.
    pub async fn subscribe_gossip(
        &self,
        topic: &str,
    ) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::SubscribeGossip {
                topic: topic.to_string(),
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Broadcasts a payload to a Gossipsub topic.
    pub async fn broadcast_gossip(
        &self,
        topic: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self.sender.read().unwrap().clone();
        sender_clone
            .send(Command::BroadcastGossip {
                topic: topic.to_string(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_network_client_hot_swap() {
        let (tx1, mut rx1) = mpsc::channel(32);
        let client = NetworkClient::new_mock(tx1);

        // Send a request to the first backend
        let client_clone = client.clone();
        tokio::spawn(async move {
            let _ = client_clone
                .publish_redundant_payload("test", vec![1, 2, 3])
                .await;
        });

        // Backend 1 receives it
        let cmd = rx1.recv().await.unwrap();
        match cmd {
            Command::PublishRedundant { name, .. } => assert_eq!(name, "test"),
            _ => panic!("Unexpected command"),
        }

        // Hot swap backend
        let (tx2, mut rx2) = mpsc::channel(32);
        client.update_backend(tx2, None);

        // Send a request to the second backend
        let client_clone2 = client.clone();
        tokio::spawn(async move {
            let _ = client_clone2
                .publish_redundant_payload("test2", vec![4, 5, 6])
                .await;
        });

        // Backend 2 receives it
        let cmd2 = rx2.recv().await.unwrap();
        match cmd2 {
            Command::PublishRedundant { name, .. } => assert_eq!(name, "test2"),
            _ => panic!("Unexpected command"),
        }
    }
}
