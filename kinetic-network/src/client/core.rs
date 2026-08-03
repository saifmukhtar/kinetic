//! Thread-safe `NetworkClient` handle for sending commands to the background P2P event loop.

use crate::client::command::Command;
use crate::client::types::{ProxyError, ProxyRequest, ProxyResponse};
use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use tokio::sync::{mpsc, oneshot};

/// The primary handle used to interact with the background network event loop.

#[derive(Clone)]
pub struct NetworkClient {
    sender: std::sync::Arc<std::sync::RwLock<mpsc::Sender<Command>>>,
    #[cfg(not(target_arch = "wasm32"))]
    stream_control: std::sync::Arc<std::sync::RwLock<Option<libp2p_stream::Control>>>,
}

impl NetworkClient {
    #[cfg(not(target_arch = "wasm32"))]
    /// Creates a new `Client` instance.
    pub fn new(sender: mpsc::Sender<Command>, stream_control: libp2p_stream::Control) -> Self {
        Self {
            sender: std::sync::Arc::new(std::sync::RwLock::new(sender)),
            stream_control: std::sync::Arc::new(std::sync::RwLock::new(Some(stream_control))),
        }
    }

    /// Create a new NetworkClient for WASM without stream control
    #[cfg(target_arch = "wasm32")]
    pub fn new(sender: mpsc::Sender<Command>) -> Self {
        Self {
            sender: std::sync::Arc::new(std::sync::RwLock::new(sender)),
        }
    }

    /// Creates a mock network client for testing.
    pub fn new_mock(sender: mpsc::Sender<Command>) -> Self {
        Self {
            sender: std::sync::Arc::new(std::sync::RwLock::new(sender)),
            #[cfg(not(target_arch = "wasm32"))]
            stream_control: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Hot-swaps the underlying channel sender, used during network resets.
    #[cfg(not(target_arch = "wasm32"))]
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

    /// Update the backend sender for WASM
    #[cfg(target_arch = "wasm32")]
    pub fn update_backend(&self, sender: mpsc::Sender<Command>) {
        if let Ok(mut s) = self.sender.write() {
            *s = sender;
        }
    }

    /// Gets a cloned copy of the command sender.
    pub fn get_sender(&self) -> mpsc::Sender<Command> {
        self.sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Gets a cloned copy of the stream control handle, if available.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn stream_control(&self) -> Option<libp2p_stream::Control> {
        if let Ok(guard) = self.stream_control.read() {
            guard.clone()
        } else {
            None
        }
    }

    /// Sends a proxy request to a remote peer and awaits the response.
    ///
    /// # Errors
    ///
    /// - Returns [`ProxyError::ChannelClosed`](crate::client::types::ProxyError::ChannelClosed) if the event loop task has terminated.
    /// - Returns [`ProxyError::Timeout`](crate::client::types::ProxyError::Timeout) if the request times out.
    pub async fn send_proxy_request(
        &self,
        peer: libp2p::PeerId,
        request: ProxyRequest,
    ) -> std::result::Result<ProxyResponse, ProxyError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::SendProxyRequest {
                peer,
                request: Box::new(request),
                responder: tx,
            })
            .await
            .map_err(|_| ProxyError::ChannelClosed)?;
        rx.await.unwrap_or(Err(ProxyError::ChannelClosed))
    }

    /// Sends a response back to an incoming proxy request.
    ///
    /// # Errors
    ///
    /// - Returns [`NetworkClientError::ChannelClosed`](kinetic_core::error::NetworkClientError::ChannelClosed) if the response channel cannot be sent to.
    pub async fn send_proxy_response(
        &self,
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        response: ProxyResponse,
    ) -> std::result::Result<(), NetworkClientError> {
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::SendProxyResponse {
                channel,
                response: Box::new(response),
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        Ok(())
    }

    /// Publishes a payload redundantly to the DHT.
    ///
    /// # Errors
    ///
    /// - Returns [`PublishError::Internal`](kinetic_core::error::PublishError::Internal) if the payload exceeds the 80 KB P2P network limit or the channel is closed.
    pub async fn publish_redundant_payload(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), PublishError> {
        // The core schema limit (MAX_PAYLOAD_SIZE) is 64 KB (65,536 bytes).
        // This client limit is deliberately set higher (80 KB) to safely accommodate
        // the 64 KB payload plus any cryptographic proofs (VDFs, signatures) and
        // structural serialization overhead without rejecting valid payloads.
        if payload_bytes.len() > 80_000 {
            return Err(PublishError::Internal {
                message: format!("Payload size ({} bytes) exceeds the 80000-byte P2P network limit. Please compress or link to external storage.", payload_bytes.len()),
                source: None,
            });
        }
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::PublishRedundant {
                name: name.to_string().into(),
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
    ///
    /// # Errors
    ///
    /// - Returns [`PublishError::Internal`](kinetic_core::error::PublishError::Internal) if the network channel is closed or communication fails.
    pub async fn publish_heartbeat(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), PublishError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::PublishHeartbeat {
                name: name.to_string().into(),
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
    ///
    /// # Errors
    ///
    /// Returns a `ResolutionError` if the item is not found or the channel is closed.
    pub async fn resolve_redundant_payload(
        &self,
        name: &str,
    ) -> std::result::Result<Vec<u8>, ResolutionError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::ResolveRedundant {
                name: name.to_string().into(),
                responder: tx,
            })
            .await
            .map_err(|_| ResolutionError::Internal {
                message: "Network channel closed unexpectedly".to_string(),
                source: None,
            })?;
        #[cfg(not(target_arch = "wasm32"))]
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(ResolutionError::Internal {
                message: "Network channel closed unexpectedly".to_string(),
                source: None,
            }),
            Err(_) => Err(ResolutionError::Internal {
                message: "Resolution timed out".to_string(),
                source: None,
            }),
        }
        #[cfg(target_arch = "wasm32")]
        {
            use futures::future::{select, Either};
            use futures_timer::Delay;
            match select(Box::pin(rx), Delay::new(std::time::Duration::from_secs(10))).await {
                Either::Left((Ok(res), _)) => res,
                Either::Left((Err(_), _)) => Err(ResolutionError::Internal {
                    message: "Network channel closed unexpectedly".to_string(),
                    source: None,
                }),
                Either::Right(_) => Err(ResolutionError::Internal {
                    message: "Resolution timed out".to_string(),
                    source: None,
                }),
            }
        }
    }

    /// Verifies that a published record has reached a quorum of nodes.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the network channel is closed.
    pub async fn verify_quorum(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<usize, NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::VerifyQuorum {
                name: name.to_string().into(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Retrieves diagnostic JSON status of the network.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the network channel is closed.
    pub async fn get_network_status(
        &self,
    ) -> std::result::Result<serde_json::Value, NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::GetNetworkStatus { responder: tx })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Initiates a bootstrap sequence to rejoin the network.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the network channel is closed.
    pub async fn rebootstrap_network(&self) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::Bootstrap { responder: tx })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Publishes a host routing record to the DHT.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if serialization fails or publishing the payload fails.
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

    /// Fetches the current drand kyn kyn from the event loop state.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the channel is closed.
    pub async fn get_current_drand_kyn(&self) -> Result<u64, NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::GetCurrentDrandKyn { responder: tx })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)
    }

    /// Resolves a host routing record from the DHT.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if resolution fails for reasons other than not found, or deserialization fails.
    pub async fn resolve_host_routing_record(
        &self,
        host_id: &str,
    ) -> std::result::Result<Option<kinetic_core::types::HostRoutingRecord>, NetworkClientError>
    {
        let current_drand_kyn = self.get_current_drand_kyn().await?;
        let key = format!("host_route_{}", host_id);
        match self.resolve_redundant_payload(&key).await {
            Ok(bytes) => {
                let record =
                    serde_json::from_slice::<kinetic_core::types::HostRoutingRecord>(&bytes)
                        .map_err(|e| NetworkClientError::Other(e.to_string()))?;
                crate::store::verification::verify_host_routing_record(&record, current_drand_kyn)
                    .map_err(|e| NetworkClientError::Other(e.to_string()))?;
                Ok(Some(record))
            }
            Err(ResolutionError::NotFound { .. }) => Ok(None),
            Err(e) => Err(NetworkClientError::Other(e.to_string())),
        }
    }

    /// Subscribes to a Gossipsub topic.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the network channel is closed.
    pub async fn subscribe_gossip(
        &self,
        topic: &str,
    ) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::SubscribeGossip {
                topic: topic.to_string().into(),
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Broadcasts a payload to a Gossipsub topic.
    ///
    /// # Errors
    ///
    /// Returns a `NetworkClientError` if the network channel is closed.
    pub async fn broadcast_gossip(
        &self,
        topic: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), NetworkClientError> {
        let (tx, rx) = oneshot::channel();
        let sender_clone = self
            .sender
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sender_clone
            .send(Command::BroadcastGossip {
                topic: topic.to_string().into(),
                payload: payload_bytes,
                responder: tx,
            })
            .await
            .map_err(|_| NetworkClientError::ChannelClosed)?;

        rx.await.map_err(|_| NetworkClientError::ChannelClosed)?
    }

    /// Report the validation result of a gossipsub message to the swarm.
    pub fn report_gossip_validation(
        &self,
        message_id: libp2p::gossipsub::MessageId,
        propagation_source: libp2p::PeerId,
        is_valid: bool,
    ) {
        let acceptance = if is_valid {
            libp2p::gossipsub::MessageAcceptance::Accept
        } else {
            libp2p::gossipsub::MessageAcceptance::Reject
        };
        if let Ok(guard) = self.sender.read() {
            let _ = guard.try_send(Command::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            });
        }
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
            Command::PublishRedundant { name, .. } => assert_eq!(&*name, "test"),
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
            Command::PublishRedundant { name, .. } => assert_eq!(&*name, "test2"),
            _ => panic!("Unexpected command"),
        }
    }
}
