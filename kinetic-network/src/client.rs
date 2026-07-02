use anyhow::Result;
use kinetic_core::error::{PublishError, ResolutionError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Request timed out")]
    Timeout,
    #[error("Peer is offline or unreachable")]
    Offline,
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
    #[error("Unsupported protocol")]
    UnsupportedProtocols,
    #[error("Internal channel error")]
    ChannelClosed,
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkMode {
    FullNode,
    LightClient,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    pub listen_addr: String,
    pub bootstrap_nodes: Vec<String>,
    pub seed_domains: Vec<String>,
    pub enable_mdns: bool,
    pub initial_drand_pulse: u64,
    pub external_address: Option<String>,
}

#[derive(Debug)]
pub enum Command {
    PublishRedundant {
        name: String,
        payload: Vec<u8>,
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    /// Re-run the Kademlia bootstrap process. Useful for mobile clients
    /// waking up from OS background suspension.
    Bootstrap {
        responder: oneshot::Sender<Result<()>>,
    },
    /// Publish a heartbeat to the *heartbeat* keyspace (separate from the Reveal keyspace)
    /// so liveness signals never overwrite or pollute DNS resolution records.
    PublishHeartbeat {
        name: String,
        payload: Vec<u8>,
        responder: oneshot::Sender<std::result::Result<(), PublishError>>,
    },
    ResolveRedundant {
        name: String,
        responder: oneshot::Sender<std::result::Result<Vec<u8>, ResolutionError>>,
    },
    VerifyQuorum {
        name: String,
        payload: Vec<u8>,
        responder: oneshot::Sender<Result<usize>>,
    },
    SendProxyRequest {
        peer: libp2p::PeerId,
        request: ProxyRequest,
        responder: oneshot::Sender<std::result::Result<ProxyResponse, ProxyError>>,
    },
    SendProxyResponse {
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        response: ProxyResponse,
    },
    GetNetworkStatus {
        responder: oneshot::Sender<Result<serde_json::Value>>,
    },
}

#[derive(Clone)]
pub struct NetworkClient {
    sender: mpsc::Sender<Command>,
}

impl NetworkClient {
    pub fn new(sender: mpsc::Sender<Command>) -> Self {
        Self { sender }
    }

    pub async fn send_proxy_request(
        &self,
        peer: libp2p::PeerId,
        request: ProxyRequest,
    ) -> std::result::Result<ProxyResponse, ProxyError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Command::SendProxyRequest {
                peer,
                request,
                responder: tx,
            })
            .await
            .map_err(|_| ProxyError::ChannelClosed)?;
        rx.await.unwrap_or(Err(ProxyError::ChannelClosed))
    }

    pub async fn send_proxy_response(
        &self,
        channel: libp2p::request_response::ResponseChannel<ProxyResponse>,
        response: ProxyResponse,
    ) -> Result<()> {
        self.sender
            .send(Command::SendProxyResponse { channel, response })
            .await?;
        Ok(())
    }

    pub async fn publish_redundant_payload(
        &self,
        name: &str,
        payload_bytes: Vec<u8>,
    ) -> std::result::Result<(), PublishError> {
        if payload_bytes.len() > 2000 {
            return Err(PublishError::Internal {
                message: format!("Payload size ({} bytes) exceeds the 2000-byte P2P network limit. Please compress or link to external storage.", payload_bytes.len()),
                source: None,
            });
        }
        let (tx, rx) = oneshot::channel();
        self.sender
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
        self.sender
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

    pub async fn resolve_redundant_payload(
        &self,
        name: &str,
    ) -> std::result::Result<Vec<u8>, ResolutionError> {
        let (tx, rx) = oneshot::channel();
        self.sender
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

    pub async fn verify_quorum(&self, name: &str, payload_bytes: Vec<u8>) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Command::VerifyQuorum {
                name: name.to_string(),
                payload: payload_bytes,
                responder: tx,
            })
            .await?;
        rx.await?
    }

    pub async fn get_network_status(&self) -> Result<serde_json::Value> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Command::GetNetworkStatus { responder: tx })
            .await?;
        rx.await?
    }

    pub async fn rebootstrap_network(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Command::Bootstrap { responder: tx })
            .await?;
        rx.await?
    }

    pub async fn publish_host_routing_record(
        &self,
        record: kinetic_core::types::HostRoutingRecord,
    ) -> Result<()> {
        let key = format!("host_route_{}", record.host_id);
        let bytes = serde_json::to_vec(&record)?;
        self.publish_redundant_payload(&key, bytes).await?;
        Ok(())
    }

    pub async fn resolve_host_routing_record(
        &self,
        host_id: &str,
    ) -> Result<Option<kinetic_core::types::HostRoutingRecord>> {
        let key = format!("host_route_{}", host_id);
        match self.resolve_redundant_payload(&key).await {
            Ok(bytes) => {
                let record = serde_json::from_slice(&bytes)?;
                Ok(Some(record))
            }
            Err(ResolutionError::NotFound { .. }) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Resolution error: {}", e)),
        }
    }
}
