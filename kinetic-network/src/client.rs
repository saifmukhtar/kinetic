use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

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
}

#[derive(Debug)]
pub enum Command {
    PublishRedundant {
        name: String,
        payload: Vec<u8>,
        responder: oneshot::Sender<Result<()>>,
    },
    ResolveRedundant {
        name: String,
        responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    VerifyQuorum {
        name: String,
        payload: Vec<u8>,
        responder: oneshot::Sender<Result<usize>>,
    },
    SendProxyRequest {
        peer: libp2p::PeerId,
        request: ProxyRequest,
        responder: oneshot::Sender<Result<ProxyResponse>>,
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

    pub async fn send_proxy_request(&self, peer: libp2p::PeerId, request: ProxyRequest) -> Result<ProxyResponse> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Command::SendProxyRequest {
            peer,
            request,
            responder: tx,
        }).await?;
        rx.await?
    }

    pub async fn send_proxy_response(&self, channel: libp2p::request_response::ResponseChannel<ProxyResponse>, response: ProxyResponse) -> Result<()> {
        self.sender.send(Command::SendProxyResponse { channel, response }).await?;
        Ok(())
    }

    pub async fn publish_redundant_payload(&self, name: &str, payload_bytes: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Command::PublishRedundant {
            name: name.to_string(),
            payload: payload_bytes,
            responder: tx,
        }).await?;
        rx.await?
    }

    pub async fn resolve_redundant_payload(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Command::ResolveRedundant {
            name: name.to_string(),
            responder: tx,
        }).await?;
        rx.await?
    }

    pub async fn verify_quorum(&self, name: &str, payload_bytes: Vec<u8>) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Command::VerifyQuorum {
            name: name.to_string(),
            payload: payload_bytes,
            responder: tx,
        }).await?;
        rx.await?
    }

    pub async fn get_network_status(&self) -> Result<serde_json::Value> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Command::GetNetworkStatus { responder: tx }).await?;
        rx.await?
    }
}
