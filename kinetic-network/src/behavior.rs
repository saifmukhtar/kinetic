#![allow(missing_docs)]

use crate::client::{ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;
use libp2p::{gossipsub, kad, swarm::NetworkBehaviour};

/// The aggregate network behavior combining Kademlia DHT for state and
/// Gossipsub for real-time propagation of reveals and heartbeats.
#[allow(missing_docs)]
#[derive(NetworkBehaviour)]
pub struct KineticBehavior {
    /// NAT traversal client behaviour (DCUtR/Relay).
    pub relay_client: libp2p::relay::client::Behaviour,
    /// Direct connection upgrade through relay.
    pub dcutr: libp2p::dcutr::Behaviour,
    /// Protocol for identifying peer capabilities and addresses.
    pub identify: libp2p::identify::Behaviour,
    /// Liveness checking protocol.
    pub ping: libp2p::ping::Behaviour,
    /// Request-response protocol for domain proxies.
    pub proxy: libp2p::request_response::cbor::Behaviour<ProxyRequest, ProxyResponse>,
    /// Stream protocol for passing raw traffic.
    #[cfg(not(target_arch = "wasm32"))]
    pub stream: libp2p_stream::Behaviour,
    /// Kademlia DHT for robust decentralized key-value storage.
    pub kademlia: kad::Behaviour<KineticRecordStore>,
    /// PubSub implementation for fast propagation of events.
    pub gossipsub: gossipsub::Behaviour,
    /// AutoNAT protocol to discover external IP address and NAT status.
    pub autonat: libp2p::autonat::Behaviour,
    /// UPnP port forwarding via IGD.
    #[cfg(not(target_arch = "wasm32"))]
    pub upnp: libp2p::swarm::behaviour::toggle::Toggle<libp2p::upnp::tokio::Behaviour>,
    /// Optional Relay Server for public nodes.
    #[cfg(not(target_arch = "wasm32"))]
    pub relay_server: libp2p::swarm::behaviour::toggle::Toggle<libp2p::relay::Behaviour>,
    /// Optional mDNS discovery for local networks.
    #[cfg(not(target_arch = "wasm32"))]
    pub mdns: libp2p::swarm::behaviour::toggle::Toggle<libp2p::mdns::tokio::Behaviour>,
}
