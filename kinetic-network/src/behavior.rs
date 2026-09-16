#![allow(missing_docs)]
//! Libp2p `NetworkBehaviour` aggregator.
//! ## Layer 7 Architecture: The Network Compositor
//! This module defines the `KineticBehavior` struct, which acts as the supreme 
//! router for all P2P sub-protocols. Because Kinetic does not rely on a global 
//! blockchain ledger, it requires a highly specific composition of decentralized 
//! protocols to maintain state and propagate events.
//!
//! ## Core Protocols Composed
//! - **Kademlia (`kad`)**: The Distributed Hash Table (DHT). Used for long-term 
//!   storage of domain `Reveals`, `Commitments`, and KYN payloads. It routes 
//!   mathematical state across the network based on XOR distance.
//! - **Gossipsub (`gossipsub`)**: The high-speed mesh flood router. Used for 
//!   ephemeral, globally relevant pulses (e.g. Time Oracle ticks, emergency 
//!   Network Halts) that must reach all nodes in milliseconds without being stored.
//! - **AutoNAT & dcutr**: Distributed NAT traversal. Allows nodes behind restrictive 
//!   home routers or carrier-grade NATs to punch holes and establish direct peer 
//!   connections for decentralized CDN routing.
//! - **Request-Response**: Point-to-point private messaging used for Tor-like 
//!   proxy routing and direct web asset delivery.

use crate::client::{ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;
use libp2p::{gossipsub, kad, swarm::NetworkBehaviour};

/// The aggregate network behavior combining Kademlia DHT for state and
/// Gossipsub for real-time propagation of reveals and heartbeats.
#[allow(missing_docs)]
#[derive(NetworkBehaviour)]
pub struct KineticBehavior {
    /// Protocol for identifying peer capabilities and addresses.
    pub identify: libp2p::identify::Behaviour,
    /// Liveness checking protocol.
    pub ping: libp2p::ping::Behaviour,

    /// Kademlia DHT for robust decentralized key-value storage.
    pub kademlia: kad::Behaviour<KineticRecordStore>,
    /// PubSub implementation for fast propagation of events.
    pub gossipsub: gossipsub::Behaviour,

    /// Request-response protocol for domain proxies.
    pub proxy: libp2p::request_response::cbor::Behaviour<ProxyRequest, ProxyResponse>,

    /// Request-response protocol for serving DHT caches (CDN).
    pub cdn: libp2p::request_response::cbor::Behaviour<
        kinetic_types::cdn::CdnRequest,
        kinetic_types::cdn::CdnResponse,
    >,

    /// Request-response protocol for syncing action state.
    pub action_sync: libp2p::request_response::cbor::Behaviour<
        kinetic_types::action::ActionSyncRequest,
        kinetic_types::action::ActionSyncResponse,
    >,

    /// Stream protocol for passing raw traffic.
    #[cfg(not(target_arch = "wasm32"))]
    pub stream: libp2p_stream::Behaviour,

    /// AutoNAT protocol to discover external IP address and NAT status.
    pub autonat: libp2p::autonat::Behaviour,
    /// NAT traversal client behaviour (DCUtR/Relay).
    pub relay_client: libp2p::relay::client::Behaviour,
    /// Direct connection upgrade through relay.
    pub dcutr: libp2p::dcutr::Behaviour,

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
