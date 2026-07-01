use crate::client::{ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;
use libp2p::{gossipsub, kad, swarm::NetworkBehaviour};

/// The aggregate network behavior combining Kademlia DHT for state and
/// Gossipsub for real-time propagation of reveals and heartbeats.
#[derive(NetworkBehaviour)]
pub struct KineticBehavior {
    pub relay_client: libp2p::relay::client::Behaviour,
    pub dcutr: libp2p::dcutr::Behaviour,
    pub identify: libp2p::identify::Behaviour,
    pub ping: libp2p::ping::Behaviour,
    pub proxy: libp2p::request_response::cbor::Behaviour<ProxyRequest, ProxyResponse>,
    pub kademlia: kad::Behaviour<KineticRecordStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: libp2p::swarm::behaviour::toggle::Toggle<libp2p::mdns::tokio::Behaviour>,
}
