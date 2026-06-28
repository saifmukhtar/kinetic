use anyhow::Result;
use libp2p::{kad, swarm::SwarmEvent, PeerId, Swarm};
use libp2p::kad::store::RecordStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::info;

use kinetic_storage::SledStorage;

use crate::behavior::{KineticBehavior, KineticBehaviorEvent};
use crate::client::{Command, NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;

pub struct NetworkEventLoop {
    swarm: Swarm<KineticBehavior>,
    command_receiver: mpsc::Receiver<Command>,
    pending_gets: HashMap<String, PendingGet>,
    pending_quorums: HashMap<String, PendingQuorum>,
    query_id_to_name: HashMap<kad::QueryId, String>,
    pending_proxy_requests: HashMap<libp2p::request_response::OutboundRequestId, oneshot::Sender<Result<ProxyResponse>>>,
    incoming_proxy_tx: Option<mpsc::Sender<(ProxyRequest, libp2p::request_response::ResponseChannel<ProxyResponse>)>>,
    bad_vdf_counts: HashMap<PeerId, (u32, std::time::Instant)>,
    current_drand_pulse: u64,
    drand_pulse_rx: watch::Receiver<u64>,
    bootstrap_peers: std::collections::HashSet<libp2p::PeerId>,
    startup_time: std::time::Instant,
}

struct PendingGet {
    responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    expected_responses: usize,
    received_payloads: Vec<Vec<u8>>,
}

struct PendingQuorum {
    responder: oneshot::Sender<Result<usize>>,
    expected_responses: usize,
    target_payload: Vec<u8>,
    match_count: usize,
}

impl NetworkEventLoop {
    pub fn new(
        config: NetworkConfig,
        local_key: libp2p::identity::Keypair,
        storage: Arc<SledStorage>,
        drand_pulse_rx: watch::Receiver<u64>,
        incoming_proxy_tx: Option<mpsc::Sender<(ProxyRequest, libp2p::request_response::ResponseChannel<ProxyResponse>)>>
    ) -> Result<(NetworkClient, Self)> {
        info!("Initializing Kinetic P2P Swarm on {}", config.listen_addr);
        
        #[cfg(not(target_os = "android"))]
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_dns()?;
            
        #[cfg(target_os = "android")]
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?;
            
        let mut swarm = builder
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let store = KineticRecordStore::new(peer_id, storage.clone(), config.initial_drand_pulse);
                let mut kademlia = kad::Behaviour::new(peer_id, store);
                if config.mode == NetworkMode::LightClient {
                    kademlia.set_mode(Some(kad::Mode::Client));
                } else {
                    kademlia.set_mode(Some(kad::Mode::Server));
                }
                
                let gossipsub = libp2p::gossipsub::Behaviour::new(
                    libp2p::gossipsub::MessageAuthenticity::Signed(key.clone()),
                    libp2p::gossipsub::Config::default(),
                ).expect("Valid gossipsub config");

                let identify = libp2p::identify::Behaviour::new(
                    libp2p::identify::Config::new("/kinetic/1.0.0".into(), key.public())
                );
                let dcutr = libp2p::dcutr::Behaviour::new(peer_id);
                let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());
                let proxy = libp2p::request_response::cbor::Behaviour::<ProxyRequest, ProxyResponse>::new(
                    [(libp2p::StreamProtocol::new("/kinetic/proxy/1.0.0"), libp2p::request_response::ProtocolSupport::Full)],
                    libp2p::request_response::Config::default(),
                );
                
                let mdns = if config.enable_mdns {
                    libp2p::swarm::behaviour::toggle::Toggle::from(Some(
                        libp2p::mdns::tokio::Behaviour::new(
                            libp2p::mdns::Config::default(),
                            peer_id,
                        ).expect("Valid mdns config")
                    ))
                } else {
                    libp2p::swarm::behaviour::toggle::Toggle::from(None)
                };
                
                KineticBehavior { relay_client, dcutr, identify, ping, proxy, kademlia, gossipsub, mdns }
            }).unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(30 * 24 * 3600)))
            .build();
            
        if config.mode == NetworkMode::FullNode && !config.listen_addr.is_empty() {
            swarm.listen_on(config.listen_addr.parse()?)?;
        }
        
        let mut bootstrap_peers = std::collections::HashSet::new();
        for node_str in &config.bootstrap_nodes {
            match node_str.parse::<libp2p::Multiaddr>() {
                Ok(addr) => {
                    tracing::info!("Successfully parsed bootstrap node: {}", addr);
                    if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                        bootstrap_peers.insert(peer_id);
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!("Failed to dial bootstrap node {}: {:?}", addr, e);
                        } else {
                            tracing::info!("Dialing bootstrap node: {}", addr);
                        }
                    } else {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!("Failed to dial bootstrap node (no peer ID) {}: {:?}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to parse bootstrap node '{}': {:?}", node_str, e);
                }
            }
        }
        
        if !config.bootstrap_nodes.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
            info!("Bootstrapping Kademlia DHT with {} seed nodes", config.bootstrap_nodes.len());
        }
        
        for domain in &config.seed_domains {
            let host_port = format!("{}:6070", domain);
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&host_port) {
                for addr in addrs {
                    let ip = addr.ip();
                    let multiaddr = libp2p::Multiaddr::empty()
                        .with(match ip {
                            std::net::IpAddr::V4(v4) => libp2p::multiaddr::Protocol::Ip4(v4),
                            std::net::IpAddr::V6(v6) => libp2p::multiaddr::Protocol::Ip6(v6),
                        })
                        .with(libp2p::multiaddr::Protocol::Tcp(addr.port()));
                    if swarm.dial(multiaddr.clone()).is_ok() {
                        info!("Dialing resolved DNS seed node: {}", multiaddr);
                    }
                }
            } else {
                tracing::warn!("Failed to resolve DNS seed domain: {}", domain);
            }
        }
        
        let (tx, rx) = mpsc::channel(32);
        let client = NetworkClient::new(tx);
        
        let event_loop = Self {
            swarm,
            command_receiver: rx,
            pending_gets: HashMap::new(),
            pending_quorums: HashMap::new(),
            query_id_to_name: HashMap::new(),
            pending_proxy_requests: HashMap::new(),
            incoming_proxy_tx,
            bad_vdf_counts: HashMap::new(),
            current_drand_pulse: config.initial_drand_pulse,
            drand_pulse_rx,
            bootstrap_peers,
            startup_time: std::time::Instant::now(),
        };
        
        Ok((client, event_loop))
    }

    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");
        
        let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(30));
        
        loop {
            tokio::select! {
                _ = keepalive_interval.tick() => {
                    // Send a dummy DHT query every 30s to reset the strict 60s idle timeout
                    // enforced by legacy kinetic-nodes on the AWS infrastructure.
                    let random_peer = libp2p::PeerId::random();
                    self.swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                }
                Ok(()) = self.drand_pulse_rx.changed() => {
                    let new_round = *self.drand_pulse_rx.borrow();
                    if new_round > self.current_drand_pulse {
                        tracing::debug!("NetworkEventLoop: drand pulse updated {} -> {}", self.current_drand_pulse, new_round);
                        self.current_drand_pulse = new_round;
                        self.swarm.behaviour_mut().kademlia.store_mut().current_drand_round = new_round;
                    }
                }
                event = libp2p::futures::StreamExt::select_next_some(&mut self.swarm) => self.handle_swarm_event(event).await,
                command = self.command_receiver.recv() => match command {
                    Some(c) => self.handle_command(c).await,
                    None => {
                        info!("Network client dropped, exiting loop");
                        break;
                    }
                }
            }
        }
    }
    
    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::PublishRedundant { name, payload, responder } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(record_key, payload.clone());
                    let _ = self.swarm.behaviour_mut().kademlia.put_record(record.clone(), kad::Quorum::One);
                    let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record);
                }
                let _ = responder.send(Ok(()));
            }
            Command::ResolveRedundant { name, responder } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);
                
                use libp2p::kad::store::RecordStore;
                let mut local_payloads = Vec::new();
                for key_bytes in &keys {
                    let record_key = kad::RecordKey::new(key_bytes);
                    if let Some(record_cow) = self.swarm.behaviour_mut().kademlia.store_mut().get(&record_key) {
                        local_payloads.push(record_cow.into_owned().value);
                    }
                }
                let final_payload = if local_payloads.is_empty() {
                    None
                } else {
                    Self::xor_tie_breaker(&name, local_payloads, self.current_drand_pulse)
                };
                if final_payload.is_some() {
                    let _ = responder.send(Ok(final_payload));
                    return;
                }

                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name.insert(query_id, name.clone());
                    expected += 1;
                }
                
                self.pending_gets.insert(name.clone(), PendingGet {
                    responder,
                    expected_responses: expected,
                    received_payloads: Vec::new(),
                });
            }
            Command::VerifyQuorum { name, payload, responder } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);
                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name.insert(query_id, format!("quorum_{}", name));
                    expected += 1;
                }
                
                self.pending_quorums.insert(name.clone(), PendingQuorum {
                    responder,
                    expected_responses: expected,
                    target_payload: payload,
                    match_count: 0,
                });
            }
            Command::SendProxyRequest { peer, request, responder } => {
                let req_id = self.swarm.behaviour_mut().proxy.send_request(&peer, request);
                self.pending_proxy_requests.insert(req_id, responder);
            }
            Command::SendProxyResponse { channel, response } => {
                let _ = self.swarm.behaviour_mut().proxy.send_response(channel, response);
            }
            Command::GetNetworkStatus { responder } => {
                let info = self.swarm.network_info();
                let peers = info.num_peers();
                let status = if peers > 0 { "Online" } else { "Offline (Bootstrap/Local)" };
                let uptime = format!("{} seconds", self.startup_time.elapsed().as_secs());
                
                // For DHT size, we can't easily access the exact count without iterating the internal store,
                // so we will provide an approximation or placeholder for now.
                let dht_size = 0; // Placeholder until store API is extended

                let _ = responder.send(Ok(serde_json::json!({
                    "status": status,
                    "peers": peers,
                    "dht_size": dht_size,
                    "uptime": uptime
                })));
            }
        }
    }
    
    async fn handle_swarm_event(&mut self, event: SwarmEvent<KineticBehaviorEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Connection established with {:?}", peer_id);
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                let pow_valid = crate::pow::is_valid_sybil_pow(&peer_id, self.current_drand_pulse, crate::pow::DEFAULT_DIFFICULTY_BITS);
                
                if !pow_valid && !is_bootstrap {
                    tracing::debug!("Peer {} failed S/Kademlia PoW for epoch, ignoring for routing table but keeping connection", peer_id);
                } else if !pow_valid && is_bootstrap {
                    // Bootstrap peers use static keys and do not mine PoW for each epoch.
                    // We must ALWAYS permit them to remain connected so the network doesn't partition.
                    tracing::debug!("Bootstrap peer {} failed PoW — permitted infinitely", peer_id);
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) => {
                match e {
                    kad::Event::OutboundQueryProgressed { id, result, .. } => {
                        match result {
                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                                if let Some(mapped_name) = self.query_id_to_name.get(&id) {
                                    if mapped_name.starts_with("quorum_") {
                                        let actual_name = mapped_name.trim_start_matches("quorum_");
                                        if let Some(pending) = self.pending_quorums.get_mut(actual_name) {
                                            if peer_record.record.value == pending.target_payload {
                                                pending.match_count += 1;
                                            }
                                        }
                                    } else {
                                        if let Some(pending) = self.pending_gets.get_mut(mapped_name) {
                                            pending.received_payloads.push(peer_record.record.value);
                                        }
                                    }
                                }
                            }
                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })) |
                            kad::QueryResult::GetRecord(Err(_)) => {
                                if let Some(mapped_name) = self.query_id_to_name.remove(&id) {
                                    if mapped_name.starts_with("quorum_") {
                                        let actual_name = mapped_name.trim_start_matches("quorum_").to_string();
                                        let mut complete = false;
                                        if let Some(pending) = self.pending_quorums.get_mut(&actual_name) {
                                            pending.expected_responses -= 1;
                                            if pending.expected_responses == 0 {
                                                complete = true;
                                            }
                                        }
                                        if complete {
                                            if let Some(pending) = self.pending_quorums.remove(&actual_name) {
                                                let _ = pending.responder.send(Ok(pending.match_count));
                                            }
                                        }
                                    } else {
                                        let mut complete = false;
                                        if let Some(pending) = self.pending_gets.get_mut(&mapped_name) {
                                            pending.expected_responses -= 1;
                                            if pending.expected_responses == 0 {
                                                complete = true;
                                            }
                                        }
                                        if complete {
                                            if let Some(pending) = self.pending_gets.remove(&mapped_name) {
                                                let winning_payload = Self::xor_tie_breaker(&mapped_name, pending.received_payloads, self.current_drand_pulse);
                                                let _ = pending.responder.send(Ok(winning_payload));
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    kad::Event::InboundRequest { request } => {
                        if let kad::InboundRequest::PutRecord { source, record, .. } = request {
                            if let Some(record) = record {
                                if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&record.value) {
                                    let store = self.swarm.behaviour_mut().kademlia.store_mut();
                                    let was_accepted = store.reveals_by_name.get(&reveal.name)
                                        .map(|r| r.pubkey == reveal.pubkey)
                                        .unwrap_or(false);

                                    if !was_accepted {
                                        let now = std::time::Instant::now();
                                        let entry = self.bad_vdf_counts.entry(source).or_insert((0, now));
                                        if now.duration_since(entry.1) > std::time::Duration::from_secs(60) {
                                            *entry = (1, now);
                                        } else {
                                            entry.0 += 1;
                                        }

                                        if entry.0 >= 3 {
                                            tracing::warn!("Peer {} sent 3 invalid VDF proofs within 60s — disconnecting", source);
                                            let _ = self.swarm.disconnect_peer_id(source);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Proxy(e)) => {
                use libp2p::request_response::{Event, Message};
                match e {
                    Event::Message { message, .. } => {
                        match message {
                            Message::Request { request, channel, .. } => {
                                if let Some(tx) = &self.incoming_proxy_tx {
                                    let _ = tx.send((request, channel)).await;
                                }
                            }
                            Message::Response { request_id, response } => {
                                if let Some(responder) = self.pending_proxy_requests.remove(&request_id) {
                                    let _ = responder.send(Ok(response));
                                }
                            }
                        }
                    }
                    Event::OutboundFailure { request_id, error, .. } => {
                        if let Some(responder) = self.pending_proxy_requests.remove(&request_id) {
                            let _ = responder.send(Err(anyhow::anyhow!("Outbound failure: {:?}", error)));
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Identify(e)) => {
                if let libp2p::identify::Event::Received { peer_id, info } = e {
                    tracing::info!("Received Identify from peer {:?} with addrs: {:?}", peer_id, info.listen_addrs);
                    let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                    let pow_valid = crate::pow::is_valid_sybil_pow(&peer_id, self.current_drand_pulse, crate::pow::DEFAULT_DIFFICULTY_BITS);
                    
                    if pow_valid || is_bootstrap {
                        for addr in info.listen_addrs {
                            tracing::info!("Adding peer {:?} addr {:?} to Kademlia", peer_id, addr);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    } else {
                        tracing::debug!("Peer {} failed PoW, ignoring for Kademlia routing table", peer_id);
                    }
                    let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Mdns(e)) => {
                if let libp2p::mdns::Event::Discovered(list) = e {
                    for (peer_id, multiaddr) in list {
                        let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                        let pow_valid = crate::pow::is_valid_sybil_pow(&peer_id, self.current_drand_pulse, crate::pow::DEFAULT_DIFFICULTY_BITS);
                        
                        if pow_valid || is_bootstrap {
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!("Outgoing connection error to peer {:?}: {:?}", peer_id, error);
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                tracing::debug!("Dialing peer {:?}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::debug!("Connection closed for peer {:?}: {:?}", peer_id, cause);
            }
            _ => {}
        }
    }

    fn xor_tie_breaker(_name: &str, payloads: Vec<Vec<u8>>, current_pulse: u64) -> Option<Vec<u8>> {
        if payloads.is_empty() { return None; }
        
        let mut pulse_bytes = [0u8; 32];
        pulse_bytes[..8].copy_from_slice(&current_pulse.to_be_bytes());
        
        let mut unique_payloads = payloads;
        unique_payloads.sort();
        unique_payloads.dedup();
        
        unique_payloads.into_iter().min_by_key(|p| {
            if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(p) {
                let y_bytes: [u8; 32] = reveal.vdf_proof.proof_bytes
                    .get(..32)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0u8; 32]);
                let mut dist = [0u8; 32];
                for i in 0..32 { dist[i] = y_bytes[i] ^ pulse_bytes[i]; }
                dist
            } else {
                [0xff; 32]
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_core::types::{Reveal, VdfProof};

    fn make_dummy_reveal(proof_first_byte: u8) -> Vec<u8> {
        let mut proof_bytes = vec![0u8; 100];
        proof_bytes[0] = proof_first_byte;
        
        let reveal = Reveal {
            protocol_version: 1,
            name: "test.kin".to_string(),
            payload: vec![],
            salt: [0u8; 32],
            drand_pulse: 0,
            drand_randomness: "".to_string(),
            vdf_proof: VdfProof {
                proof_bytes,
            },
            iterations: 1000,
            pubkey: vec![],
            signature: vec![],
        };
        serde_json::to_vec(&reveal).unwrap()
    }

    #[test]
    fn test_xor_tie_breaker() {
        let payload_a = make_dummy_reveal(0x10);
        let payload_b = make_dummy_reveal(0x05);
        
        let winner = NetworkEventLoop::xor_tie_breaker("test.kin", vec![payload_a.clone(), payload_b.clone()], 0);
        assert_eq!(winner.unwrap(), payload_b);
        
        let pulse: u64 = 0x1500_0000_0000_0000;
        let winner2 = NetworkEventLoop::xor_tie_breaker("test.kin", vec![payload_a.clone(), payload_b.clone()], pulse);
        assert_eq!(winner2.unwrap(), payload_a);
    }
}
