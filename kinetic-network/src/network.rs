use libp2p::{
    gossipsub, kad, swarm::NetworkBehaviour, swarm::SwarmEvent, Swarm, PeerId,
};
use libp2p::kad::store::RecordStore;
use libp2p::futures::StreamExt;
use tracing::info;
use anyhow::Result;
use tokio::sync::{mpsc, oneshot};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// The aggregate network behavior combining Kademlia DHT for state and 
/// Gossipsub for real-time propagation of reveals and heartbeats.
#[derive(NetworkBehaviour)]
pub struct KineticBehavior {
    pub kademlia: kad::Behaviour<KineticRecordStore>,
    pub gossipsub: gossipsub::Behaviour,
}

use std::time::{Instant, Duration};

pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    reveals_by_name: HashMap<String, kinetic_core::types::Reveal>,
    last_heartbeats_by_name: HashMap<String, Instant>,
    hibernations_by_name: HashMap<String, Instant>,
}

impl KineticRecordStore {
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            inner: kad::store::MemoryStore::new(local_peer_id),
            reveals_by_name: HashMap::new(),
            last_heartbeats_by_name: HashMap::new(),
            hibernations_by_name: HashMap::new(),
        }
    }

    fn verify_reveal(reveal: &kinetic_core::types::Reveal) -> bool {
        use kinetic_core::types::Commitment;
        use ed25519_dalek::{Verifier, Signature, VerifyingKey};
        use sha2::{Sha256, Digest};
        use kinetic_core::traits::VdfEngine;
        use kinetic_vdf::ChiaVdfEngine;

        let signable = reveal.signable_bytes();
        let pubkey = match VerifyingKey::try_from(reveal.pubkey.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&reveal.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if pubkey.verify(&signable, &signature).is_err() {
            tracing::warn!("Rejecting Kademlia Reveal: Invalid Ed25519 Signature");
            return false;
        }

        let engine = ChiaVdfEngine::new();
        let challenge_bytes = hex::decode(&reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(reveal.name.as_bytes());
        hasher.update(&reveal.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = Commitment { hash };

        let required_iterations = kinetic_core::types::calculate_required_iterations(&reveal.name, reveal.drand_pulse);
        if reveal.iterations < required_iterations {
            tracing::warn!("Rejecting Kademlia Reveal: VDF iterations ({}) below required minimum ({})", reveal.iterations, required_iterations);
            return false;
        }
        
        match engine.verify(&challenge, &reveal.vdf_proof, reveal.iterations) {
            Ok(true) => true,
            _ => {
                tracing::warn!("Rejecting Kademlia Reveal: Invalid VDF Proof");
                false
            }
        }
    }
}

impl kad::store::RecordStore for KineticRecordStore {
    type RecordsIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &kad::RecordKey) -> Option<std::borrow::Cow<'_, kad::Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        tracing::info!("KineticRecordStore::put called for key: {:?}", r.key);
        
        // 1. Try parsing as Reveal first (most fields, strict subset requirements prevent false positives)
        if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Reveal for {}", reveal.name);
            if !Self::verify_reveal(&reveal) {
                return Err(kad::store::Error::ValueTooLarge);
            }

            if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
                if existing_reveal.pubkey != reveal.pubkey {
                    let last_hb = self.last_heartbeats_by_name.get(&reveal.name).copied().unwrap_or(Instant::now() - Duration::from_secs(86400));
                    let grace_period = Duration::from_secs(300); // 5 minutes grace period
                    
                    let last_hibernation = self.hibernations_by_name.get(&reveal.name).copied().unwrap_or(Instant::now() - Duration::from_secs(31536000 * 2));
                    let hibernation_period = Duration::from_secs(31536000); // 1 year exemption
                    
                    if last_hb.elapsed() < grace_period || last_hibernation.elapsed() < hibernation_period {
                        tracing::warn!("Rejecting Steal Reveal for {}: Name is actively maintained or hibernated", reveal.name);
                        return Err(kad::store::Error::ValueTooLarge);
                    }
                    
                    // Name is dead. Check for Grace-Period Escalation penalty
                    let required = kinetic_core::types::calculate_required_iterations(&reveal.name, reveal.drand_pulse);
                    let penalty = 500_000;
                    if reveal.iterations < required + penalty {
                        tracing::warn!("Rejecting Steal Reveal for {}: Iterations {} below escalation penalty ({})", reveal.name, reveal.iterations, required + penalty);
                        return Err(kad::store::Error::ValueTooLarge);
                    }
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner.", reveal.name);
                }
            }

            self.reveals_by_name.insert(reveal.name.clone(), reveal.clone());
            // Optional: Also mark heartbeat and hibernation as updated when we receive a reveal?
            // Usually we rely on explicit heartbeats, but let's record it.
            self.last_heartbeats_by_name.insert(reveal.name.clone(), Instant::now());
            return self.inner.put(r);
        }

        // 2. Try parsing as Hibernation
        if let Ok(hibernation) = serde_json::from_slice::<kinetic_core::types::Hibernation>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Hibernation for {}", hibernation.name);
            if let Some(existing_reveal) = self.reveals_by_name.get(&hibernation.name) {
                let signable = hibernation.signable_bytes();
                if let Ok(pubkey) = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice()) {
                    if let Ok(sig) = ed25519_dalek::Signature::from_slice(&hibernation.signature) {
                        use ed25519_dalek::Verifier;
                        if pubkey.verify(&signable, &sig).is_ok() {
                            
                            if hibernation.iterations >= 500_000_000 {
                                tracing::info!("Accepted valid Hibernation VDF for {}. Exempt from heartbeats for 1 year.", hibernation.name);
                                self.hibernations_by_name.insert(hibernation.name.clone(), Instant::now());
                                return self.inner.put(r);
                            } else {
                                tracing::warn!("Hibernation for {} failed: VDF iterations must be >= 500_000_000", hibernation.name);
                            }
                        }
                    }
                }
            }
            return Err(kad::store::Error::ValueTooLarge);
        }

        // 3. Try parsing as Heartbeat
        if let Ok(heartbeat) = serde_json::from_slice::<kinetic_core::types::Heartbeat>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Heartbeat for {}", heartbeat.name);
            if let Some(existing_reveal) = self.reveals_by_name.get(&heartbeat.name) {
                let signable = heartbeat.signable_bytes();
                if let Ok(pubkey) = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice()) {
                    if let Ok(sig) = ed25519_dalek::Signature::from_slice(&heartbeat.signature) {
                        use ed25519_dalek::Verifier;
                        if pubkey.verify(&signable, &sig).is_ok() {
                            tracing::info!("Accepted valid Heartbeat for {}", heartbeat.name);
                            self.last_heartbeats_by_name.insert(heartbeat.name.clone(), Instant::now());
                            return self.inner.put(r);
                        }
                    }
                }
            }
            tracing::warn!("Rejecting Heartbeat for {}: Invalid signature or no existing Reveal", heartbeat.name);
            return Err(kad::store::Error::ValueTooLarge);
        }

        tracing::warn!("Rejecting Kademlia record: Neither Reveal, Hibernation, nor Heartbeat");
        Err(kad::store::Error::ValueTooLarge)
    }

    fn remove(&mut self, k: &kad::RecordKey) {
        self.inner.remove(k)
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, record: kad::ProviderRecord) -> kad::store::Result<()> {
        self.inner.add_provider(record)
    }

    fn providers(&self, key: &kad::RecordKey) -> Vec<kad::ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, k: &kad::RecordKey, p: &PeerId) {
        self.inner.remove_provider(k, p)
    }
}

pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_nodes: Vec<String>,
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
}

#[derive(Clone)]
pub struct NetworkClient {
    sender: mpsc::Sender<Command>,
}

impl NetworkClient {
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
}

pub struct NetworkEventLoop {
    swarm: Swarm<KineticBehavior>,
    command_receiver: mpsc::Receiver<Command>,
    // Track pending get queries. Maps name -> state
    pending_gets: HashMap<String, PendingGet>,
    // Maps kad::QueryId -> name
    query_id_to_name: HashMap<kad::QueryId, String>,
}

struct PendingGet {
    responder: oneshot::Sender<Result<Option<Vec<u8>>>>,
    expected_responses: usize,
    received_payloads: Vec<Vec<u8>>,
}

impl NetworkEventLoop {
    pub fn new(config: NetworkConfig, local_key: libp2p::identity::Keypair) -> Result<(NetworkClient, Self)> {
        info!("Initializing Kinetic P2P Swarm on {}", config.listen_addr);
        
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();
                let store = KineticRecordStore::new(peer_id);
                let kademlia = kad::Behaviour::new(peer_id, store);
                
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
                ).expect("Valid gossipsub config");
                
                KineticBehavior { kademlia, gossipsub }
            }).unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
            .build();
            
        swarm.listen_on(config.listen_addr.parse()?)?;
        
        for node_str in &config.bootstrap_nodes {
            if let Ok(addr) = node_str.parse::<libp2p::Multiaddr>() {
                if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    let _ = swarm.dial(addr);
                }
            }
        }
        
        if !config.bootstrap_nodes.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
            info!("Bootstrapping Kademlia DHT with {} seed nodes", config.bootstrap_nodes.len());
        }
        
        let (tx, rx) = mpsc::channel(32);
        let client = NetworkClient { sender: tx };
        
        let event_loop = Self {
            swarm,
            command_receiver: rx,
            pending_gets: HashMap::new(),
            query_id_to_name: HashMap::new(),
        };
        
        Ok((client, event_loop))
    }

    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");
        
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
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
                    // In an isolated test network without peers, Quorum::One is required to self-put
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
                if !local_payloads.is_empty() {
                    let winning_payload = Self::xor_tie_breaker(&name, local_payloads);
                    let _ = responder.send(Ok(winning_payload));
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
        }
    }
    
    async fn handle_swarm_event(&mut self, event: SwarmEvent<KineticBehaviorEvent>) {
        if let SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) = event {
            match e {
                kad::Event::OutboundQueryProgressed { id, result, .. } => {
                    match result {
                        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                            if let Some(name) = self.query_id_to_name.get(&id) {
                                if let Some(pending) = self.pending_gets.get_mut(name) {
                                    pending.received_payloads.push(peer_record.record.value);
                                }
                            }
                        }
                        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })) |
                        kad::QueryResult::GetRecord(Err(_)) => {
                            if let Some(name) = self.query_id_to_name.remove(&id) {
                                let mut complete = false;
                                if let Some(pending) = self.pending_gets.get_mut(&name) {
                                    pending.expected_responses -= 1;
                                    if pending.expected_responses == 0 {
                                        complete = true;
                                    }
                                }
                                if complete {
                                    if let Some(pending) = self.pending_gets.remove(&name) {
                                        let winning_payload = Self::xor_tie_breaker(&name, pending.received_payloads);
                                        let _ = pending.responder.send(Ok(winning_payload));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    /// Implements the client-side XOR lottery tie-breaker if multiple conflicting payloads exist.
    fn xor_tie_breaker(name: &str, payloads: Vec<Vec<u8>>) -> Option<Vec<u8>> {
        if payloads.is_empty() { return None; }
        
        let mut name_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        name_hash.copy_from_slice(&hasher.finalize());
        
        let mut unique_payloads = payloads;
        unique_payloads.sort();
        unique_payloads.dedup();
        
        unique_payloads.into_iter().min_by_key(|p| {
            let mut p_hash = [0u8; 32];
            let mut p_hasher = Sha256::new();
            p_hasher.update(p);
            p_hash.copy_from_slice(&p_hasher.finalize());
            
            let mut distance = [0u8; 32];
            for i in 0..32 {
                distance[i] = name_hash[i] ^ p_hash[i];
            }
            distance
        })
    }
}
