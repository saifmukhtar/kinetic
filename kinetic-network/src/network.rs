use libp2p::{
    gossipsub, kad, swarm::NetworkBehaviour, swarm::SwarmEvent, Swarm, PeerId,
};
use libp2p::kad::store::RecordStore;
use libp2p::futures::StreamExt;
use tracing::info;
use anyhow::Result;
use tokio::sync::{mpsc, oneshot, watch};
use std::collections::HashMap;
use std::sync::Arc;

use serde::{Serialize, Deserialize};
use kinetic_storage::SledStorage;
use kinetic_core::traits::StorageEngine;

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
}



/// Sled key prefixes for persistent KineticRecordStore state
const KRS_REVEAL_PREFIX: &str = "krs_reveal:";
const KRS_HB_PREFIX: &str = "krs_hb:";
const KRS_HIB_PREFIX: &str = "krs_hib:";

pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    pub storage: Arc<SledStorage>,
    pub reveals_by_name: HashMap<String, kinetic_core::types::Reveal>,
    pub last_heartbeats_by_name: HashMap<String, u64>,
    pub hibernations_by_name: HashMap<String, u64>,
    pub commitments_by_hash: HashMap<[u8; 32], u64>,
    pub accepted_reveals_timestamps: std::collections::VecDeque<std::time::Instant>,
    pub current_drand_round: u64,
}

impl KineticRecordStore {
    pub fn new(local_peer_id: PeerId, storage: Arc<SledStorage>, initial_drand_round: u64) -> Self {
        let mut reveals_by_name: HashMap<String, kinetic_core::types::Reveal> = HashMap::new();
        let mut last_heartbeats_by_name: HashMap<String, u64> = HashMap::new();
        let mut hibernations_by_name: HashMap<String, u64> = HashMap::new();

        // Restore state from sled on startup
        // Reveals
        if let Ok(iter) = storage.scan_prefix(KRS_REVEAL_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_REVEAL_PREFIX).to_string();
                if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&val_bytes) {
                    tracing::info!("[KRS restore] Reveal for {}", name);
                    reveals_by_name.insert(name, reveal);
                }
            }
        }
        // Heartbeat rounds
        if let Ok(iter) = storage.scan_prefix(KRS_HB_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_HB_PREFIX).to_string();
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8;8]));
                    tracing::info!("[KRS restore] Heartbeat round {} for {}", round, name);
                    last_heartbeats_by_name.insert(name, round);
                }
            }
        }
        // Hibernation rounds
        if let Ok(iter) = storage.scan_prefix(KRS_HIB_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_HIB_PREFIX).to_string();
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8;8]));
                    tracing::info!("[KRS restore] Hibernation round {} for {}", round, name);
                    hibernations_by_name.insert(name, round);
                }
            }
        }

        Self {
            inner: kad::store::MemoryStore::new(local_peer_id),
            storage,
            reveals_by_name,
            last_heartbeats_by_name,
            hibernations_by_name,
            commitments_by_hash: HashMap::new(),
            accepted_reveals_timestamps: std::collections::VecDeque::new(),
            current_drand_round: initial_drand_round,
        }
    }

    fn verify_reveal(&self, reveal: &kinetic_core::types::Reveal) -> bool {
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

        if reveal.protocol_version >= 2 {
            // Check if commitment was broadcast before the reveal
            if let Some(&commit_round) = self.commitments_by_hash.get(&hash) {
                // Must have been seen in a round *prior* to or same as current round.
                // In practice, it must just exist in our DHT state.
                tracing::info!("Commitment matched for Reveal of {} (committed around round {})", reveal.name, commit_round);
            } else {
                tracing::warn!("Rejecting v2 Reveal for {}: No prior Commitment found in DHT!", reveal.name);
                return false;
            }
        }

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
        
        // 0. Try parsing as Commitment
        if let Ok(commitment) = serde_json::from_slice::<kinetic_core::types::Commitment>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Commitment");
            self.commitments_by_hash.insert(commitment.hash, self.current_drand_round);
            return self.inner.put(r);
        }

        // 1. Try parsing as Reveal first (most fields, strict subset requirements prevent false positives)
        if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Reveal for {}", reveal.name);
            
            // Phase 5.4: Check for stale VDF proofs
            if self.current_drand_round.saturating_sub(reveal.drand_pulse) > kinetic_core::types::RESQUARING_EPOCH_ROUNDS {
                tracing::warn!("Rejecting Reveal for {}: VDF proof is too old (> 1 year)", reveal.name);
                return Err(kad::store::Error::ValueTooLarge);
            }

            if !self.verify_reveal(&reveal) {
                return Err(kad::store::Error::ValueTooLarge);
            }

            if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
                if existing_reveal.pubkey != reveal.pubkey {
                    // Grace-period check using drand round arithmetic (2.2)
                    // A name is protected if heartbeated within the last 10 rounds (~5 min)
                    let grace_period_rounds: u64 = 10;
                    let hibernation_period_rounds: u64 = 1_051_200; // ~1 year at 30s/round

                    let last_hb_round = self.last_heartbeats_by_name.get(&reveal.name)
                        .copied()
                        .unwrap_or(0);
                    let last_hib_round = self.hibernations_by_name.get(&reveal.name)
                        .copied()
                        .unwrap_or(0);

                    let hb_age = self.current_drand_round.saturating_sub(last_hb_round);
                    let hib_age = self.current_drand_round.saturating_sub(last_hib_round);

                    if hb_age < grace_period_rounds || hib_age < hibernation_period_rounds {
                        tracing::warn!(
                            "Rejecting Steal Reveal for {}: Name is actively maintained \
                             (last HB {} rounds ago) or hibernated ({} rounds ago)",
                            reveal.name, hb_age, hib_age
                        );
                        return Err(kad::store::Error::ValueTooLarge);
                    }

                    // Name is dead. Check for Grace-Period Escalation penalty
                    // T_steal(Δt) = T_base * e^(-β * Δt_rounds)
                    let idle_rounds = hb_age;
                    let beta: f64 = 0.005; // decay constant — tuneable
                    let t_max_multiplier: f64 = 50.0; // at idle=0, steal costs 50× base
                    let decay = (-beta * idle_rounds as f64).exp();
                    let steal_multiplier = 1.0 + (t_max_multiplier - 1.0) * decay;
                    let required = kinetic_core::types::calculate_required_iterations(&reveal.name, reveal.drand_pulse);
                    let steal_threshold = (required as f64 * steal_multiplier) as u64;

                    if reveal.iterations < steal_threshold {
                        tracing::warn!("Rejecting Steal Reveal for {}: Iterations {} below steal threshold ({})", reveal.name, reveal.iterations, steal_threshold);
                        return Err(kad::store::Error::ValueTooLarge);
                    }
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner.", reveal.name);
                }
            }

            self.reveals_by_name.insert(reveal.name.clone(), reveal.clone());
            // Persist reveal to sled
            let reveal_key = format!("{}{}", KRS_REVEAL_PREFIX, reveal.name);
            if let Ok(bytes) = serde_json::to_vec(&reveal) {
                let _ = self.storage.put(reveal_key.as_bytes(), &bytes);
            }
            
            // Phase 6.1: Alert Layer
            let now = std::time::Instant::now();
            self.accepted_reveals_timestamps.push_back(now);
            while let Some(t) = self.accepted_reveals_timestamps.front() {
                if now.duration_since(*t) > std::time::Duration::from_secs(3600) {
                    self.accepted_reveals_timestamps.pop_front();
                } else {
                    break;
                }
            }
            if self.accepted_reveals_timestamps.len() > 100 {
                tracing::warn!("ALERT: High registration rate ({} valid reveals accepted in the last hour). VDF difficulty parameters may need revision.", self.accepted_reveals_timestamps.len());
            }

            // Record fresh heartbeat at the current drand round
            let current_round = self.current_drand_round;
            self.last_heartbeats_by_name.insert(reveal.name.clone(), current_round);
            let hb_key = format!("{}{}", KRS_HB_PREFIX, reveal.name);
            let _ = self.storage.put(hb_key.as_bytes(), &current_round.to_be_bytes());

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

                            if hibernation.iterations < 500_000_000 {
                                tracing::warn!("Hibernation for {} failed: VDF iterations must be >= 500_000_000", hibernation.name);
                                return Err(kad::store::Error::ValueTooLarge);
                            }

                            // Reconstruct the VDF challenge from the Hibernation fields
                            // (mirrors the Commitment construction in the CLI)
                            use sha2::{Sha256, Digest as _};
                            use kinetic_core::traits::VdfEngine;
                            use kinetic_vdf::ChiaVdfEngine;

                            // Reconstruct challenge: CLI uses zero salt ([0u8; 32]) inline for Hibernation
                            let challenge_bytes = hex::decode(&hibernation.drand_randomness)
                                .unwrap_or_else(|_| vec![0u8; 32]);
                            let mut hasher = Sha256::new();
                            hasher.update(hibernation.name.as_bytes());
                            hasher.update(&hibernation.salt); // salt — Hibernation struct now has salt
                            hasher.update(&challenge_bytes);
                            hasher.update(&existing_reveal.pubkey);
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&hasher.finalize());
                            let challenge = kinetic_core::types::Commitment { hash };

                            let engine = ChiaVdfEngine::new();
                            match engine.verify(&challenge, &hibernation.vdf_proof, hibernation.iterations) {
                                Ok(true) => {
                                    tracing::info!("Accepted valid Hibernation VDF for {}. Exempt from heartbeats for 1 year.", hibernation.name);
                                    // Store hibernation round (drand-anchored)
                                    let current_round = self.current_drand_round;
                                    self.hibernations_by_name.insert(hibernation.name.clone(), current_round);
                                    let hib_key = format!("{}{}", KRS_HIB_PREFIX, hibernation.name);
                                    let _ = self.storage.put(hib_key.as_bytes(), &current_round.to_be_bytes());
                                    return self.inner.put(r);
                                }
                                Ok(false) => {
                                    tracing::warn!("Hibernation for {} failed: VDF proof invalid for {} iterations", hibernation.name, hibernation.iterations);
                                }
                                Err(e) => {
                                    tracing::warn!("Hibernation for {} failed: VDF verification error: {}", hibernation.name, e);
                                }
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
                            tracing::info!("Accepted valid Heartbeat for {} at drand round {}", heartbeat.name, heartbeat.latest_drand_pulse);
                            // Use the pulse number from the heartbeat itself for provable liveness
                            let hb_round = heartbeat.latest_drand_pulse;
                            self.last_heartbeats_by_name.insert(heartbeat.name.clone(), hb_round);
                            // Persist to sled
                            let hb_key = format!("{}{}", KRS_HB_PREFIX, heartbeat.name);
                            let _ = self.storage.put(hb_key.as_bytes(), &hb_round.to_be_bytes());
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

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_nodes: Vec<String>,
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
}

#[derive(Clone)]
pub struct NetworkClient {
    sender: mpsc::Sender<Command>,
}

impl NetworkClient {
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
}

pub struct NetworkEventLoop {
    swarm: Swarm<KineticBehavior>,
    command_receiver: mpsc::Receiver<Command>,
    // Track pending get queries. Maps name -> state
    pending_gets: HashMap<String, PendingGet>,
    pending_quorums: HashMap<String, PendingQuorum>,
    // Maps kad::QueryId -> name
    query_id_to_name: HashMap<kad::QueryId, String>,
    pending_proxy_requests: HashMap<libp2p::request_response::OutboundRequestId, oneshot::Sender<Result<ProxyResponse>>>,
    incoming_proxy_tx: Option<mpsc::Sender<(ProxyRequest, libp2p::request_response::ResponseChannel<ProxyResponse>)>>,
    bad_vdf_counts: HashMap<PeerId, (u32, std::time::Instant)>,
    current_drand_pulse: u64,
    /// Receives real Drand round numbers pushed by the daemon's heartbeat loop.
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
        
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_dns()?
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let store = KineticRecordStore::new(peer_id, storage.clone(), config.initial_drand_pulse);
                let kademlia = kad::Behaviour::new(peer_id, store);
                
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
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
                
                KineticBehavior { relay_client, dcutr, identify, ping, proxy, kademlia, gossipsub }
            }).unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
            .build();
            
        swarm.listen_on(config.listen_addr.parse()?)?;
        
        let mut bootstrap_peers = std::collections::HashSet::new();
        for node_str in &config.bootstrap_nodes {
            if let Ok(addr) = node_str.parse::<libp2p::Multiaddr>() {
                if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                    bootstrap_peers.insert(peer_id);
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
        
        loop {
            tokio::select! {
                // Accept real Drand round pushes from the daemon's heartbeat loop
                Ok(()) = self.drand_pulse_rx.changed() => {
                    let new_round = *self.drand_pulse_rx.borrow();
                    if new_round > self.current_drand_pulse {
                        tracing::debug!("NetworkEventLoop: drand pulse updated {} -> {}", self.current_drand_pulse, new_round);
                        self.current_drand_pulse = new_round;
                        // Keep the KineticRecordStore in sync
                        self.swarm.behaviour_mut().kademlia.store_mut().current_drand_round = new_round;
                    }
                }
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
                let final_payload = if local_payloads.is_empty() {
                    None
                } else {
                    let winning_payload = Self::xor_tie_breaker(&name, local_payloads, self.current_drand_pulse);
                    winning_payload
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
        }
    }
    
    async fn handle_swarm_event(&mut self, event: SwarmEvent<KineticBehaviorEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                let pow_valid = crate::pow::is_valid_sybil_pow(&peer_id, self.current_drand_pulse, crate::pow::DEFAULT_DIFFICULTY_BITS);
                
                if !pow_valid && !is_bootstrap {
                    tracing::warn!("Disconnecting peer {} - Failed S/Kademlia PoW for epoch", peer_id);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                } else if !pow_valid && is_bootstrap {
                    let is_startup_phase = self.startup_time.elapsed() < std::time::Duration::from_secs(300);
                    if is_startup_phase {
                        tracing::warn!("Bootstrap peer {} failed PoW — permitted during cold-start only", peer_id);
                    } else {
                        tracing::warn!("Disconnecting bootstrap peer {} - Failed S/Kademlia PoW after cold-start phase", peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    }
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
                                    // Check if the store actually accepted this reveal. If not, it was rejected (invalid VDF, protected name, etc.)
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
                                            tracing::warn!("Peer {} sent 3 invalid VDF proofs within 60s — disconnecting (Hashcash reconnect required)", source);
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
                Event::Message { peer: _, message } => {
                    match message {
                        Message::Request { request_id: _, request, channel } => {
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
        _ => {}
        }
    }

    /// Implements the client-side XOR lottery tie-breaker if multiple conflicting payloads exist.
    fn xor_tie_breaker(_name: &str, payloads: Vec<Vec<u8>>, current_pulse: u64) -> Option<Vec<u8>> {
        if payloads.is_empty() { return None; }
        
        // Use current drand pulse as the "future" anchor
        let mut pulse_bytes = [0u8; 32];
        pulse_bytes[..8].copy_from_slice(&current_pulse.to_be_bytes());
        
        let mut unique_payloads = payloads;
        unique_payloads.sort();
        unique_payloads.dedup();
        
        unique_payloads.into_iter().min_by_key(|p| {
            if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(p) {
                // VDF output y is the first 100 bytes of proof; take first 32
                let y_bytes: [u8; 32] = reveal.vdf_proof.proof_bytes
                    .get(..32)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0u8; 32]);
                let mut dist = [0u8; 32];
                for i in 0..32 { dist[i] = y_bytes[i] ^ pulse_bytes[i]; }
                dist
            } else {
                [0xff; 32] // invalid payloads sort last
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
        // Current pulse 0 -> pulse_bytes starts with 0
        // Payload A: proof_bytes[0] = 0x10 -> distance = 0x10
        // Payload B: proof_bytes[0] = 0x05 -> distance = 0x05 (Closer!)
        
        let payload_a = make_dummy_reveal(0x10);
        let payload_b = make_dummy_reveal(0x05);
        
        let winner = NetworkEventLoop::xor_tie_breaker("test.kin", vec![payload_a.clone(), payload_b.clone()], 0);
        assert_eq!(winner.unwrap(), payload_b);
        
        // Let's change the pulse so that 0x10 is closer
        // If pulse_bytes[0] = 0x15 (pulse is 0x15000000_00000000 in u64)
        // distance to A (0x10) = 0x05
        // distance to B (0x05) = 0x10
        let pulse: u64 = 0x1500_0000_0000_0000;
        let winner2 = NetworkEventLoop::xor_tie_breaker("test.kin", vec![payload_a.clone(), payload_b.clone()], pulse);
        assert_eq!(winner2.unwrap(), payload_a);
    }
}
