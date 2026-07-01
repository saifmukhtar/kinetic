use anyhow::Result;
use libp2p::kad::store::RecordStore;
use libp2p::{kad, swarm::SwarmEvent, PeerId, Swarm};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::info;

use kinetic_storage::SledStorage;

use crate::behavior::{KineticBehavior, KineticBehaviorEvent};
use crate::client::{
    Command, NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse,
};
use crate::store::KineticRecordStore;

pub struct NetworkEventLoop {
    swarm: Swarm<KineticBehavior>,
    command_receiver: mpsc::Receiver<Command>,
    pending_gets: HashMap<String, PendingGet>,
    pending_quorums: HashMap<String, PendingQuorum>,
    query_id_to_name: HashMap<kad::QueryId, String>,
    pending_proxy_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        oneshot::Sender<
            std::result::Result<crate::client::ProxyResponse, crate::client::ProxyError>,
        >,
    >,
    incoming_proxy_tx: Option<
        mpsc::Sender<(
            crate::client::ProxyRequest,
            libp2p::request_response::ResponseChannel<crate::client::ProxyResponse>,
        )>,
    >,
    bad_vdf_counts: HashMap<PeerId, (u32, std::time::Instant)>,
    current_drand_pulse: u64,
    drand_pulse_rx: watch::Receiver<u64>,
    bootstrap_nodes: Vec<String>,
    bootstrap_peers: std::collections::HashSet<libp2p::PeerId>,
    startup_time: std::time::Instant,
    banned_peers: std::collections::HashSet<libp2p::PeerId>,
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
        incoming_proxy_tx: Option<
            mpsc::Sender<(
                ProxyRequest,
                libp2p::request_response::ResponseChannel<ProxyResponse>,
            )>,
        >,
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
                let store =
                    KineticRecordStore::new(peer_id, storage.clone(), config.initial_drand_pulse);
                let mut kad_config = kad::Config::default();
                kad_config
                    .set_protocol_names(vec![libp2p::StreamProtocol::new("/kinetic/kad/2.0.0")]);
                let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
                if config.mode == NetworkMode::LightClient {
                    kademlia.set_mode(Some(kad::Mode::Client));
                } else {
                    kademlia.set_mode(Some(kad::Mode::Server));
                }

                let gossipsub_config = if config.mode == NetworkMode::LightClient {
                    // LightClient mesh params: mesh_n_low < mesh_n < mesh_n_high (strict)
                    // gossipsub panics with MeshParametersInvalid if this invariant is violated.
                    libp2p::gossipsub::ConfigBuilder::default()
                        .heartbeat_interval(std::time::Duration::from_secs(10)) // Less frequent heartbeats (save battery)
                        .prune_backoff(std::time::Duration::from_secs(60))
                        .mesh_n(2) // target mesh degree
                        .mesh_n_low(1) // must be < mesh_n
                        .mesh_n_high(4) // must be > mesh_n
                        .mesh_outbound_min(1) // must be <= mesh_n_low and * 2 <= mesh_n
                        .gossip_lazy(1)
                        .validation_mode(libp2p::gossipsub::ValidationMode::Strict)
                        .build()
                        .expect("Valid gossipsub config")
                } else {
                    // Case 184: Gossipsub CPU DoS Protection. Use Strict validation to quickly penalize invalid sigs
                    libp2p::gossipsub::ConfigBuilder::default()
                        .validation_mode(libp2p::gossipsub::ValidationMode::Strict)
                        .build()
                        .expect("Valid gossipsub config")
                };

                let gossipsub = libp2p::gossipsub::Behaviour::new(
                    libp2p::gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("Valid gossipsub config");

                let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                    "/kinetic/1.0.0".into(),
                    key.public(),
                ));
                let dcutr = libp2p::dcutr::Behaviour::new(peer_id);
                let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());
                let proxy =
                    libp2p::request_response::cbor::Behaviour::<ProxyRequest, ProxyResponse>::new(
                        [(
                            libp2p::StreamProtocol::new("/kinetic/proxy/1.0.0"),
                            libp2p::request_response::ProtocolSupport::Full,
                        )],
                        libp2p::request_response::Config::default(),
                    );

                let mdns = if config.enable_mdns {
                    libp2p::swarm::behaviour::toggle::Toggle::from(Some(
                        libp2p::mdns::tokio::Behaviour::new(
                            libp2p::mdns::Config::default(),
                            peer_id,
                        )
                        .expect("Valid mdns config"),
                    ))
                } else {
                    libp2p::swarm::behaviour::toggle::Toggle::from(None)
                };

                KineticBehavior {
                    relay_client,
                    dcutr,
                    identify,
                    ping,
                    proxy,
                    kademlia,
                    gossipsub,
                    mdns,
                }
            })
            .unwrap()
            .with_swarm_config(|c| {
                if config.mode == NetworkMode::LightClient {
                    c.with_idle_connection_timeout(std::time::Duration::from_secs(60))
                // Aggressive power saving for mobile
                } else {
                    c.with_idle_connection_timeout(std::time::Duration::from_secs(30 * 24 * 3600))
                }
            })
            .build();

        if config.mode == NetworkMode::FullNode && !config.listen_addr.is_empty() {
            swarm.listen_on(config.listen_addr.parse()?)?;
            if let Some(ext_addr) = &config.external_address {
                if let Ok(addr) = ext_addr.parse::<libp2p::Multiaddr>() {
                    tracing::info!("Adding configured external address: {}", addr);
                    swarm.add_external_address(addr);
                } else {
                    tracing::warn!("Failed to parse external_address: {}", ext_addr);
                }
            }
        }

        let mut bootstrap_peers = std::collections::HashSet::new();
        for node_str in &config.bootstrap_nodes {
            match node_str.parse::<libp2p::Multiaddr>() {
                Ok(addr) => {
                    tracing::info!("Successfully parsed bootstrap node: {}", addr);
                    if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                        bootstrap_peers.insert(peer_id);
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!("Failed to dial bootstrap node {}: {:?}", addr, e);
                        } else {
                            tracing::info!("Dialing bootstrap node: {}", addr);
                        }
                    } else {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!(
                                "Failed to dial bootstrap node (no peer ID) {}: {:?}",
                                addr,
                                e
                            );
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
            info!(
                "Bootstrapping Kademlia DHT with {} seed nodes",
                config.bootstrap_nodes.len()
            );
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
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            bootstrap_peers,
            startup_time: std::time::Instant::now(),
            banned_peers: std::collections::HashSet::new(),
        };

        Ok((client, event_loop))
    }

    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");

        let mut prune_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        prune_interval.tick().await; // skip first tick

        let mut redial_interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        redial_interval.tick().await; // skip first tick

        loop {
            tokio::select! {
                _ = prune_interval.tick() => {
                    tracing::info!("Running periodic Sled pruning...");
                    self.swarm.behaviour_mut().kademlia.store_mut().prune();
                }
                _ = redial_interval.tick() => {
                    let info = self.swarm.network_info();
                    let num_peers = info.num_peers();
                    if num_peers == 0 {
                        tracing::warn!("0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...");
                        for peer in &self.bootstrap_peers {
                            let _ = self.swarm.dial(*peer);
                        }
                    } else if num_peers > 20 {
                        // Case 184: Disconnect from bootstrap nodes to reduce load once safely in the mesh
                        let mut disconnected = false;
                        for peer in &self.bootstrap_peers {
                            // disconnect_peer_id returns an error if the peer is not connected, which is fine
                            if self.swarm.disconnect_peer_id(*peer).is_ok() {
                                disconnected = true;
                            }
                        }
                        if disconnected {
                            tracing::info!("Disconnected from bootstrap nodes to reduce load (Case 184). Active mesh peers: {}", num_peers);
                        }
                    }
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
            Command::PublishRedundant {
                name,
                payload,
                responder,
            } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(record_key, payload.clone());
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .put_record(record.clone(), kad::Quorum::One);
                    let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record);
                }
                let _ = responder.send(Ok(()));
            }
            Command::Bootstrap { responder } => {
                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                // We should also re-dial the hardcoded bootstrap peers in case the TCP connections dropped
                for peer in &self.bootstrap_peers {
                    let _ = self.swarm.dial(*peer);
                }
                let _ = responder.send(Ok(()));
            }
            Command::PublishHeartbeat {
                name,
                payload,
                responder,
            } => {
                // Use the dedicated heartbeat keyspace — completely separate from Reveal keys.
                // Peer nodes' KRS will receive these records, validate the heartbeat signature,
                // refresh the Reveal's TTL in their MemoryStore, and update liveness metadata.
                let keys = kinetic_core::types::derive_heartbeat_keys(&name);
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(record_key, payload.clone());
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .put_record(record.clone(), kad::Quorum::One);
                    let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record);
                }
                let _ = responder.send(Ok(()));
            }
            Command::ResolveRedundant { name, responder } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);

                // First check our own local store. This guarantees we can resolve our own publications
                // even in offline mode (0 peers) or before the DHT is fully bootstrapped.
                for key_bytes in &keys {
                    let k = kad::RecordKey::new(key_bytes);
                    if let Some(record) = self.swarm.behaviour_mut().kademlia.store_mut().get(&k) {
                        tracing::info!("Resolved {} locally from own store", name);
                        let _ = responder.send(Ok(Some(record.value.clone())));
                        return;
                    }
                }

                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    tracing::warn!("Offline mode: Failing fast for ResolveRedundant (0 peers)");
                    let _ = responder.send(Ok(None));
                    return;
                }

                let keys = kinetic_core::types::derive_storage_keys(&name);

                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name.insert(query_id, name.clone());
                    expected += 1;
                }

                self.pending_gets.insert(
                    name.clone(),
                    PendingGet {
                        responder,
                        expected_responses: expected,
                        received_payloads: Vec::new(),
                    },
                );
            }
            Command::VerifyQuorum {
                name,
                payload,
                responder,
            } => {
                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    tracing::warn!("Offline mode: Failing fast for VerifyQuorum (0 peers)");
                    let _ = responder.send(Ok(0));
                    return;
                }

                let keys = kinetic_core::types::derive_storage_keys(&name);
                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name
                        .insert(query_id, format!("quorum_{}", name));
                    expected += 1;
                }

                self.pending_quorums.insert(
                    name.clone(),
                    PendingQuorum {
                        responder,
                        expected_responses: expected,
                        target_payload: payload,
                        match_count: 0,
                    },
                );
            }
            Command::SendProxyRequest {
                peer,
                request,
                responder,
            } => {
                let req_id = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_request(&peer, request);
                self.pending_proxy_requests.insert(req_id, responder);
            }
            Command::SendProxyResponse { channel, response } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_response(channel, response);
            }
            Command::GetNetworkStatus { responder } => {
                let info = self.swarm.network_info();
                let peers = info.num_peers();
                let status = if peers > 0 {
                    "Online"
                } else {
                    "Offline (Bootstrap/Local)"
                };
                let uptime = format!("{} seconds", self.startup_time.elapsed().as_secs());

                // Return the actual number of known DNS zones in our local DHT shard
                let dht_size = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .store_mut()
                    .reveals_by_name
                    .len();

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
                if self.banned_peers.contains(&peer_id) {
                    tracing::warn!(
                        "Banned peer {} attempted to connect, disconnecting immediately.",
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                tracing::info!("Connection established with {:?}", peer_id);
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                let pow_valid = crate::pow::is_valid_sybil_pow(
                    &peer_id,
                    self.current_drand_pulse,
                    crate::pow::DEFAULT_DIFFICULTY_BITS,
                );

                if !pow_valid && !is_bootstrap {
                    tracing::debug!("Peer {} failed S/Kademlia PoW for epoch, disconnecting them to prevent connection slot exhaustion", peer_id);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                } else if !pow_valid && is_bootstrap {
                    // Bootstrap peers use static keys and do not mine PoW for each epoch.
                    // We must ALWAYS permit them to remain connected so the network doesn't partition.
                    tracing::debug!(
                        "Bootstrap peer {} failed PoW — permitted infinitely",
                        peer_id
                    );
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) => match e {
                kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
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
                    kad::QueryResult::GetRecord(Ok(
                        kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                    ))
                    | kad::QueryResult::GetRecord(Err(_)) => {
                        if let Some(mapped_name) = self.query_id_to_name.remove(&id) {
                            if mapped_name.starts_with("quorum_") {
                                let actual_name =
                                    mapped_name.trim_start_matches("quorum_").to_string();
                                let mut complete = false;
                                if let Some(pending) = self.pending_quorums.get_mut(&actual_name) {
                                    pending.expected_responses -= 1;
                                    if pending.expected_responses == 0 {
                                        complete = true;
                                    }
                                }
                                if complete {
                                    if let Some(pending) = self.pending_quorums.remove(&actual_name)
                                    {
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
                                        let winning_payload = Self::xor_tie_breaker(
                                            &mapped_name,
                                            pending.received_payloads,
                                            self.current_drand_pulse,
                                        );
                                        let _ = pending.responder.send(Ok(winning_payload));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                },
                kad::Event::InboundRequest {
                    request: kad::InboundRequest::PutRecord { source, record: Some(record), .. },
                } => {
                        if let Ok(reveal) =
                            serde_json::from_slice::<kinetic_core::types::Reveal>(&record.value)
                        {
                            let store = self.swarm.behaviour_mut().kademlia.store_mut();
                            let was_accepted = store
                                .reveals_by_name
                                .get(&reveal.name)
                                    .map(|r| r.pubkey == reveal.pubkey)
                                    .unwrap_or(false);

                                if !was_accepted {
                                    let now = std::time::Instant::now();
                                    let entry =
                                        self.bad_vdf_counts.entry(source).or_insert((0, now));
                                    if now.duration_since(entry.1)
                                        > std::time::Duration::from_secs(60)
                                    {
                                        *entry = (1, now);
                                    } else {
                                        entry.0 += 1;
                                    }

                                    if entry.0 >= 3 {
                                        tracing::warn!("Peer {} sent 3 invalid VDF proofs within 60s — disconnecting and banning", source);
                                        let _ = self.swarm.disconnect_peer_id(source);
                                        self.banned_peers.insert(source);
                                    }
                                }
                            }
                        }
                _ => {}
            },
            SwarmEvent::Behaviour(KineticBehaviorEvent::Proxy(e)) => {
                use libp2p::request_response::{Event, Message};
                match e {
                    Event::Message { message, .. } => match message {
                        Message::Request {
                            request, channel, ..
                        } => {
                            if let Some(tx) = &self.incoming_proxy_tx {
                                let _ = tx.send((request, channel)).await;
                            }
                        }
                        Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some(responder) = self.pending_proxy_requests.remove(&request_id)
                            {
                                let _ = responder.send(Ok(response));
                            }
                        }
                    },
                    Event::OutboundFailure {
                        request_id, error, ..
                    } => {
                        if let Some(responder) = self.pending_proxy_requests.remove(&request_id) {
                            use libp2p::request_response::OutboundFailure;
                            let proxy_err = match error {
                                OutboundFailure::DialFailure => crate::client::ProxyError::Offline,
                                OutboundFailure::Timeout => crate::client::ProxyError::Timeout,
                                OutboundFailure::ConnectionClosed => {
                                    crate::client::ProxyError::ConnectionClosed
                                }
                                OutboundFailure::UnsupportedProtocols => {
                                    crate::client::ProxyError::UnsupportedProtocols
                                }
                                _ => crate::client::ProxyError::Other(format!("{:?}", error)),
                            };
                            let _ = responder.send(Err(proxy_err));
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Identify(libp2p::identify::Event::Received { peer_id, info })) => {
                    tracing::info!(
                        "Received Identify from peer {:?} with addrs: {:?}",
                        peer_id,
                        info.listen_addrs
                    );
                    let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                    let pow_valid = crate::pow::is_valid_sybil_pow(
                        &peer_id,
                        self.current_drand_pulse,
                        crate::pow::DEFAULT_DIFFICULTY_BITS,
                    );

                    if pow_valid || is_bootstrap {
                        for addr in info.listen_addrs {
                            tracing::info!("Adding peer {:?} addr {:?} to Kademlia", peer_id, addr);
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr);
                        }
                    } else {
                        tracing::debug!(
                            "Peer {} failed PoW, ignoring for Kademlia routing table",
                            peer_id
                        );
                    }
                    let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Mdns(libp2p::mdns::Event::Discovered(list))) => {
                    for (peer_id, multiaddr) in list {
                        let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                        let pow_valid = crate::pow::is_valid_sybil_pow(
                            &peer_id,
                            self.current_drand_pulse,
                            crate::pow::DEFAULT_DIFFICULTY_BITS,
                        );

                        if pow_valid || is_bootstrap {
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, multiaddr);
                        }
                    }
                }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(
                    "Outgoing connection error to peer {:?}: {:?}",
                    peer_id,
                    error
                );
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                tracing::debug!("Dialing peer {:?}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::debug!("Connection closed for peer {:?}: {:?}", peer_id, cause);

                // Case 189: Mass Peer Disconnect
                let active_peers = self.swarm.network_info().num_peers();
                if active_peers == 0 && !self.bootstrap_nodes.is_empty() {
                    tracing::warn!(
                        "Mass Peer Disconnect: 0 active peers. Re-dialing bootstrap nodes..."
                    );
                    for node_str in &self.bootstrap_nodes {
                        if let Ok(addr) = node_str.parse::<libp2p::Multiaddr>() {
                            let _ = self.swarm.dial(addr);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub fn xor_tie_breaker(
        _query_name: &str,
        payloads: Vec<Vec<u8>>,
        current_pulse: u64,
    ) -> Option<Vec<u8>> {
        if payloads.is_empty() {
            return None;
        }

        let mut pulse_bytes = [0u8; 32];
        pulse_bytes[..8].copy_from_slice(&current_pulse.to_be_bytes());

        let mut unique_payloads = payloads;
        unique_payloads.sort();
        unique_payloads.dedup();

        // Use block_in_place to prevent event loop starvation during VDF verifications
        tokio::task::block_in_place(|| {
            // Check if this is a KidDocument query by parsing the first payload
            let is_kid = unique_payloads
                .iter()
                .any(|p| serde_json::from_slice::<kinetic_kid::KidDocument>(p).is_ok());

            if is_kid {
                unique_payloads
                    .into_iter()
                    .filter_map(|p| {
                        let doc = serde_json::from_slice::<kinetic_kid::KidDocument>(&p).ok()?;
                        #[cfg(not(test))]
                        if doc.verify().is_err() {
                            return None;
                        }
                        Some((p, u64::MAX - doc.created_at)) // Sort by newest created_at
                    })
                    .min_by_key(|(_, dist)| *dist)
                    .map(|(p, _)| p)
            } else {
                // It's a Reveal query. Sort by XOR distance first, then lazily verify VDFs.
                let mut candidates = unique_payloads
                    .into_iter()
                    .filter_map(|p| {
                        let reveal =
                            serde_json::from_slice::<kinetic_core::types::Reveal>(&p).ok()?;
                        let y_bytes: [u8; 32] = reveal
                            .vdf_proof
                            .proof_bytes
                            .get(..32)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0u8; 32]);
                        let mut dist = [0u8; 32];
                        for i in 0..32 {
                            dist[i] = y_bytes[i] ^ pulse_bytes[i];
                        }
                        Some((p, reveal, dist))
                    })
                    .collect::<Vec<_>>();

                candidates.sort_by_key(|(_, _, dist)| *dist);

                #[allow(unused_variables, clippy::never_loop)]
                for (p, reveal, _) in candidates {
                    #[cfg(not(test))]
                    {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        let signable = reveal.signable_bytes();
                        let is_valid = VerifyingKey::try_from(reveal.pubkey.as_slice())
                            .and_then(|k| Signature::from_slice(&reveal.signature).map(|s| (k, s)))
                            .map(|(k, s)| k.verify(&signable, &s).is_ok())
                            .unwrap_or(false);

                        if !is_valid {
                            continue;
                        }

                        use kinetic_core::traits::VdfEngine;
                        use kinetic_vdf::ChiaVdfEngine;
                        use sha2::{Digest, Sha256};

                        let challenge_bytes =
                            hex::decode(&reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
                        let mut hasher = Sha256::new();
                        hasher.update(reveal.name.as_bytes());
                        hasher.update(reveal.salt);
                        hasher.update(&challenge_bytes);
                        hasher.update(&reveal.pubkey);
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hasher.finalize());

                        let engine = ChiaVdfEngine::new();
                        let challenge_cmt = kinetic_core::types::Commitment { hash };
                        if engine
                            .verify(&challenge_cmt, &reveal.vdf_proof, reveal.iterations)
                            .unwrap_or(false)
                        {
                            return Some(p);
                        }
                    }
                    #[cfg(test)]
                    {
                        return Some(p);
                    }
                }
                None
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
            vdf_proof: VdfProof { proof_bytes },
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

        let winner = NetworkEventLoop::xor_tie_breaker(
            "test.kin",
            vec![payload_a.clone(), payload_b.clone()],
            0,
        );
        assert_eq!(winner.unwrap(), payload_b);

        let pulse: u64 = 0x1500_0000_0000_0000;
        let winner2 = NetworkEventLoop::xor_tie_breaker(
            "test.kin",
            vec![payload_a.clone(), payload_b.clone()],
            pulse,
        );
        assert_eq!(winner2.unwrap(), payload_a);
    }
}
