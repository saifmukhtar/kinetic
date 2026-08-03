use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::info;
#[cfg(not(target_arch = "wasm32"))]
use libp2p::kad;

#[cfg(not(target_arch = "wasm32"))]
use crate::behavior::KineticBehavior;
use crate::client::{NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};
#[cfg(not(target_arch = "wasm32"))]
use crate::store::KineticRecordStore;

#[cfg(not(target_arch = "wasm32"))]
use super::fullnode;
use super::lightnode;

impl super::core::NetworkEventLoop {
    /// Initializes a new P2P Swarm and returns the client handle and the event loop.
    pub fn new(
        config: NetworkConfig,
        local_key: libp2p::identity::Keypair,
        storage: Arc<dyn kinetic_core::traits::StorageEngine>,
        drand_kyn_rx: watch::Receiver<u64>,
        incoming_proxy_tx: Option<
            mpsc::Sender<(
                ProxyRequest,
                libp2p::request_response::ResponseChannel<ProxyResponse>,
            )>,
        >,
        gossip_tx: Option<
            tokio::sync::broadcast::Sender<(
                String,
                Vec<u8>,
                libp2p::gossipsub::MessageId,
                libp2p::PeerId,
            )>,
        >,
        vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    ) -> std::result::Result<(NetworkClient, Self), anyhow::Error> {
        let (tx, rx) = mpsc::channel(32);

        let (mut swarm, client) = if config.mode == NetworkMode::LightNode {
            lightnode::build_light_swarm(&config, local_key, storage.clone(), vdf_engine, tx)?
        } else {
            #[cfg(target_arch = "wasm32")]
            panic!("FullNode mode is not supported on WebAssembly");
            
            #[cfg(not(target_arch = "wasm32"))]
            fullnode::build_full_swarm(&config, local_key, storage.clone(), vdf_engine, tx)?
        };

        let mut bootstrap_peers = rustc_hash::FxHashSet::default();
        for addr in &config.bootstrap_nodes {
            tracing::info!("Successfully loaded bootstrap node: {}", addr);
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                bootstrap_peers.insert(peer_id);
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
            }
            if let Err(e) = swarm.dial(addr.clone()) {
                tracing::warn!("Failed to dial bootstrap node {}: {:?}", addr, e);
            } else {
                tracing::info!("Dialing bootstrap node: {}", addr);
            }
        }

        if !config.bootstrap_nodes.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
            info!(
                "Bootstrapping Kademlia DHT with {} seed nodes",
                config.bootstrap_nodes.len()
            );
        }

        // Seed domains are now deferred to NetworkEventLoop::run() to avoid blocking the thread here.

        let event_loop = Self {
            swarm,
            command_receiver: rx,
            pending_gets: rustc_hash::FxHashMap::default(),
            pending_quorums: rustc_hash::FxHashMap::default(),
            pending_puts: rustc_hash::FxHashMap::default(),
            query_id_to_name: rustc_hash::FxHashMap::default(),
            pending_proxy_requests: rustc_hash::FxHashMap::default(),
            incoming_proxy_tx,
            gossip_tx,
            bad_vdf_counts: lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()),
            current_drand_kyn: config.initial_drand_kyn,
            drand_kyn_rx,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            bootstrap_peers,
            startup_time: web_time::Instant::now(),
            disable_pow: config.disable_pow,
            banned_peers: {
                let mut peers = lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap());
                if let Ok(iter) = storage.scan_prefix(
                    kinetic_core::constants::DB_PREFIX_BANNED_PEER.as_bytes(),
                    None,
                ) {
                    for (key_bytes, val_bytes) in iter {
                        let prefix_len = kinetic_core::constants::DB_PREFIX_BANNED_PEER.len();
                        if key_bytes.len() > prefix_len {
                            if let Ok(peer_id_str) = std::str::from_utf8(&key_bytes[prefix_len..]) {
                                if let Ok(peer_id) = peer_id_str.parse::<libp2p::PeerId>() {
                                    if val_bytes.len() == 8 {
                                        let expire = u64::from_be_bytes(
                                            val_bytes[..8].try_into().unwrap_or([0; 8]),
                                        );
                                        let now = web_time::SystemTime::now()
                                            .duration_since(web_time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        if expire > now {
                                            peers.put(peer_id, expire);
                                        } else {
                                            let _ = storage.delete(&key_bytes);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                peers
            },
            seed_domain: config.seed_domain.clone(),

            bootstrap_connection_time: rustc_hash::FxHashMap::default(),
            nat_status: "Unknown".to_string(),
            loopback_tx: None,
            pow_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            light_nodes: rustc_hash::FxHashSet::default(),
            light_node_ips: rustc_hash::FxHashMap::default(),
        };

        Ok((client, event_loop))
    }

    #[doc(hidden)]
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_test_node(
        config: NetworkConfig,
        local_key: libp2p::identity::Keypair,
        storage: Arc<dyn kinetic_core::traits::StorageEngine>,
        vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    ) -> std::result::Result<(NetworkClient, Self), anyhow::Error> {
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_quic();

        let storage_clone = storage.clone();
        let vdf_engine_clone = vdf_engine.clone();

        let mut swarm = builder
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
            .with_behaviour(move |key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let store = KineticRecordStore::new(
                    peer_id,
                    storage_clone,
                    0,
                    std::num::NonZeroUsize::new(100).unwrap(),
                    100,
                    vdf_engine_clone.clone(),
                );
                let mut kad_config = kad::Config::default();
                kad_config.set_protocol_names(vec![libp2p::StreamProtocol::try_from_owned(
                    format!("/{}/kad/2.0.0", kinetic_core::constants::NETWORK_ID),
                )
                .unwrap()]);

                kad_config.set_query_timeout(std::time::Duration::from_secs(5));

                let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
                kademlia.set_mode(Some(kad::Mode::Server));

                let gossipsub = libp2p::gossipsub::Behaviour::new(
                    libp2p::gossipsub::MessageAuthenticity::Signed(key.clone()),
                    libp2p::gossipsub::ConfigBuilder::default()
                        .validation_mode(libp2p::gossipsub::ValidationMode::Strict)
                        .validate_messages()
                        .build()
                        .unwrap(),
                )
                .unwrap();

                let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                    format!("/{}/1.0.0", kinetic_core::constants::NETWORK_ID),
                    key.public(),
                ));
                let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());

                KineticBehavior {
                    relay_client,
                    dcutr: libp2p::dcutr::Behaviour::new(peer_id),
                    identify,
                    ping,
                    proxy: libp2p::request_response::cbor::Behaviour::new(
                        [(
                            libp2p::StreamProtocol::try_from_owned(format!(
                                "/{}/proxy/1.0.0",
                                kinetic_core::constants::NETWORK_ID
                            ))
                            .unwrap(),
                            libp2p::request_response::ProtocolSupport::Full,
                        )],
                        Default::default(),
                    ),
                    stream: libp2p_stream::Behaviour::new(),
                    kademlia,
                    gossipsub,
                    autonat: libp2p::autonat::Behaviour::new(peer_id, Default::default()),
                    upnp: libp2p::swarm::behaviour::toggle::Toggle::from(None),
                    relay_server: libp2p::swarm::behaviour::toggle::Toggle::from(None),
                    mdns: libp2p::swarm::behaviour::toggle::Toggle::from(None),
                }
            })
            .unwrap()
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(web_time::Duration::from_secs(300))
            })
            .build();

        let (tx, rx) = mpsc::channel(32);
        let client = NetworkClient::new(tx.clone(), libp2p_stream::Behaviour::new().new_control());

        let (_, drand_kyn_rx) = watch::channel(0);

        for addr in &config.listen_addrs {
            if !addr.is_empty() {
                let _ = swarm.listen_on(addr.clone());
            }
        }
        for quic_addr in &config.quic_listen_addrs {
            if !quic_addr.is_empty() {
                let _ = swarm.listen_on(quic_addr.clone());
            }
        }

        let mut bootstrap_peers = rustc_hash::FxHashSet::default();
        for addr in &config.bootstrap_nodes {
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                bootstrap_peers.insert(peer_id);
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
            }
            let _ = swarm.dial(addr.clone());
        }

        if !config.bootstrap_nodes.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        let event_loop = Self {
            swarm,
            command_receiver: rx,
            pending_gets: Default::default(),
            pending_quorums: Default::default(),
            pending_puts: Default::default(),
            query_id_to_name: Default::default(),
            pending_proxy_requests: Default::default(),
            incoming_proxy_tx: None,
            gossip_tx: None,
            bad_vdf_counts: lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()),
            current_drand_kyn: 0,
            drand_kyn_rx,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            bootstrap_peers: Default::default(),
            startup_time: web_time::Instant::now(),
            disable_pow: config.disable_pow,
            banned_peers: lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()),
            seed_domain: vec![],

            bootstrap_connection_time: Default::default(),
            nat_status: "Unknown".to_string(),
            loopback_tx: None,
            pow_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            light_nodes: rustc_hash::FxHashSet::default(),
            light_node_ips: rustc_hash::FxHashMap::default(),
        };

        Ok((client, event_loop))
    }
}
