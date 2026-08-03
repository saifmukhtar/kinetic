use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use crate::client::{NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};

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

        // Kademlia bootstrap is deferred until after connection establishment in NetworkEventLoop::run()

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
                                        let now = config.initial_drand_kyn;
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
            has_bootstrapped: false,
            proxy_cdn_usage: (0, web_time::Instant::now()),
        };

        Ok((client, event_loop))
    }

}
