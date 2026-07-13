use libp2p::kad;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::{NetworkClient, NetworkConfig, NetworkMode, ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;
use kinetic_storage::SledStorage;

impl super::core::NetworkEventLoop {
    /// Initializes a new P2P Swarm and returns the client handle and the event loop.
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
        gossip_tx: Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
    ) -> std::result::Result<(NetworkClient, Self), anyhow::Error> {
        info!("Initializing Kinetic P2P Swarm on {}", config.listen_addr);

        #[cfg(all(not(target_os = "android"), not(target_arch = "wasm32")))]
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_dns()?;

        #[cfg(all(target_os = "android", not(target_arch = "wasm32")))]
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().port_reuse(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?;

        #[cfg(target_arch = "wasm32")]
        let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_wasm_bindgen()
            .with_other_transport(|key| {
                use libp2p::core::Transport;
                libp2p::websocket_websys::Transport::default()
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(libp2p::noise::Config::new(key).unwrap())
                    .multiplex(libp2p::yamux::Config::default())
                    .map(|(peer, muxer), _| {
                        (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer))
                    })
            })
            .expect("Valid websocket websys transport");

        #[cfg(not(target_arch = "wasm32"))]
        let (control_tx, control_rx) = std::sync::mpsc::channel();
        let storage_clone = storage.clone();
        let mode = config.mode.clone();
        let initial_drand_pulse = config.initial_drand_pulse;
        let _enable_mdns = config.enable_mdns;

        let mut swarm = builder
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
            .with_behaviour(move |key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let store = KineticRecordStore::new(peer_id, storage_clone, initial_drand_pulse);
                let mut kad_config = kad::Config::default();
                kad_config
                    .set_protocol_names(vec![libp2p::StreamProtocol::new("/kinetic/kad/2.0.0")]);
                let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
                if mode == NetworkMode::LightClient {
                    kademlia.set_mode(Some(kad::Mode::Client));
                } else {
                    kademlia.set_mode(Some(kad::Mode::Server));
                }

                let gossipsub_config = if mode == NetworkMode::LightClient {
                    // LightClient mesh params: mesh_n_low < mesh_n < mesh_n_high (strict)
                    // gossipsub panics with MeshParametersInvalid if this invariant is violated.
                    libp2p::gossipsub::ConfigBuilder::default()
                        .heartbeat_interval(web_time::Duration::from_secs(10)) // Less frequent heartbeats (save battery)
                        .prune_backoff(web_time::Duration::from_secs(60))
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

                #[cfg(not(target_arch = "wasm32"))]
                let stream = libp2p_stream::Behaviour::new();
                #[cfg(not(target_arch = "wasm32"))]
                let _ = control_tx.send(stream.new_control());

                #[cfg(not(target_arch = "wasm32"))]
                let mdns = if _enable_mdns {
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

                let autonat = libp2p::autonat::Behaviour::new(
                    peer_id,
                    libp2p::autonat::Config {
                        boot_delay: std::time::Duration::from_secs(15),
                        retry_interval: std::time::Duration::from_secs(90),
                        refresh_interval: std::time::Duration::from_secs(3600),
                        ..Default::default()
                    },
                );

                #[cfg(not(target_arch = "wasm32"))]
                let upnp = libp2p::swarm::behaviour::toggle::Toggle::from(Some(
                    libp2p::upnp::tokio::Behaviour::default(),
                ));

                #[cfg(not(target_arch = "wasm32"))]
                let relay_server = if mode == NetworkMode::FullNode {
                    libp2p::swarm::behaviour::toggle::Toggle::from(Some(
                        libp2p::relay::Behaviour::new(
                            peer_id,
                            libp2p::relay::Config {
                                max_circuits: 16,
                                max_circuits_per_peer: 4,
                                circuit_src_rate_limiters: vec![],
                                max_circuit_duration: std::time::Duration::from_secs(2 * 60),
                                max_circuit_bytes: 1024 * 1024 * 4,
                                reservation_rate_limiters: vec![],
                                max_reservations: 128,
                                max_reservations_per_peer: 4,
                                reservation_duration: std::time::Duration::from_secs(60 * 60),
                            },
                        ),
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
                    #[cfg(not(target_arch = "wasm32"))]
                    stream,
                    kademlia,
                    gossipsub,
                    autonat,
                    #[cfg(not(target_arch = "wasm32"))]
                    upnp,
                    #[cfg(not(target_arch = "wasm32"))]
                    relay_server,
                    #[cfg(not(target_arch = "wasm32"))]
                    mdns,
                }
            })
            .unwrap()
            .with_swarm_config(|c| {
                if config.mode == NetworkMode::LightClient {
                    c.with_idle_connection_timeout(web_time::Duration::from_secs(60))
                // Aggressive power saving for mobile
                } else {
                    c.with_idle_connection_timeout(web_time::Duration::from_secs(30 * 24 * 3600))
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

        #[cfg(not(target_arch = "wasm32"))]
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
        #[cfg(not(target_arch = "wasm32"))]
        let stream_control = control_rx
            .recv()
            .unwrap_or_else(|_| panic!("Stream control not sent (unless wasm32)"));
        #[cfg(not(target_arch = "wasm32"))]
        let client = NetworkClient::new(tx.clone(), stream_control);
        #[cfg(target_arch = "wasm32")]
        let client = NetworkClient::new(tx.clone());

        let event_loop = Self {
            swarm,
            command_receiver: rx,
            pending_gets: HashMap::new(),
            pending_quorums: HashMap::new(),
            query_id_to_name: HashMap::new(),
            pending_proxy_requests: HashMap::new(),
            incoming_proxy_tx,
            gossip_tx,
            bad_vdf_counts: HashMap::new(),
            current_drand_pulse: config.initial_drand_pulse,
            drand_pulse_rx,
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            bootstrap_peers,
            startup_time: web_time::Instant::now(),
            banned_peers: {
                let mut peers = std::collections::HashSet::new();
                if let Ok(iter) = storage.scan_prefix(b"kinetic_banned_peer:") {
                    for (key_bytes, val_bytes) in iter {
                        let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                        let peer_id_str = key_str.trim_start_matches("kinetic_banned_peer:");
                        if let Ok(peer_id) = peer_id_str.parse::<libp2p::PeerId>() {
                            if val_bytes.len() == 8 {
                                let expire =
                                    u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0; 8]));
                                let now = web_time::SystemTime::now()
                                    .duration_since(web_time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                if expire > now {
                                    peers.insert(peer_id);
                                }
                            }
                        }
                    }
                }
                peers
            },
            commitment_miss_counts: HashMap::new(),
            bootstrap_connection_time: HashMap::new(),
            nat_status: "Unknown".to_string(),
        };

        Ok((client, event_loop))
    }
}
