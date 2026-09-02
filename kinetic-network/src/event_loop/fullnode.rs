#![cfg(not(target_arch = "wasm32"))]

use libp2p::kad;
use std::sync::Arc;
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::{NetworkClient, NetworkConfig, ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;

pub(crate) fn build_full_swarm(
    config: &NetworkConfig,
    local_key: libp2p::identity::Keypair,
    storage: Arc<dyn kinetic_core::traits::StorageEngine>,
    vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    tx: tokio::sync::mpsc::Sender<crate::client::Command>,
) -> Result<(libp2p::Swarm<KineticBehavior>, NetworkClient), anyhow::Error> {
    info!(
        "Initializing Kinetic FULL Node P2P Swarm on {:?}",
        config.listen_addrs
    );

    let yamux_config = || {
        let mut config = libp2p::yamux::Config::default();
        config.set_max_num_streams(1024);
        config
    };

    let builder_tcp = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            yamux_config,
        )?;

    #[cfg(not(target_os = "android"))]
    let builder = builder_tcp
        .with_quic()
        .with_other_transport(|key| {
            libp2p_webrtc::tokio::Transport::new(
                key.clone(),
                libp2p_webrtc::tokio::Certificate::generate(&mut rand::thread_rng()).expect("Failed to generate WebRTC cert"),
            )
        })
        .expect("Failed to inject WebRTC")
        .with_dns()?;

    #[cfg(target_os = "android")]
    let builder = builder_tcp
        .with_quic()
        .with_other_transport(|key| {
            libp2p_webrtc::tokio::Transport::new(
                key.clone(),
                libp2p_webrtc::tokio::Certificate::generate(&mut rand::thread_rng()).expect("Failed to generate WebRTC cert"),
            )
        })
        .expect("Failed to inject WebRTC");

    let (control_tx, control_rx) = std::sync::mpsc::channel();
    let initial_kyn = config.initial_kyn;
    let enable_mdns = config.enable_mdns;
    let enable_upnp = config.enable_upnp;
    let enable_relay_server = config.enable_relay_server;
    let lru_cache_size = config.lru_cache_size;
    let max_reveals_per_hour = config.max_reveals_per_hour;
    let test_mode = config.test_mode;

    let mut swarm = builder
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(move |key, relay_client| {
            let peer_id = key.public().to_peer_id();
            let store = KineticRecordStore::new(
                peer_id,
                storage.clone(),
                initial_kyn,
                lru_cache_size,
                max_reveals_per_hour,
                vdf_engine.clone(),
            );

            let mut kad_config = kad::Config::new(
                libp2p::StreamProtocol::try_from_owned(format!(
                    "/{}/kad/2.0.0",
                    kinetic_core::constants::NETWORK_SALT_HEX
                ))
                .unwrap()
            );
            kad_config
                .set_max_packet_size(kinetic_core::constants::LIMITS_P2P_MAX_PACKET_SIZE)
                .set_provider_record_ttl(Some(std::time::Duration::from_secs(
                    kinetic_core::constants::KADEMLIA_PROVIDER_RECORD_TTL_SECS,
                )))
                .set_provider_publication_interval(Some(std::time::Duration::from_secs(
                    kinetic_core::constants::KADEMLIA_PUBLICATION_INTERVAL_SECS,
                )));

            if test_mode {
                kad_config.set_query_timeout(std::time::Duration::from_secs(5));
            } else {
                // In production, keep longer timeout or defaults
            }

            let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
            // Full Node MUST be a Server
            kademlia.set_mode(Some(kad::Mode::Server));

            let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
                .validation_mode(libp2p::gossipsub::ValidationMode::Strict)
                .max_transmit_size(kinetic_core::constants::LIMITS_P2P_MAX_PACKET_SIZE)
                .validate_messages()
                .build()
                .expect("Valid gossipsub config");

            let gossipsub = libp2p::gossipsub::Behaviour::new(
                libp2p::gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("Valid gossipsub config");

            let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                format!("/{}/1.0.0", kinetic_core::constants::NETWORK_SALT_HEX),
                key.public(),
            ));

            let dcutr = libp2p::dcutr::Behaviour::new(peer_id);
            let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());
            let proxy =
                libp2p::request_response::cbor::Behaviour::<ProxyRequest, ProxyResponse>::new(
                    [(
                        libp2p::StreamProtocol::try_from_owned(format!(
                            "/{}/proxy/1.0.0",
                            kinetic_core::constants::NETWORK_SALT_HEX
                        ))
                        .unwrap(),
                        libp2p::request_response::ProtocolSupport::Full,
                    )],
                    libp2p::request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(60)),
                );

            let cdn = libp2p::request_response::cbor::Behaviour::<
                kinetic_types::cdn::CdnRequest,
                kinetic_types::cdn::CdnResponse,
            >::new(
                [(
                    libp2p::StreamProtocol::try_from_owned(format!(
                        "/{}/cdn/1.0.0",
                        kinetic_core::constants::NETWORK_SALT_HEX
                    ))
                    .unwrap(),
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                libp2p::request_response::Config::default(),
            );

            let stream = libp2p_stream::Behaviour::new();
            let _ = control_tx.send(stream.new_control());

            let mdns = if enable_mdns && !test_mode {
                match libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer_id)
                {
                    Ok(behaviour) => {
                        libp2p::swarm::behaviour::toggle::Toggle::from(Some(behaviour))
                    }
                    Err(e) => {
                        let err = kinetic_core::error::P2pError::MdnsBindFailed(e.to_string());
                        tracing::warn!(error_code = err.code(), "{}", err);
                        libp2p::swarm::behaviour::toggle::Toggle::from(None)
                    }
                }
            } else {
                libp2p::swarm::behaviour::toggle::Toggle::from(None)
            };

            let autonat = if test_mode {
                libp2p::autonat::Behaviour::new(
                    peer_id,
                    libp2p::autonat::Config {
                        boot_delay: std::time::Duration::from_secs(2),
                        retry_interval: std::time::Duration::from_secs(2),
                        refresh_interval: std::time::Duration::from_secs(3600),
                        ..Default::default()
                    },
                )
            } else {
                libp2p::autonat::Behaviour::new(
                    peer_id,
                    libp2p::autonat::Config {
                        boot_delay: std::time::Duration::from_secs(10),
                        retry_interval: std::time::Duration::from_secs(90),
                        refresh_interval: std::time::Duration::from_secs(3600),
                        ..Default::default()
                    },
                )
            };

            let upnp = if enable_upnp && !test_mode {
                libp2p::swarm::behaviour::toggle::Toggle::from(Some(
                    libp2p::upnp::tokio::Behaviour::default(),
                ))
            } else {
                libp2p::swarm::behaviour::toggle::Toggle::from(None)
            };

            let relay_server = if enable_relay_server && !test_mode {
                libp2p::swarm::behaviour::toggle::Toggle::from(Some(libp2p::relay::Behaviour::new(
                    peer_id,
                    libp2p::relay::Config {
                        max_circuits: 1024,
                        max_circuits_per_peer: 10,
                        circuit_src_rate_limiters: vec![],
                        max_circuit_duration: std::time::Duration::from_secs(2 * 60),
                        max_circuit_bytes: kinetic_core::constants::LIMITS_P2P_MAX_CIRCUIT_BYTES
                            as u64,
                        reservation_rate_limiters: vec![],
                        max_reservations: 1024,
                        max_reservations_per_peer: 2,
                        reservation_duration: std::time::Duration::from_secs(5 * 60),
                    },
                )))
            } else {
                libp2p::swarm::behaviour::toggle::Toggle::from(None)
            };

            KineticBehavior {
                relay_client,
                dcutr,
                identify,
                ping,
                proxy,
                cdn,
                stream,
                kademlia,
                gossipsub,
                autonat,
                upnp,
                relay_server,
                mdns,
            }
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(web_time::Duration::from_secs(300)))
        .build();

    // Full nodes listen on TCP and QUIC
    let mut tcp_success = false;
    for addr in &config.listen_addrs {
        if !addr.is_empty() {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => {
                    tracing::info!("Listening on TCP: {}", addr);
                    tcp_success = true;
                }
                Err(e) => tracing::warn!(
                    error = ?kinetic_core::error::SystemError::PortInUse(format!("{}: {}", addr, e)),
                    "Failed to bind TCP on {}", addr
                ),
            }
        }
    }
    let mut quic_success = false;
    for quic_addr in &config.quic_listen_addrs {
        if !quic_addr.is_empty() {
            match swarm.listen_on(quic_addr.clone()) {
                Ok(_) => {
                    tracing::info!("Listening on QUIC: {}", quic_addr);
                    quic_success = true;
                }
                Err(e) => tracing::warn!(
                    error = ?kinetic_core::error::SystemError::PortInUse(format!("{}: {}", quic_addr, e)),
                    "Failed to bind QUIC on {}", quic_addr
                ),
            }
        }
    }
    if !quic_success && !config.quic_listen_addrs.is_empty() {
        tracing::warn!(
            error = ?kinetic_core::error::SystemError::PortInUse("All QUIC addresses".into()),
            "Failed to bind any QUIC addresses. Falling back to TCP only."
        );
    }

    if !tcp_success && !quic_success {
        return Err(anyhow::anyhow!(
            "FATAL: Failed to bind to any TCP or QUIC listening ports. Cannot operate as a Full Node."
        ));
    }

    if let Some(addr) = &config.external_address {
        tracing::info!("Adding configured external address: {}", addr);
        swarm.add_external_address(addr.clone());
    }

    let stream_control = control_rx.recv().unwrap();
    let client = NetworkClient::new(tx, stream_control);

    Ok((swarm, client))
}
