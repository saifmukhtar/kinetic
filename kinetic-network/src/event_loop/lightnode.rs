use libp2p::kad;
use std::sync::Arc;
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::{NetworkClient, NetworkConfig, ProxyRequest, ProxyResponse};
use crate::store::KineticRecordStore;

#[allow(clippy::type_complexity)]
pub(crate) fn build_light_swarm(
    config: &NetworkConfig,
    local_key: libp2p::identity::Keypair,
    storage: Arc<dyn kinetic_core::traits::StorageEngine>,
    vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    tx: tokio::sync::mpsc::Sender<crate::client::Command>,
) -> Result<(libp2p::Swarm<KineticBehavior>, NetworkClient), anyhow::Error> {
    info!("Initializing Kinetic LIGHT Node P2P Swarm");

    #[cfg(target_arch = "wasm32")]
    let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_wasm_bindgen()
        .with_other_transport(|key| {
            use libp2p::core::Transport;
            libp2p::websocket_websys::Transport::default()
                .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                .authenticate(libp2p::noise::Config::new(key).unwrap())
                .multiplex(libp2p::yamux::Config::default())
                .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        })
        .expect("Valid websocket websys transport");

    #[cfg(not(target_arch = "wasm32"))]
    let yamux_config = || {
        let mut config = libp2p::yamux::Config::default();
        config.set_max_num_streams(1024);
        config
    };

    #[cfg(all(not(target_os = "android"), not(target_arch = "wasm32")))]
    let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().port_reuse(false),
            libp2p::noise::Config::new,
            yamux_config,
        )?
        .with_quic()
        .with_dns()?;

    #[cfg(all(target_os = "android", not(target_arch = "wasm32")))]
    let builder = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().port_reuse(false),
            libp2p::noise::Config::new,
            yamux_config,
        )?
        .with_quic();

    #[cfg(not(target_arch = "wasm32"))]
    let (control_tx, control_rx) = std::sync::mpsc::channel();

    let initial_kyn = config.initial_kyn;
    let lru_cache_size = config.lru_cache_size;
    let max_reveals_per_hour = config.max_reveals_per_hour;
    let test_mode = config.test_mode;

    let swarm = builder
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

            let mut kad_config = kad::Config::default();
            kad_config
                .set_protocol_names(vec![
                    libp2p::StreamProtocol::try_from_owned(format!(
                        "/{}/kad/2.0.0",
                        kinetic_core::constants::NETWORK_SALT_HEX
                    ))
                    .unwrap(),
                ])
                .set_max_packet_size(kinetic_core::constants::LIMITS_P2P_MAX_PACKET_SIZE)
                .set_provider_record_ttl(Some(std::time::Duration::from_secs(
                    kinetic_core::constants::KADEMLIA_PROVIDER_RECORD_TTL_SECS,
                )))
                .set_provider_publication_interval(Some(std::time::Duration::from_secs(
                    kinetic_core::constants::KADEMLIA_PUBLICATION_INTERVAL_SECS,
                )));

            #[cfg(test)]
            kad_config.set_query_timeout(std::time::Duration::from_secs(5));

            let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
            // Light Node MUST be a Client (Parasite)
            kademlia.set_mode(Some(kad::Mode::Client));

            let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
                .heartbeat_interval(web_time::Duration::from_secs(10))
                .prune_backoff(web_time::Duration::from_secs(60))
                .mesh_n(4)
                .mesh_n_low(3)
                .mesh_n_high(8)
                .mesh_outbound_min(2)
                .gossip_lazy(1)
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

            #[cfg(not(target_arch = "wasm32"))]
            let stream = libp2p_stream::Behaviour::new();
            #[cfg(not(target_arch = "wasm32"))]
            let _ = control_tx.send(stream.new_control());

            #[cfg(not(target_arch = "wasm32"))]
            let mdns = if config.enable_mdns && !test_mode {
                match libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer_id)
                {
                    Ok(behaviour) => {
                        libp2p::swarm::behaviour::toggle::Toggle::from(Some(behaviour))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "KIN-NET-075: Failed to bind mDNS: {}. Local peer discovery disabled.",
                            e
                        );
                        libp2p::swarm::behaviour::toggle::Toggle::from(None)
                    }
                }
            } else {
                libp2p::swarm::behaviour::toggle::Toggle::from(None)
            };
            #[cfg(not(target_arch = "wasm32"))]
            let upnp = libp2p::swarm::behaviour::toggle::Toggle::from(None);
            #[cfg(not(target_arch = "wasm32"))]
            let relay_server = libp2p::swarm::behaviour::toggle::Toggle::from(None);

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
                cdn,
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
            // Aggressive power saving for light nodes
            c.with_idle_connection_timeout(web_time::Duration::from_secs(60))
        })
        .build();

    // Light nodes do NOT listen on any ports. Dial out only.

    #[cfg(not(target_arch = "wasm32"))]
    let stream_control = control_rx.recv().unwrap();
    #[cfg(not(target_arch = "wasm32"))]
    let client = NetworkClient::new(tx, stream_control);

    #[cfg(target_arch = "wasm32")]
    let client = NetworkClient::new(tx);

    Ok((swarm, client))
}
