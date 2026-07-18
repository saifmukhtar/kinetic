use kinetic_core::drand::DrandClient;
use kinetic_network::{NetworkClient, NetworkConfig, NetworkEventLoop};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::watch;

pub async fn start_dynamic_routing_publisher(
    publisher_host_key: libp2p::identity::Keypair,
    local_peer_id_str: Arc<RwLock<String>>,
    host_peer_id_str: String,
    publisher_client: NetworkClient,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let Ok(ed_key) = publisher_host_key.try_into_ed25519() else {
        tracing::error!("Host key is not ed25519");
        return;
    };
    let ed_bytes = ed_key.to_bytes();
    let Ok(dalek_kp) = ed25519_dalek::SigningKey::try_from(&ed_bytes[0..32]) else {
        tracing::error!("Failed to create dalek key");
        return;
    };

    loop {
        interval.tick().await;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut record = kinetic_core::types::HostRoutingRecord {
            host_id: host_peer_id_str.clone(),
            current_peer_id: local_peer_id_str
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            timestamp,
            signature: vec![],
        };

        use ed25519_dalek::Signer;
        let signature = dalek_kp.sign(&record.signable_bytes());
        record.signature = signature.to_bytes().to_vec();

        if let Err(e) = publisher_client.publish_host_routing_record(record).await {
            tracing::warn!("Failed to publish HostRoutingRecord: {}", e);
        } else {
            tracing::info!("Published dynamic HostRoutingRecord to DHT");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_drand_heartbeat(
    hb_drand: Arc<DrandClient>,
    drand_pulse_tx: watch::Sender<u64>,
    mut hb_local_peer_id: libp2p::PeerId,
    shared_peer_id: Arc<RwLock<String>>,
    loop_handle_ref: Arc<tokio::sync::Mutex<tokio::task::JoinHandle<()>>>,
    hc_client: NetworkClient,
    hc_drand_rx: watch::Receiver<u64>,
    hc_config: NetworkConfig,
    hc_storage: Arc<dyn kinetic_core::traits::StorageEngine>,
    hc_inc_tx: tokio::sync::mpsc::Sender<(
        kinetic_network::ProxyRequest,
        libp2p::request_response::ResponseChannel<kinetic_network::ProxyResponse>,
    )>,
    hc_gossip_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
    hc_vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    let mut last_verified_epoch: Option<u64> = None;
    loop {
        interval.tick().await;
        if let Ok(pulse) = hb_drand.fetch_latest().await {
            if !pulse.is_unavailable && !pulse.is_from_cache {
                let _ = drand_pulse_tx.send(pulse.round);

                let current_epoch = kinetic_network::pow::get_staggered_epoch(
                    &hb_local_peer_id.to_bytes(),
                    pulse.round,
                );

                let needs_validation = match last_verified_epoch {
                    Some(epoch) => epoch != current_epoch,
                    None => true,
                };

                if needs_validation {
                    let peer_id_clone = hb_local_peer_id;
                    let pulse_round = pulse.round;
                    let pow_valid = tokio::task::spawn_blocking(move || {
                        kinetic_network::pow::is_valid_sybil_pow(
                            &peer_id_clone,
                            pulse_round,
                            kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                        )
                    })
                    .await
                    .unwrap_or(false);

                    if !pow_valid {
                        tracing::info!(
                            "PoW epoch expired for ephemeral identity. Hot-swapping network loop..."
                        );
                        let current_local_key = tokio::task::spawn_blocking(move || {
                            kinetic_network::pow::mine_sybil_keypair(
                                pulse_round,
                                kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                            )
                        })
                        .await
                        .unwrap_or_else(|_| {
                            tracing::error!(
                                "PoW mining task panicked, falling back to random identity"
                            );
                            libp2p::identity::Keypair::generate_ed25519()
                        });
                        hb_local_peer_id =
                            libp2p::PeerId::from_public_key(&current_local_key.public());
                        last_verified_epoch = None;

                        if let Ok(mut lock) = shared_peer_id.write() {
                            *lock = hb_local_peer_id.to_string();
                        }

                        let mut handle = loop_handle_ref.lock().await;
                        handle.abort();

                        if let Ok((new_client, new_loop)) = NetworkEventLoop::new(
                            hc_config.clone(),
                            current_local_key.clone(),
                            hc_storage.clone(),
                            hc_drand_rx.clone(),
                            Some(hc_inc_tx.clone()),
                            Some(hc_gossip_tx.clone()),
                            hc_vdf_engine.clone(),
                        ) {
                            hc_client.update_backend(
                                new_client.get_sender(),
                                new_client.stream_control(),
                            );
                            *handle = tokio::spawn(async move {
                                new_loop.run().await;
                            });
                            tracing::info!("Successfully hot-swapped P2P backend with new PoW identity in Host mode.");
                        }
                    } else {
                        last_verified_epoch = Some(current_epoch);
                    }
                }
            }
        }
    }
}
