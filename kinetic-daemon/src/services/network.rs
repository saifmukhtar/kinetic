//! Background network loops for dynamic PoW identity rotation and periodic DHT name republishing.

use kinetic_core::traits::StorageEngine;

#[allow(clippy::too_many_arguments)]
/// Starts a background loop that monitors Drand kyns and seamlessly rotates
/// the node's libp2p identity to maintain a valid Proof of Work (PoW) Sybil resistance.
pub fn start_pow_miner_loop(
    hc_client: kinetic_network::NetworkClient,
    hc_drand_rx: tokio::sync::watch::Receiver<u64>,
    hc_config: kinetic_network::NetworkConfig,
    hc_storage: std::sync::Arc<dyn StorageEngine>,
    incoming_tx: tokio::sync::mpsc::Sender<(
        kinetic_network::ProxyRequest,
        libp2p::request_response::ResponseChannel<kinetic_network::ProxyResponse>,
    )>,
    gossip_tx: tokio::sync::broadcast::Sender<(
        String,
        Vec<u8>,
        libp2p::gossipsub::MessageId,
        libp2p::PeerId,
    )>,
    mut network_loop_handle: tokio::task::JoinHandle<()>,
    mut current_local_key: libp2p::identity::Keypair,
    hc_vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = hc_drand_rx.clone();
        let mut last_verified_epoch: Option<u64> = None;
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let kyn = *rx.borrow();
            if kyn == 0 {
                continue;
            }
            let peer_id = libp2p::PeerId::from_public_key(&current_local_key.public());
            let current_epoch =
                kinetic_network::pow::get_staggered_epoch(&peer_id.to_bytes(), kyn);

            let needs_validation = match last_verified_epoch {
                Some(epoch) => epoch != current_epoch,
                None => true,
            };

            if needs_validation {
                let peer_id_clone = peer_id;
                let pow_valid = tokio::task::spawn_blocking(move || {
                    kinetic_network::pow::is_valid_sybil_pow(
                        &peer_id_clone,
                        kyn,
                        kinetic_core::constants::POW_DIFFICULTY_BITS,
                    )
                })
                .await
                .unwrap_or(false);

                if !pow_valid {
                    tracing::info!("PoW epoch expired. Remining identity seamlessly...");
                    current_local_key = tokio::task::spawn_blocking(move || {
                        kinetic_network::pow::mine_sybil_keypair(
                            kyn,
                            kinetic_core::constants::POW_DIFFICULTY_BITS,
                        )
                    })
                    .await
                    .expect("mining task panicked");
                    last_verified_epoch = None; // Reset to force revalidation on next loop

                    network_loop_handle.abort();

                    let mut retries = 0;
                    let mut backoff = 100;
                    let (new_client, new_loop) = loop {
                        tokio::task::yield_now().await;
                        tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;

                        match kinetic_network::NetworkEventLoop::new(
                            hc_config.clone(),
                            current_local_key.clone(),
                            hc_storage.clone(),
                            hc_drand_rx.clone(),
                            Some(incoming_tx.clone()),
                            Some(gossip_tx.clone()),
                            hc_vdf_engine.clone(),
                        ) {
                            Ok(res) => break res,
                            Err(e) => {
                                retries += 1;
                                if retries > 10 {
                                    tracing::error!("FATAL: Failed to hot-swap P2P backend: {}", e);
                                    return; // Abort miner task
                                }
                                tracing::warn!(
                                    "Port in use during hot-swap, retrying... ({}/10)",
                                    retries
                                );
                                backoff *= 2;
                            }
                        }
                    };

                    hc_client.update_backend(new_client.get_sender(), new_client.stream_control());
                    network_loop_handle = tokio::spawn(async move {
                        new_loop.run().await;
                    });
                    tracing::info!("Successfully hot-swapped P2P backend with new PoW identity");
                } else {
                    last_verified_epoch = Some(current_epoch);
                }
            }
        }
    })
}

/// Starts a background loop that periodically republishes owned name payloads
/// to the DHT to ensure they remain alive and discoverable.
pub fn start_republisher(
    republish_network: kinetic_network::NetworkClient,
    republish_storage: std::sync::Arc<dyn StorageEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            kinetic_core::constants::TIMEOUTS_HEARTBEAT_AGE_WARNING_SECONDS,
        )); // 12 hours
        loop {
            interval.tick().await;
            let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
            if let Ok(Some(bytes)) = republish_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for (i, name) in names.into_iter().enumerate() {
                        let reveal_key =
                            format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, name);
                        if let Ok(Some(reveal_bytes)) = republish_storage.get(reveal_key.as_bytes())
                        {
                            if let Ok(reveal) =
                                serde_json::from_slice::<kinetic_core::types::Reveal>(&reveal_bytes)
                            {
                                let rn_commit = republish_network.clone();
                                let n_commit = name.clone();
                                let n_reveal = name.clone();

                                tokio::spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_millis(
                                        i as u64 * 100,
                                    ))
                                    .await;

                                    use sha2::Digest;
                                    let mut hasher = sha2::Sha256::new();
                                    hasher.update(reveal.name.as_bytes());
                                    hasher.update(reveal.salt);
                                    if let Ok(drand_rand) = hex::decode(&reveal.drand_signature) {
                                        hasher.update(&drand_rand);
                                        hasher.update(&reveal.pubkey);
                                        let mut hash = [0u8; 32];
                                        hash.copy_from_slice(&hasher.finalize());
                                        let commitment = kinetic_core::types::Commitment { hash };

                                        if let Ok(commit_bytes) = serde_json::to_vec(&commitment) {
                                            tracing::info!(
                                                "Republisher: Publishing commitment for {}",
                                                n_commit
                                            );
                                            // Republish the commitment to satisfy the commitment gate on new DHT nodes
                                            let _ = rn_commit
                                                .publish_redundant_payload(&n_commit, commit_bytes)
                                                .await;

                                            // Wait 12 Drand rounds (36 seconds) so the commitment matures (>10 rounds required)
                                            tokio::time::sleep(std::time::Duration::from_secs(36))
                                                .await;

                                            tracing::info!(
                                                "Republisher: Publishing reveal for {}",
                                                n_reveal
                                            );
                                            // Republish the reveal
                                            let _ = rn_commit
                                                .publish_redundant_payload(
                                                    &n_reveal,
                                                    reveal_bytes.to_vec(),
                                                )
                                                .await;
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }
    })
}
