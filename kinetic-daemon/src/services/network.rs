use kinetic_core::traits::StorageEngine;

pub fn start_pow_miner_loop(
    hc_client: kinetic_network::NetworkClient,
    hc_drand_rx: tokio::sync::watch::Receiver<u64>,
    hc_config: kinetic_network::NetworkConfig,
    hc_storage: std::sync::Arc<kinetic_storage::SledStorage>,
    hc_inc_tx: tokio::sync::mpsc::Sender<(kinetic_network::ProxyRequest, libp2p::request_response::ResponseChannel<kinetic_network::ProxyResponse>)>,
    hc_gossip_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
    mut network_loop_handle: tokio::task::JoinHandle<()>,
    mut current_local_key: libp2p::identity::Keypair,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = hc_drand_rx.clone();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let pulse = *rx.borrow();
            if pulse == 0 {
                continue;
            }
            let peer_id = libp2p::PeerId::from_public_key(&current_local_key.public());
            if !kinetic_network::pow::is_valid_sybil_pow(
                &peer_id,
                pulse,
                kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
            ) {
                tracing::info!("PoW epoch expired. Remining identity seamlessly...");
                current_local_key = kinetic_network::pow::mine_sybil_keypair(
                    pulse,
                    kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                );

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
                        Some(hc_inc_tx.clone()),
                        Some(hc_gossip_tx.clone()),
                    ) {
                        Ok(res) => break res,
                        Err(e) => {
                            retries += 1;
                            if retries > 10 {
                                tracing::error!("FATAL: Failed to hot-swap P2P backend: {}", e);
                                return; // Abort miner task
                            }
                            tracing::warn!("Port in use during hot-swap, retrying... ({}/10)", retries);
                            backoff *= 2;
                        }
                    }
                };

                hc_client.update_backend(new_client.get_sender(), new_client.stream_control());
                network_loop_handle = tokio::spawn(async move {
                    new_loop.run().await;
                });
                tracing::info!("Successfully hot-swapped P2P backend with new PoW identity");
            }
        }
    })
}


pub fn start_republisher(
    republish_network: kinetic_network::NetworkClient,
    republish_storage: std::sync::Arc<kinetic_storage::SledStorage>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(43200)); // 12 hours
        loop {
            interval.tick().await;
            let owned_key = b"kinetic_owned_names";
            if let Ok(Some(bytes)) = republish_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for name in names {
                        let reveal_key = format!("kinetic_reveal:{}", name);
                        if let Ok(Some(reveal_bytes)) = republish_storage.get(reveal_key.as_bytes())
                        {
                            let rn = republish_network.clone();
                            let n = name.clone();
                            
                            tokio::spawn(async move {
                                let _ = rn.publish_redundant_payload(&n, reveal_bytes.to_vec()).await;
                            });
                        }
                    }
                }
            }
        }
    })
}
