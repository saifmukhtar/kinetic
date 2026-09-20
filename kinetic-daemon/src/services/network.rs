//! Background network loops for dynamic PoW identity rotation and periodic DHT name republishing.
//!
//! ## Layer 8 Architecture: Client Identity Rotation
//! Just like the `kinetic-host` payload seeder, the `kinetic-daemon` must maintain Sybil 
//! resistance to interact with the Kademlia DHT. It achieves this by continuously calculating 
//! a Proof-of-Work threshold bound to the current KYN epoch. When the time oracle pulses a 
//! new network time, this background worker safely hot-swaps the underlying P2P swarm identity.

use kinetic_core::traits::StorageEngine;

#[allow(clippy::too_many_arguments)]
/// Initiates the Sybil-resistant Proof-of-Work (PoW) hot-swapping loop.
///
/// > [!IMPORTANT]
/// > Kinetic requires all DHT participants to prove identity through a PoW challenge bound 
/// > to the current cryptographic time epoch (KYN). When time advances, identities expire.
///
/// This asynchronous worker operates completely independently from the REST API. It performs 
/// three critical state transitions:
///
/// 1. **Time Epoch Monitoring**: It blocks on `kyn_rx.changed()`, waiting for the Gossipsub 
///    mesh to flood a new Time Oracle pulse.
/// 2. **Preemptive Mining**: When the network time advances, it spins up a heavily threaded 
///    background miner (`tokio::task::spawn_blocking`) to calculate a new valid Ed25519 identity 
///    that satisfies the mathematical leading-zero requirement of the new epoch.
/// 3. **The Hot Swap**: It terminates the existing Libp2p `NetworkEventLoop` handle, re-initializes 
///    the Swarm with the newly mined PoW identity, and seamlessly re-attaches the MPSC channels.
///
/// ### Arguments
/// * `hc_client`: The thread-safe channel to the running Libp2p event loop.
/// * `kyn_rx`: The reactive receiver for Time Oracle pulses.
/// * `hc_config` & `hc_storage`: Bootstrapping dependencies required to rebuild the Swarm.
/// * `incoming_tx` & `gossip_tx`: Channels required to reconnect proxy and action routing after the swap.
pub fn start_pow_miner_loop(
    hc_client: kinetic_network::NetworkClient,
    kyn_rx: tokio::sync::watch::Receiver<u64>,
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
        let mut rx = kyn_rx.clone();
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
            let current_epoch = kinetic_network::pow::get_staggered_epoch(
                &peer_id.to_bytes(),
                kinetic_kyn::types::Kyn(kyn),
            );

            let needs_validation = match last_verified_epoch {
                Some(epoch) => epoch != current_epoch,
                None => true,
            };

            if needs_validation {
                let peer_id_clone = peer_id;
                let pow_valid = tokio::task::spawn_blocking(move || {
                    kinetic_network::pow::verify_p2p_pow(
                        &peer_id_clone,
                        kinetic_kyn::types::Kyn(kyn),
                        kinetic_core::constants::POW_DIFFICULTY_BITS,
                    )
                })
                .await
                .unwrap_or(false);

                if !pow_valid {
                    tracing::info!("PoW epoch expired. Remining identity seamlessly...");
                    current_local_key = tokio::task::spawn_blocking(move || {
                        kinetic_network::pow::mine_p2p_keypair(
                            kinetic_kyn::types::Kyn(kyn),
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
                            kyn_rx.clone(),
                            Some(incoming_tx.clone()),
                            Some(gossip_tx.clone()),
                            hc_vdf_engine.clone(),
                        ) {
                            Ok(res) => break res,
                            Err(e) => {
                                retries += 1;
                                if retries > 10 {
                                    tracing::error!(
                                        error = ?kinetic_core::error::SystemError::NetworkHotswapFailed(e.to_string()),
                                        "FATAL: Failed to hot-swap P2P backend after 10 retries"
                                    );
                                    return; // Abort miner task
                                }
                                tracing::warn!(
                                    error = ?kinetic_core::error::SystemError::PortInUse(e.to_string()),
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

/// Initiates the background Distributed Hash Table (DHT) liveness republisher.
///
/// > [!NOTE]
/// > Because Kademlia DHT nodes are highly ephemeral (laptops go to sleep, routers reboot), 
/// > records naturally fall out of the network over time. 
///
/// To guarantee that a user's locally owned `.kin` domain routing payloads remain discoverable, 
/// this asynchronous worker periodically wakes up, queries the local `kinetic-storage` for all 
/// owned `NameRecord` datasets, and aggressively pushes `put_record` requests back into the DHT 
/// to refresh their Time-To-Live (TTL).
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
            if let Ok(Some(bytes)) = republish_storage.get(owned_key)
                && let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes)
            {
                for (i, name) in names.into_iter().enumerate() {
                    let reveal_key =
                        format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, name);
                    if let Ok(Some(reveal_bytes)) = republish_storage.get(reveal_key.as_bytes())
                        && let Ok(reveal) =
                            serde_json::from_slice::<kinetic_core::types::Reveal>(&reveal_bytes)
                    {
                        let rn_commit = republish_network.clone();
                        let n_commit = name.clone();
                        let n_reveal = name.clone();

                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(i as u64 * 100))
                                .await;

                            if let Ok(beacon_sig_bytes) = hex::decode(&reveal.beacon_signature) {
                                let commitment = kinetic_core::types::Commitment::derive(
                                    kinetic_core::constants::NETWORK_SALT,
                                    &reveal.name,
                                    &reveal.salt,
                                    &beacon_sig_bytes,
                                    &reveal.pubkey,
                                );

                                if let Ok(commit_bytes) = serde_json::to_vec(&commitment) {
                                    tracing::info!(
                                        "Republisher: Publishing commitment for {}",
                                        n_commit
                                    );
                                    // Republish the commitment to satisfy the commitment gate on new DHT nodes
                                    let _ = rn_commit
                                        .publish_redundant_payload(&n_commit, commit_bytes)
                                        .await;

                                    // Wait 12 KYN Time Provider rounds (36 seconds) so the commitment matures (>10 rounds required)
                                    tokio::time::sleep(std::time::Duration::from_secs(36)).await;

                                    tracing::info!(
                                        "Republisher: Publishing reveal for {}",
                                        n_reveal
                                    );
                                    // Republish the reveal
                                    let _ = rn_commit
                                        .publish_redundant_payload(&n_reveal, reveal_bytes.to_vec())
                                        .await;
                                }
                            }
                        });
                    }
                }
            }
        }
    })
}
