//! Backgkyn pub/sub gossip message processor for governance updates and Drand time kyns.

/// Starts the backgkyn task that processes incoming pubsub gossip messages.
pub fn start_gossip_processor(
    network_client: kinetic_network::NetworkClient,
    mut gossip_rx: tokio::sync::broadcast::Receiver<(
        String,
        Vec<u8>,
        libp2p::gossipsub::MessageId,
        libp2p::PeerId,
    )>,
    gossip_gov_path: std::sync::Arc<std::path::PathBuf>,
    drand_client_gossip: std::sync::Arc<kinetic_core::drand::DrandClient>,
    kyn_tx_gossip: tokio::sync::watch::Sender<u64>,
    storage: Option<std::sync::Arc<dyn kinetic_core::traits::StorageEngine>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (topic, payload, message_id, propagation_source) = match gossip_rx.recv().await {
                Ok(msg) => msg,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if topic == kinetic_core::constants::GOSSIP_TOPIC_GLOBAL {
                if payload.is_empty() {
                    network_client.report_gossip(message_id, propagation_source, false);
                    continue;
                }
                let opcode = payload[0];
                let actual_payload = &payload[1..];

                if opcode == kinetic_types::network::NetworkOpcode::Governance as u8 {
                    let mut is_valid = false;
                    if let Ok(signed_msg) = serde_json::from_slice::<
                        kinetic_core::governance::SignedGovernanceMessage,
                    >(actual_payload)
                    {
                        use kinetic_core::types::clock::KynNetworkExt;
                        let current_kyn = match drand_client_gossip.fetch_latest().await {
                            Ok(kyn) => kyn.kyn,
                            Err(_) => kinetic_core::types::Kyn::now_local().0,
                        };
                        let Ok(mut state) =
                            kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
                        else {
                            network_client.report_gossip(
                                message_id,
                                propagation_source,
                                is_valid,
                            );
                            continue;
                        };

                        match kinetic_core::governance::process_governance_message(
                            &mut state,
                            &signed_msg,
                            kinetic_types::clock::Kyn(current_kyn),
                        ) {
                            Ok(Some(effect)) => {
                                is_valid = true;
                                tracing::info!(
                                    "Governance state updated via gossip. Effect: {:?}",
                                    effect
                                );

                                if let Some(storage) = &storage {
                                    use kinetic_core::constants::DB_PREFIX_REVEAL;
                                    use kinetic_core::governance::types::GovernanceEffect;
                                    use kinetic_core::types::NameRecord;

                                    match &effect {
                                        GovernanceEffect::PrimeMapped {
                                            name,
                                            target_pubkey,
                                        } => {
                                            let record = NameRecord::Prime {
                                                name: name.clone(),
                                                pubkey: target_pubkey.clone(),
                                                granted_at: std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs(),
                                                payload: Vec::new(),
                                                signature: Vec::new(),
                                                authorization: None,
                                            };
                                            let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                            if let Ok(json_bytes) = serde_json::to_vec(&record) {
                                                let _ = storage.put(key.as_bytes(), &json_bytes);
                                                tracing::info!(
                                                    "Injected NameRecord::Prime into storage for {}",
                                                    name
                                                );
                                            }
                                        }
                                        GovernanceEffect::PrimeUnmapped { name } => {
                                            let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                            let _ = storage.delete(key.as_bytes());
                                            tracing::info!(
                                                "Revoked NameRecord::Prime from storage for {}",
                                                name
                                            );
                                        }
                                        GovernanceEffect::InfraUnmapped { name } => {
                                            let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                            let _ = storage.delete(key.as_bytes());
                                            tracing::info!(
                                                "Revoked NameRecord::Infra from storage for {}",
                                                name
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                if let Err(e) = state.save_to_disk(&gossip_gov_path) {
                                    let err = kinetic_core::error::GovernanceError::StateSaveFailed;
                                    tracing::error!(error_code = err.code(), "Failed to save modified governance state to disk: {}", e);
                                }
                            }
                            Ok(None) => {
                                is_valid = true;
                                tracing::info!(
                                    "Governance state updated via gossip. No immediate effect."
                                );
                                if let Err(e) = state.save_to_disk(&gossip_gov_path) {
                                    let err = kinetic_core::error::GovernanceError::StateSaveFailed;
                                    tracing::error!(error_code = err.code(), "Failed to save modified governance state to disk: {}", e);
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "Governance gossip message rejected by process_governance_message: {:?}",
                                    e
                                );
                            }
                        }
                    }
                    network_client.report_gossip(
                        message_id,
                        propagation_source,
                        is_valid,
                    );
                } else if opcode == kinetic_types::network::NetworkOpcode::Drand as u8 {
                    let mut is_valid = false;
                    if let Ok(kyn) =
                        serde_json::from_slice::<kinetic_core::drand::RawKyn>(actual_payload)
                    {
                        let kyn_clone = kyn.clone();
                        is_valid = tokio::task::spawn_blocking(move || kyn_clone.verify())
                            .await
                            .unwrap_or(false);
                        if is_valid {
                            let latest_kyn = match drand_client_gossip.load_cached_kyn() {
                                Ok(latest) => {
                                    if latest.is_unavailable { 0 } else { latest.kyn }
                                },
                                Err(e) => {
                                    if !matches!(e, kinetic_core::error::DrandError::NoCachedKyn) {
                                        tracing::error!(error_code = e.code(), "Failed to load cached kyn in gossip handler: {}", e);
                                    }
                                    0
                                }
                            };

                            if kyn.kyn > latest_kyn {
                                if let Err(e) = drand_client_gossip.cache_kyn(&kyn) {
                                    tracing::error!(error_code = e.code(), "Failed to cache drand kyn in gossip handler: {}", e);
                                }
                                let _ = kyn_tx_gossip.send(kyn.kyn);
                            }
                        }
                    }
                    network_client.report_gossip(
                        message_id,
                        propagation_source,
                        is_valid,
                    );
                } else {
                    network_client.report_gossip(message_id, propagation_source, false);
                }
            }
        }
    })
}
