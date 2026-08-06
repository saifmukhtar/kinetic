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
    drand_kyn_tx_gossip: tokio::sync::watch::Sender<u64>,
    storage: Option<std::sync::Arc<dyn kinetic_core::traits::StorageEngine>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (topic, payload, message_id, propagation_source) = match gossip_rx.recv().await {
                Ok(msg) => msg,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if topic == kinetic_core::constants::GOSSIP_TOPIC_GOVERNANCE {
                let mut is_valid = false;
                if let Ok(signed_msg) = serde_json::from_slice::<
                    kinetic_core::governance::SignedGovernanceMessage,
                >(&payload)
                {
                    let Ok(mut state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
                    else {
                        network_client.report_gossip_validation(message_id, propagation_source, is_valid);
                        continue;
                    };
                    match kinetic_core::governance::process_governance_message(
                        &mut state,
                        &signed_msg,
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
                                    GovernanceEffect::PremiumNameGranted {
                                        name,
                                        target_pubkey,
                                    } => {
                                        let record = NameRecord::Premium {
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
                                                "Injected NameRecord::Premium into Sled for {}",
                                                name
                                            );
                                        }
                                    }
                                    GovernanceEffect::PremiumNameRevoked { name } => {
                                        let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                        let _ = storage.delete(key.as_bytes());
                                        tracing::info!(
                                            "Revoked NameRecord::Premium from Sled for {}",
                                            name
                                        );
                                    }
                                    _ => {}
                                }
                            }

                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Ok(None) => {
                            is_valid = true;
                            tracing::info!(
                                "Governance state updated via gossip. No immediate effect."
                            );
                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Err(e) => {
                            tracing::debug!("Governance gossip message rejected by process_governance_message: {:?}", e);
                        }
                    }
                }
                network_client.report_gossip_validation(message_id, propagation_source, is_valid);
            } else if topic == kinetic_core::constants::GOSSIP_TOPIC_DRAND {
                let mut is_valid = false;
                if let Ok(kyn) =
                    serde_json::from_slice::<kinetic_core::drand::RawKyn>(&payload)
                {
                    let kyn_clone = kyn.clone();
                    is_valid = tokio::task::spawn_blocking(move || kyn_clone.verify())
                        .await
                        .unwrap_or(false);
                    if is_valid {
                        if let Ok(latest) = drand_client_gossip.load_cached_kyn() {
                            if (kyn.kyn > latest.kyn || latest.is_unavailable)
                                && drand_client_gossip.cache_kyn(&kyn).is_ok()
                            {
                                let _ = drand_kyn_tx_gossip.send(kyn.kyn);
                            }
                        }
                    }
                }
                network_client.report_gossip_validation(message_id, propagation_source, is_valid);
            }
        }
    })
}
