//! Background pub/sub gossip message processor for governance updates and Drand time pulses.

/// Starts the background task that processes incoming pubsub gossip messages.
pub fn start_gossip_processor(
    mut gossip_rx: tokio::sync::broadcast::Receiver<(String, Vec<u8>)>,
    gossip_gov_path: std::sync::Arc<std::path::PathBuf>,
    drand_client_gossip: std::sync::Arc<kinetic_core::drand::DrandClient>,
    drand_pulse_tx_gossip: tokio::sync::watch::Sender<u64>,
    storage: Option<std::sync::Arc<dyn kinetic_core::traits::StorageEngine>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (topic, payload) = match gossip_rx.recv().await {
                Ok(msg) => msg,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if topic == kinetic_core::constants::GOSSIP_TOPIC_GOVERNANCE {
                if let Ok(signed_msg) = serde_json::from_slice::<
                    kinetic_core::governance::SignedGovernanceMessage,
                >(&payload)
                {
                    let Ok(mut state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
                    else {
                        continue;
                    };
                    match kinetic_core::governance::process_governance_message(
                        &mut state,
                        &signed_msg,
                    ) {
                        Ok(Some(effect)) => {
                            tracing::info!(
                                "Governance state updated via gossip. Effect: {:?}",
                                effect
                            );

                            if let Some(storage) = &storage {
                                use kinetic_core::governance::types::GovernanceEffect;
                                use kinetic_core::types::DomainRecord;
                                use kinetic_core::constants::DB_PREFIX_REVEAL;

                                match &effect {
                                    GovernanceEffect::PremiumNameGranted { name, target_pubkey } => {
                                        let record = DomainRecord::Premium {
                                            name: name.clone(),
                                            pubkey: target_pubkey.clone(),
                                            granted_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                            payload: Vec::new(),
                                            signature: Vec::new(),
                                        };
                                        let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                        if let Ok(json_bytes) = serde_json::to_vec(&record) {
                                            let _ = storage.put(key.as_bytes(), &json_bytes);
                                            tracing::info!("Injected DomainRecord::Premium into Sled for {}", name);
                                        }
                                    }
                                    GovernanceEffect::PremiumNameRevoked { name } => {
                                        let key = format!("{}{}", DB_PREFIX_REVEAL, name);
                                        let _ = storage.delete(key.as_bytes());
                                        tracing::info!("Revoked DomainRecord::Premium from Sled for {}", name);
                                    }
                                    _ => {}
                                }
                            }

                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Ok(None) => {
                            tracing::info!(
                                "Governance state updated via gossip. No immediate effect."
                            );
                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Err(e) => {
                            tracing::debug!("Governance gossip message rejected: {:?}", e);
                        }
                    }
                }
            } else if topic == kinetic_core::constants::GOSSIP_TOPIC_DRAND {
                if let Ok(pulse) =
                    serde_json::from_slice::<kinetic_core::drand::DrandPulse>(&payload)
                {
                    let pulse_clone = pulse.clone();
                    let is_valid = tokio::task::spawn_blocking(move || pulse_clone.verify())
                        .await
                        .unwrap_or(false);
                    if is_valid {
                        if let Ok(latest) = drand_client_gossip.load_cached_pulse() {
                            if (pulse.round > latest.round || latest.is_unavailable)
                                && drand_client_gossip.cache_pulse(&pulse).is_ok()
                            {
                                let _ = drand_pulse_tx_gossip.send(pulse.round);
                            }
                        }
                    }
                }
            }
        }
    })
}
