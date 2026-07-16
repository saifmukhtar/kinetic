/// Starts the background task that processes incoming pubsub gossip messages.
pub fn start_gossip_processor(
    mut gossip_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    gossip_gov_path: std::sync::Arc<std::path::PathBuf>,
    drand_client_gossip: std::sync::Arc<kinetic_core::drand::DrandClient>,
    drand_pulse_tx_gossip: tokio::sync::watch::Sender<u64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if topic == "kinetic_governance" {
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
            } else if topic == "drand_pulse_quicknet" {
                if let Ok(pulse) =
                    serde_json::from_slice::<kinetic_core::drand::DrandPulse>(&payload)
                {
                    if pulse.verify() {
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
