//! Governance gossip message handler and disk persistence listener for Kinetic host nodes.

use kinetic_core::traits::KynProvider;
use std::path::PathBuf;
use std::sync::Arc;

use libp2p::PeerId;
use libp2p::gossipsub::MessageId;

/// Starts an async loop to listen for governance gossip messages, update global state, and save to disk.
pub async fn start_gossip_listener(
    kyn_provider: Arc<dyn KynProvider>,
    mut gossip_rx: tokio::sync::broadcast::Receiver<(String, Vec<u8>, MessageId, PeerId)>,
    gov_state_path: Arc<PathBuf>,
) {
    while let Ok((topic, payload, _, _)) = gossip_rx.recv().await {
        if topic == kinetic_core::constants::GOSSIP_TOPIC_GLOBAL {
            if payload.is_empty() {
                continue;
            }
            let opcode = payload[0];
            let actual_payload = &payload[1..];

            if opcode == kinetic_types::network::NetworkOpcode::Governance as u8
                && let Ok(signed_msg) = serde_json::from_slice::<
                    kinetic_core::governance::SignedGovernanceMessage,
                >(actual_payload)
            {
                use kinetic_core::types::clock::KynNetworkExt;
                let current_kyn = match kyn_provider.load_cached_kyn() {
                    Ok(kyn) => kyn.kyn,
                    Err(_) => match kyn_provider.fetch_latest().await {
                        Ok(kyn) => kyn.kyn,
                        Err(_) => kinetic_core::types::Kyn::now_local().0,
                    },
                };

                let (should_save, cloned_state) = {
                    let Ok(mut state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
                    else {
                        tracing::error!(
                            error = ?kinetic_core::error::SystemError::MutexPoisoned("GLOBAL_GOVERNANCE_STATE".into()),
                            "FATAL: Global governance state mutex is poisoned!"
                        );
                        continue;
                    };

                    match kinetic_core::governance::process_governance_message(
                        &mut state,
                        &signed_msg,
                        kinetic_types::clock::Kyn(current_kyn),
                    ) {
                        Ok(Some(effect)) => {
                            tracing::info!(
                                "Governance state updated via gossip. Effect: {:?}",
                                effect
                            );
                            (true, state.clone())
                        }
                        Ok(None) => {
                            tracing::info!(
                                "Governance state updated via gossip. No immediate effect."
                            );
                            (true, state.clone())
                        }
                        Err(e) => {
                            tracing::debug!("Governance gossip message rejected: {:?}", e);
                            (false, state.clone())
                        }
                    }
                };
                if should_save {
                    let path_clone = gov_state_path.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = cloned_state.save_to_disk(&path_clone) {
                            let err = kinetic_core::error::GovernanceError::StateSaveFailed;
                            tracing::error!(
                                error_code = err.code(),
                                "Failed to save modified governance state to disk: {}",
                                e
                            );
                        }
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod proptests {

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_gossip_garbage_payloads(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
            // Guarantee that receiving absolute garbage over the P2P gossip network
            // will never cause a deserialization panic.
            let _ = serde_json::from_slice::<kinetic_core::governance::SignedGovernanceMessage>(&payload);
        }
    }
}
