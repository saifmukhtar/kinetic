//! Governance gossip message handler and disk persistence listener for Kinetic host nodes.

use std::path::PathBuf;
use std::sync::Arc;

/// Starts an async loop to listen for governance gossip messages, update global state, and save to disk.
pub async fn start_gossip_listener(
    mut gossip_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    gov_state_path: Arc<PathBuf>,
) {
    while let Some((topic, payload)) = gossip_rx.recv().await {
        if topic == kinetic_core::constants::GOSSIP_TOPIC_GOVERNANCE {
            if let Ok(signed_msg) = serde_json::from_slice::<
                kinetic_core::governance::SignedGovernanceMessage,
            >(&payload)
            {
                let Ok(mut state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock() else {
                    continue;
                };
                match kinetic_core::governance::process_governance_message(&mut state, &signed_msg)
                {
                    Ok(Some(effect)) => {
                        tracing::info!("Governance state updated via gossip. Effect: {:?}", effect);
                        let _ = state.save_to_disk(&gov_state_path);
                    }
                    Ok(None) => {
                        tracing::info!("Governance state updated via gossip. No immediate effect.");
                        let _ = state.save_to_disk(&gov_state_path);
                    }
                    Err(e) => {
                        tracing::debug!("Governance gossip message rejected: {:?}", e);
                    }
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
        fn doesnt_panic_on_garbage_gossip(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
            // Guarantee that receiving absolute garbage over the P2P gossip network
            // will never cause a deserialization panic.
            let _ = serde_json::from_slice::<kinetic_core::governance::SignedGovernanceMessage>(&payload);
        }
    }
}
