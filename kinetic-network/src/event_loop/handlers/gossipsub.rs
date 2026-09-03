use crate::event_loop::core::NetworkEventLoop;
use libp2p::gossipsub::Event;

pub(crate) async fn handle(event_loop: &mut NetworkEventLoop, e: Event) {
    if let Event::Message {
        propagation_source,
        message_id,
        message,
    } = e
    {
        let topic = message.topic.into_string();
        let payload = message.data;
        let loopback = event_loop.loopback_tx.clone();
        let gossip_tx = event_loop.gossip_tx.clone();
        let semaphore = event_loop.gossip_semaphore.clone();

        let _permit = match semaphore.try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let err = kinetic_core::error::P2pError::GossipSemaphoreSaturated(propagation_source.to_string(), topic.to_string());
                tracing::warn!(error_code = err.code(), "{}", err);
                if let Some(tx) = &event_loop.loopback_tx {
                    let _ = tx.send(
                        crate::event_loop::core::LoopbackCommand::CommitGossipValidation {
                            message_id,
                            source: propagation_source,
                            is_valid: None,
                        },
                    );
                }
                return;
            }
        };

        crate::event_loop::utils::spawn(async move {
            let payload_clone = payload.clone();
            let topic_clone = topic.clone();

            let is_valid = crate::event_loop::utils::spawn_blocking(move || {
                if topic_clone == kinetic_core::constants::GOSSIP_TOPIC_GLOBAL {
                    if payload_clone.is_empty() {
                        return false;
                    }
                    let opcode = payload_clone[0];
                    let actual_payload = &payload_clone[1..];

                    if opcode == kinetic_types::network::NetworkOpcode::Drand as u8 {
                        if let Ok(kyn) =
                            serde_json::from_slice::<kinetic_core::drand::RawKyn>(actual_payload)
                        {
                            return kyn.verify();
                        }
                        return false;
                    } else if opcode == kinetic_types::network::NetworkOpcode::Governance as u8 {
                        if kinetic_core::constants::GOVERNANCE_MODEL == "permissionless" {
                            return false;
                        }
                        if let Ok(signed_msg) = serde_json::from_slice::<
                            kinetic_core::governance::SignedGovernanceMessage,
                        >(actual_payload)
                        {
                            let gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Ok(root_key) = gov.get_root_key() {
                                drop(gov);
                                let action_bytes = signed_msg.to_bytes();
                                return signed_msg.signatures.iter().any(|sig| {
                                    kinetic_core::governance::verify_signature(
                                        &root_key,
                                        &action_bytes,
                                        sig,
                                    )
                                });
                            }
                        }
                        return false;
                    }

                    // Reject any unrecognized opcode on the global protocol topic
                    return false;
                }
                // For non-global topics (app-layer), default to accepting the message
                true
            })
            .await;

            if let Some(tx) = loopback {
                let _ = tx.send(
                    crate::event_loop::core::LoopbackCommand::CommitGossipValidation {
                        message_id: message_id.clone(),
                        source: propagation_source,
                        is_valid: Some(is_valid),
                    },
                );
            }

            if is_valid && let Some(tx) = gossip_tx {
                let _ = tx.send((topic, payload, message_id, propagation_source));
            }
        });
    }
}
