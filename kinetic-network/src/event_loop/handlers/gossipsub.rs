use crate::event_loop::core::NetworkEventLoop;
use libp2p::gossipsub::Event;

pub(crate) async fn handle(event_loop: &mut NetworkEventLoop, e: Event) {
    match e {
        Event::Message {
            propagation_source,
            message_id,
            message,
        } => {
            let topic = message.topic.into_string();
            let payload = message.data;
            let loopback = event_loop.loopback_tx.clone();
            let gossip_tx = event_loop.gossip_tx.clone();
            let semaphore = event_loop.gossip_semaphore.clone();

            let _permit = match semaphore.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        "Gossip semaphore saturated — dropping message from {} on topic {}",
                        propagation_source, topic
                    );
                    if let Some(tx) = &event_loop.loopback_tx {
                        let _ = tx.send(crate::event_loop::core::LoopbackCommand::CommitGossipValidation {
                            message_id,
                            source: propagation_source,
                            is_valid: false,
                        });
                    }
                    return;
                }
            };

            crate::event_loop::utils::spawn(async move {
                let payload_clone = payload.clone();
                let topic_clone = topic.clone();
                
                let is_valid = crate::event_loop::utils::spawn_blocking(move || {
                    if topic_clone == kinetic_core::constants::GOSSIP_TOPIC_DRAND {
                        if let Ok(kyn) = serde_json::from_slice::<kinetic_core::drand::RawKyn>(&payload_clone) {
                            return kyn.verify();
                        }
                        return false;
                    } else if topic_clone == kinetic_core::constants::GOSSIP_TOPIC_GOVERNANCE {
                        if let Ok(signed_msg) = serde_json::from_slice::<kinetic_core::governance::SignedGovernanceMessage>(&payload_clone) {
                            let gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Ok(root_key) = gov.get_root_key() {
                                drop(gov); 
                                let action_bytes = signed_msg.to_canonical_bytes();
                                return signed_msg
                                    .signatures
                                    .iter()
                                    .any(|sig| kinetic_core::governance::verify_signature(&root_key, &action_bytes, sig));
                            }
                        }
                        return false;
                    }
                    true
                }).await;

                if let Some(tx) = loopback {
                    let _ = tx.send(crate::event_loop::core::LoopbackCommand::CommitGossipValidation {
                        message_id: message_id.clone(),
                        source: propagation_source,
                        is_valid,
                    });
                }

                if is_valid {
                    if let Some(tx) = gossip_tx {
                        let _ = tx.send((
                            topic,
                            payload,
                            message_id,
                            propagation_source,
                        ));
                    }
                }
            });
        }
        _ => {}
    }
}
