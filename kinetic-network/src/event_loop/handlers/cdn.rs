use crate::event_loop::core::NetworkEventLoop;
use kinetic_types::cdn::{CdnRequest, CdnResponse};
use libp2p::kad::store::RecordStore;
use libp2p::request_response::{Event, Message};

pub(crate) async fn handle(event_loop: &mut NetworkEventLoop, e: Event<CdnRequest, CdnResponse>) {
    match e {
        Event::Message { message, peer } => match message {
            Message::Request {
                request, channel, ..
            } => {
                let name = request.name.as_ref();
                let record = {
                    let keys = kinetic_core::types::derive_storage_keys(
                        name,
                        kinetic_core::constants::NETWORK_SALT,
                    );
                    let mut result = None;
                    for key_bytes in &keys {
                        let k = libp2p::kad::RecordKey::new(key_bytes);
                        if let Some(record) = event_loop
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .store_mut()
                            .get(&k)
                        {
                            result = Some(record.value.clone());
                            break;
                        }
                    }
                    result
                };

                let _ = event_loop
                    .swarm
                    .behaviour_mut()
                    .cdn
                    .send_response(channel, kinetic_types::cdn::CdnResponse { record });

                event_loop.proxy_cdn_usage.0 += 1;
            }
            Message::Response {
                request_id,
                response,
            } => {
                if let Some(domain) = event_loop.pending_cdn_requests.remove(&request_id)
                    && let Some(record_bytes) = response.record
                    && let Ok(record) =
                        serde_json::from_slice::<kinetic_core::types::NameRecord>(&record_bytes)
                {
                    let skip_verify = kinetic_core::config::is_dev_mode();
                    let loopback = event_loop.loopback_tx.clone();

                    if let Some(tx) = loopback {
                        let store_ref = event_loop.swarm.behaviour_mut().kademlia.store_mut();
                        let storage = store_ref.storage.clone();
                        let engine = store_ref.vdf_engine.clone();
                        let current_drand_kyn = store_ref.current_drand_kyn;
                        let peer = peer.clone();

                        crate::event_loop::utils::spawn(async move {
                            let is_valid = if skip_verify {
                                true
                            } else {
                                crate::event_loop::utils::spawn_blocking(move || {
                                    if let kinetic_core::types::NameRecord::Standard(reveal) =
                                        &record
                                    {
                                        crate::store::verification::verify_reveal(
                                            reveal,
                                            &storage,
                                            current_drand_kyn,
                                            &engine,
                                        )
                                        .is_ok()
                                    } else {
                                        true
                                    }
                                })
                                .await
                            };

                            if is_valid {
                                let _ = tx.send(
                                    crate::event_loop::core::LoopbackCommand::CdnResolutionVerified {
                                        domain,
                                        record_bytes,
                                        peer,
                                    },
                                );
                            }
                        });
                    }
                }
            }
        },
        Event::OutboundFailure { request_id, .. } => {
            event_loop.pending_cdn_requests.remove(&request_id);
        }
        _ => {}
    }
}
