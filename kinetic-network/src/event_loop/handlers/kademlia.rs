use libp2p::kad;
use crate::event_loop::core::NetworkEventLoop;

pub(crate) async fn handle(event_loop: &mut NetworkEventLoop, e: kad::Event) {
    match e {
        kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                tracing::debug!("GetRecord Ok FoundRecord for query {:?}", id);
                if let Some(mapped_name) = event_loop.query_id_to_name.get(&id) {
                    match mapped_name {
                        crate::event_loop::core::QueryType::Quorum(name) => {
                            if let Some(pending) = event_loop.pending_quorums.get_mut(name) {
                                if peer_record.record.value == pending.target_payload {
                                    pending.match_count += 1;
                                }
                            }
                        }
                        crate::event_loop::core::QueryType::Get(name) => {
                            if let Some(pending) = event_loop.pending_gets.get_mut(name) {
                                pending.received_payloads.push(peer_record.record.value);
                            }
                        }
                        crate::event_loop::core::QueryType::Put(_) => {}
                    }
                }
            }
            kad::QueryResult::GetRecord(Ok(
                kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
            ))
            | kad::QueryResult::GetRecord(Err(_)) => {
                tracing::debug!("GetRecord Finished/Err for query {:?}", id);
                if let Some(mapped_name) = event_loop.query_id_to_name.remove(&id) {
                    match mapped_name {
                        crate::event_loop::core::QueryType::Quorum(name) => {
                            event_loop.handle_quorum_completion(name);
                        }
                        crate::event_loop::core::QueryType::Get(name) => {
                            event_loop.handle_get_completion(name);
                        }
                        crate::event_loop::core::QueryType::Put(_) => {}
                    }
                }
            }
            kad::QueryResult::PutRecord(res) => {
                if let Some(crate::event_loop::core::QueryType::Put(name)) =
                    event_loop.query_id_to_name.remove(&id)
                {
                    let mut complete = false;
                    if let Some(pending) = event_loop.pending_puts.get_mut(&name) {
                        pending.expected_responses -= 1;
                        if res.is_ok() {
                            pending.success_count += 1;
                        }
                        if pending.expected_responses == 0 {
                            complete = true;
                        }
                    }
                    if complete {
                        if let Some(pending) = event_loop.pending_puts.remove(&name) {
                            if pending.success_count > 0 {
                                tracing::debug!(name = %name, success = %pending.success_count, "Publish succeeded over network");
                                let _ = pending.responder.send(Ok(()));
                            } else {
                                tracing::warn!(error_code = "KIN-PUB-004", name = %name, "Publish: all DHT puts failed over network");
                                let _ = pending.responder.send(Err(
                                    kinetic_core::error::PublishError::AllFailed {
                                        count: 0,
                                    },
                                ));
                            }
                        }
                    }
                }
            }
            _ => {}
        },
        kad::Event::InboundRequest {
            request:
                kad::InboundRequest::PutRecord {
                    source,
                    record: Some(record),
                    ..
                },
        } => {
            if event_loop.light_nodes.contains(&source) {
                tracing::warn!("Light node {} attempted to PutRecord (Write). Rejecting and disconnecting.", source);
                let _ = event_loop.swarm.disconnect_peer_id(source);
                let expire_time = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 86400;
                event_loop.banned_peers.put(source, expire_time);
                return;
            }

            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                if parsed.get("vdf_proof").is_some() {
                    if let Ok(reveal) =
                        serde_json::from_value::<kinetic_core::types::Reveal>(parsed)
                    {
                        let store = event_loop.swarm.behaviour_mut().kademlia.store_mut();
                        let storage = store.storage.clone();
                        let engine = store.vdf_engine.clone();
                        let current_drand_kyn = store.current_drand_kyn;

                        if let Some(loopback) = &event_loop.loopback_tx {
                            let loopback_clone = loopback.clone();
                            let record_clone = record.clone();
                            crate::event_loop::utils::spawn(async move {
                                let verdict =
                                    crate::event_loop::utils::spawn_blocking(move || {
                                        crate::store::verification::verify_reveal(
                                            &reveal,
                                            &storage,
                                            current_drand_kyn,
                                            &engine,
                                        )
                                    })
                                    .await;

                                let _ = loopback_clone.send(crate::event_loop::core::LoopbackCommand::CommitVerifiedRecord {
                                    source,
                                    record: record_clone,
                                    verdict,
                                });
                            });
                        }
                        return;
                    }
                }
            }

            let put_result = event_loop
                .swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .put_record(record.clone());

            if let Err(e) = put_result {
                if e.severity() == kinetic_core::error::Severity::Error {
                    let now = web_time::Instant::now();
                    let (count, last_time) = event_loop
                        .bad_vdf_counts
                        .get(&source)
                        .copied()
                        .unwrap_or((0, now));
                    let new_val = if now.duration_since(last_time)
                        > web_time::Duration::from_secs(60)
                    {
                        (1, now)
                    } else {
                        (count + 1, now)
                    };
                    event_loop.bad_vdf_counts.put(source, new_val);

                    if new_val.0 >= 3 {
                        tracing::warn!("Peer {} sent 3 invalid records within 60s — disconnecting and banning", source);
                        let _ = event_loop.swarm.disconnect_peer_id(source);
                        let expire_time = web_time::SystemTime::now()
                            .duration_since(web_time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            + 86400;

                        event_loop.banned_peers.put(source, expire_time);

                        let key = format!(
                            "{}{}",
                            kinetic_core::constants::DB_PREFIX_BANNED_PEER,
                            source
                        );
                        let _ = event_loop
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .store_mut()
                            .storage
                            .put(key.as_bytes(), &expire_time.to_be_bytes());
                    }
                } else {
                    tracing::debug!(
                        "Peer {} sent a record rejected with non-fatal error: {}",
                        source,
                        e
                    );
                }
            }
        }
        _ => {}
    }
}
