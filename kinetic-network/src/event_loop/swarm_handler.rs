//! Inbound libp2p swarm event handling, peer validation, and protocol dispatching.

use crate::behavior::KineticBehaviorEvent;
use crate::event_loop::utils::*;
use kinetic_core::error::ResolutionError;

use libp2p::kad::store::RecordStore;
use libp2p::{kad, swarm::SwarmEvent};

impl super::core::NetworkEventLoop {
    pub(crate) fn is_valid_pow(&self, peer_id: &libp2p::PeerId) -> bool {
        if self.disable_pow {
            return true;
        }
        self.current_drand_kyn > 0
            && crate::pow::is_valid_sybil_pow(
                peer_id,
                self.current_drand_kyn,
                kinetic_core::constants::POW_DIFFICULTY_BITS,
            )
    }

    fn handle_quorum_completion(&mut self, name: std::sync::Arc<str>) {
        if let std::collections::hash_map::Entry::Occupied(mut pending) =
            self.pending_quorums.entry(name.clone())
        {
            pending.get_mut().expected_responses -= 1;
            if pending.get().expected_responses == 0 {
                let p = pending.remove();
                let _ = p.responder.send(Ok(p.match_count));
            }
        }
    }

    fn handle_get_completion(&mut self, name: std::sync::Arc<str>) {
        if let std::collections::hash_map::Entry::Occupied(mut pending) =
            self.pending_gets.entry(name.clone())
        {
            pending.get_mut().expected_responses -= 1;
            if pending.get().expected_responses == 0 {
                let p = pending.remove();
                let name_clean = name.trim_end_matches('.').to_string();
                let peers_q = p.peers_queried;

                // Pre-compute local fallback before offloading
                let keys = kinetic_core::types::derive_storage_keys(
                    &name,
                    kinetic_core::constants::NETWORK_ID,
                );
                let mut local_fallback = None;
                for key_bytes in &keys {
                    let k = kad::RecordKey::new(key_bytes);
                    if let Some(record) = self.swarm.behaviour_mut().kademlia.store_mut().get(&k) {
                        local_fallback = Some(record.value.clone());
                        break;
                    }
                }

                let current_drand_kyn = self.current_drand_kyn;

                // Spawn a blocking task to do heavy VDF processing
                crate::event_loop::utils::spawn(async move {
                    let tie_breaker_result = crate::event_loop::utils::spawn_blocking(move || {
                        Self::xor_tie_breaker(&name, p.received_payloads, current_drand_kyn)
                    })
                    .await;

                    match tie_breaker_result {
                        Some(payload) => {
                            tracing::debug!(
                                name = %name_clean,
                                peers_queried = %peers_q,
                                "DHT resolution succeeded"
                            );
                            for responder in p.responders {
                                let _ = responder.send(Ok(payload.clone()));
                            }
                        }
                        None => {
                            if let Some(payload) = local_fallback {
                                tracing::info!(
                                    "Resolved {} locally from own store after DHT network failure",
                                    name_clean
                                );
                                for responder in p.responders {
                                    let _ = responder.send(Ok(payload.clone()));
                                }
                            } else {
                                tracing::warn!(
                                    error_code = "KIN-RES-002",
                                    name = %name_clean,
                                    peers_queried = %peers_q,
                                    "DHT resolution: name not found in network or local cache"
                                );
                                for responder in p.responders {
                                    let _ = responder.send(Err(ResolutionError::NotFound {
                                        name: name_clean.clone(),
                                        peers_queried: peers_q,
                                    }));
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    pub(crate) async fn handle_swarm_event(&mut self, event: SwarmEvent<KineticBehaviorEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let now = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if let Some(&expire_time) = self.banned_peers.peek(&peer_id) {
                    if expire_time > now {
                        tracing::warn!(
                            "Banned peer {} attempted to connect, disconnecting immediately.",
                            peer_id
                        );
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        return;
                    } else {
                        // Expired, remove from memory
                        self.banned_peers.pop(&peer_id);
                    }
                }

                tracing::info!("Connection established with {:?}", peer_id);
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                if is_bootstrap {
                    self.bootstrap_connection_time
                        .insert(peer_id, web_time::Instant::now());
                }

                if self.current_drand_kyn == 0 && !is_bootstrap && !self.disable_pow {
                    tracing::debug!(
                        "Peer {} connected during uninitialized drand kyn, disconnecting",
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                if self.disable_pow {
                    return;
                }

                if let Some(loopback) = &self.loopback_tx {
                    let loopback_clone = loopback.clone();
                    let current_kyn = self.current_drand_kyn;
                    let peer_id_clone = peer_id;
                    let pow_semaphore = self.pow_semaphore.clone();
                    let remote_addr = endpoint.get_remote_address().clone();
                    crate::event_loop::utils::spawn(async move {
                        let _permit = pow_semaphore.acquire().await;
                        let valid = crate::event_loop::utils::spawn_blocking(move || {
                            crate::pow::is_valid_sybil_pow(
                                &peer_id_clone,
                                current_kyn,
                                kinetic_core::constants::POW_DIFFICULTY_BITS,
                            )
                        })
                        .await;
                        let _ = loopback_clone.send(
                            crate::event_loop::core::LoopbackCommand::ConnectionPoWVerified {
                                peer_id: peer_id_clone,
                                valid,
                                is_bootstrap,
                                remote_addr,
                            },
                        );
                    });
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) => match e {
                kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
                    kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                        tracing::debug!("GetRecord Ok FoundRecord for query {:?}", id);
                        if let Some(mapped_name) = self.query_id_to_name.get(&id) {
                            match mapped_name {
                                crate::event_loop::core::QueryType::Quorum(name) => {
                                    if let Some(pending) = self.pending_quorums.get_mut(name) {
                                        if peer_record.record.value == pending.target_payload {
                                            pending.match_count += 1;
                                        }
                                    }
                                }
                                crate::event_loop::core::QueryType::Get(name) => {
                                    if let Some(pending) = self.pending_gets.get_mut(name) {
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
                        if let Some(mapped_name) = self.query_id_to_name.remove(&id) {
                            match mapped_name {
                                crate::event_loop::core::QueryType::Quorum(name) => {
                                    self.handle_quorum_completion(name);
                                }
                                crate::event_loop::core::QueryType::Get(name) => {
                                    self.handle_get_completion(name);
                                }
                                crate::event_loop::core::QueryType::Put(_) => {}
                            }
                        }
                    }
                    kad::QueryResult::PutRecord(res) => {
                        if let Some(crate::event_loop::core::QueryType::Put(name)) =
                            self.query_id_to_name.remove(&id)
                        {
                            let mut complete = false;
                            if let Some(pending) = self.pending_puts.get_mut(&name) {
                                pending.expected_responses -= 1;
                                if res.is_ok() {
                                    pending.success_count += 1;
                                }
                                if pending.expected_responses == 0 {
                                    complete = true;
                                }
                            }
                            if complete {
                                if let Some(pending) = self.pending_puts.remove(&name) {
                                    if pending.success_count > 0 {
                                        tracing::debug!(name = %name, success = %pending.success_count, "Publish succeeded over network");
                                        let _ = pending.responder.send(Ok(()));
                                    } else {
                                        tracing::warn!(error_code = "KIN-PUB-004", name = %name, "Publish: all DHT puts failed over network");
                                        let _ = pending.responder.send(Err(
                                            kinetic_core::error::PublishError::AllFailed {
                                                count: 0,
                                            },
                                        )); // We lost original count context, but count isn't critical.
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
                    if self.light_nodes.contains(&source) {
                        tracing::warn!("Light node {} attempted to PutRecord (Write). Rejecting and disconnecting.", source);
                        let _ = self.swarm.disconnect_peer_id(source);
                        let expire_time = web_time::SystemTime::now()
                            .duration_since(web_time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            + 86400;
                        self.banned_peers.put(source, expire_time);
                        return;
                    }

                    // Offload VDF verification for Reveals
                    if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                        if parsed.get("vdf_proof").is_some() {
                            if let Ok(reveal) =
                                serde_json::from_value::<kinetic_core::types::Reveal>(parsed)
                            {
                                let store = self.swarm.behaviour_mut().kademlia.store_mut();
                                let storage = store.storage.clone();
                                let engine = store.vdf_engine.clone();
                                let current_drand_kyn = store.current_drand_kyn;

                                if let Some(loopback) = &self.loopback_tx {
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

                    // For non-Reveal records or if parsing fails (will be rejected), run inline
                    let put_result = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .put_record(record.clone());

                    if let Err(e) = put_result {
                        if e.severity() == kinetic_core::error::Severity::Error {
                            let now = web_time::Instant::now();
                            let (count, last_time) = self
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
                            self.bad_vdf_counts.put(source, new_val);

                            if new_val.0 >= 3 {
                                tracing::warn!("Peer {} sent 3 invalid records within 60s — disconnecting and banning", source);
                                let _ = self.swarm.disconnect_peer_id(source);
                                let expire_time = web_time::SystemTime::now()
                                    .duration_since(web_time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    + 86400;

                                self.banned_peers.put(source, expire_time);

                                let key = format!(
                                    "{}{}",
                                    kinetic_core::constants::DB_PREFIX_BANNED_PEER,
                                    source
                                );
                                let _ = self
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
            },
            SwarmEvent::Behaviour(KineticBehaviorEvent::Proxy(e)) => {
                use libp2p::request_response::{Event, Message};
                match e {
                    Event::Message { message, .. } => match message {
                        Message::Request {
                            request, channel, ..
                        } => {
                            if let Some(tx) = &self.incoming_proxy_tx {
                                let tx_clone = tx.clone();
                                crate::event_loop::utils::spawn(async move {
                                    let _ = tx_clone.send((request, channel)).await;
                                });
                            }
                        }
                        Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some(responder) = self.pending_proxy_requests.remove(&request_id)
                            {
                                let _ = responder.send(Ok(response));
                            }
                        }
                    },
                    Event::OutboundFailure {
                        request_id, error, ..
                    } => {
                        if let Some(responder) = self.pending_proxy_requests.remove(&request_id) {
                            use libp2p::request_response::OutboundFailure;
                            let proxy_err = match error {
                                OutboundFailure::DialFailure => crate::client::ProxyError::Offline,
                                OutboundFailure::Timeout => crate::client::ProxyError::Timeout,
                                OutboundFailure::ConnectionClosed => {
                                    crate::client::ProxyError::ConnectionClosed
                                }
                                OutboundFailure::UnsupportedProtocols => {
                                    crate::client::ProxyError::UnsupportedProtocols
                                }
                                _ => {
                                    crate::client::ProxyError::Other(format!("{:?}", error).into())
                                }
                            };
                            let _ = responder.send(Err(proxy_err));
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Cdn(e)) => {
                use libp2p::request_response::{Event, Message};
                match e {
                    Event::Message { message, peer } => match message {
                        Message::Request {
                            request, channel, ..
                        } => {
                            let domain = request.domain.as_ref();
                            let record = {
                                let keys = kinetic_core::types::derive_storage_keys(
                                    domain,
                                    kinetic_core::constants::NETWORK_ID,
                                );
                                let mut result = None;
                                for key_bytes in &keys {
                                    let k = libp2p::kad::RecordKey::new(key_bytes);
                                    if let Some(record) =
                                        self.swarm.behaviour_mut().kademlia.store_mut().get(&k)
                                    {
                                        result = Some(record.value.clone());
                                        break;
                                    }
                                }
                                result
                            };
                            
                            let _ = self.swarm.behaviour_mut().cdn.send_response(
                                channel,
                                kinetic_types::cdn::CdnResponse { record },
                            );
                            
                            self.proxy_cdn_usage.0 += 1;
                        }
                        Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some(domain) = self.pending_cdn_requests.remove(&request_id) {
                                if let Some(record_bytes) = response.record {
                                    if let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&record_bytes) {
                                        let skip_verify = kinetic_core::config::is_dev_mode();
                                        if self.swarm.behaviour_mut().kademlia.store_mut().handle_record(&record, skip_verify).is_ok() {
                                            tracing::info!("CDN Hit! Accelerated resolution of {} via {}", domain, peer);
                                            if let Some(mut pending) = self.pending_gets.remove(&domain) {
                                                for tx in pending.responders.drain(..) {
                                                    let _ = tx.send(Ok(record_bytes.clone()));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Event::OutboundFailure {
                        request_id, ..
                    } => {
                        self.pending_cdn_requests.remove(&request_id);
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Gossipsub(
                libp2p::gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                },
            )) => {
                let topic = message.topic.into_string();
                let payload = message.data;
                let loopback = self.loopback_tx.clone();
                let gossip_tx = self.gossip_tx.clone();
                let semaphore = self.gossip_semaphore.clone();

                // Reject immediately if the verification pool is saturated.
                // This prevents a flood attacker from exhausting the blocking thread pool.
                let _permit = match semaphore.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(
                            "Gossip semaphore saturated — dropping message from {} on topic {}",
                            propagation_source, topic
                        );
                        if let Some(tx) = &self.loopback_tx {
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
                                // Pure signature check — no state mutation, no executed_hashes touch.
                                // We only need to confirm at least one signature is valid against the root key.
                                let gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                if let Ok(root_key) = gov.get_root_key() {
                                    drop(gov); // Release lock before crypto work
                                    let action_bytes = signed_msg.to_canonical_bytes();
                                    return signed_msg
                                        .signatures
                                        .iter()
                                        .any(|sig| kinetic_core::governance::verify_signature(&root_key, &action_bytes, sig));
                                }
                            }
                            return false;
                        }
                        // Unknown topic — gossipsub only delivers messages on topics we subscribed to,
                        // so this peer is not spamming. We have no application-level crypto rule for
                        // this topic yet, so accept it and let the downstream application decide.
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
            SwarmEvent::Behaviour(KineticBehaviorEvent::Gossipsub(_)) => {}
            SwarmEvent::Behaviour(KineticBehaviorEvent::Autonat(
                libp2p::autonat::Event::StatusChanged { old, new },
            )) => {
                tracing::info!("AutoNAT status changed from {:?} to {:?}", old, new);
                if let libp2p::autonat::NatStatus::Public(address) = new {
                    tracing::info!("Node is PUBLIC. We are fully reachable at {}", address);
                    // Add external address to Kademlia to ensure we are visible
                    self.swarm.add_external_address(address);
                    self.nat_status = "Public".to_string();

                    let peers: Vec<_> = self.swarm.connected_peers().copied().collect();
                    for peer in peers {
                        self.swarm
                            .behaviour_mut()
                            .identify
                            .push(std::iter::once(peer));
                    }
                } else if matches!(new, libp2p::autonat::NatStatus::Private) {
                    tracing::info!("Node is PRIVATE (Behind NAT). Relay & UPnP fallback active.");
                    self.nat_status = "Relayed (Private)".to_string();
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Autonat(_)) => {}
            #[cfg(not(target_arch = "wasm32"))]
            SwarmEvent::Behaviour(KineticBehaviorEvent::Upnp(event)) => {
                tracing::info!("UPnP Event: {:?}", event);
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Dcutr(event)) => {
                tracing::info!("DCUtR Event: {:?}", event);
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::RelayClient(event)) => {
                tracing::debug!("RelayClient Event: {:?}", event);
            }
            #[cfg(not(target_arch = "wasm32"))]
            SwarmEvent::Behaviour(KineticBehaviorEvent::RelayServer(event)) => {
                tracing::debug!("RelayServer Event: {:?}", event);
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info },
            )) => {
                tracing::info!(
                    "Received Identify from peer {:?} with addrs: {:?}",
                    peer_id,
                    info.listen_addrs
                );
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                let pow_valid = self.is_valid_pow(&peer_id);

                if !pow_valid && is_bootstrap {
                    if let Some(conn_time) = self.bootstrap_connection_time.get(&peer_id) {
                        if conn_time.elapsed() > web_time::Duration::from_secs(24 * 3600) {
                            tracing::warn!("Bootstrap peer {} failed to provide valid PoW after 24 hours. Disconnecting.", peer_id);
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            return;
                        }
                    }
                }

                if self.disable_pow || pow_valid || is_bootstrap {
                    for addr in info.listen_addrs {
                        if !is_routable_multiaddr(&addr, self.disable_pow) {
                            tracing::debug!(
                                "Discarding unroutable address {:?} for peer {}",
                                addr,
                                peer_id
                            );
                            continue;
                        }
                        tracing::info!("Adding peer {:?} addr {:?} to Kademlia", peer_id, addr);
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                } else {
                    tracing::debug!(
                        "Peer {} failed PoW, ignoring for Kademlia routing table",
                        peer_id
                    );
                }
                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
            }
            #[cfg(not(target_arch = "wasm32"))]
            SwarmEvent::Behaviour(KineticBehaviorEvent::Mdns(libp2p::mdns::Event::Discovered(
                list,
            ))) => {
                for (peer_id, multiaddr) in list {
                    let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                    let pow_valid = self.is_valid_pow(&peer_id);

                    if pow_valid || is_bootstrap {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, multiaddr);
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(
                    "Outgoing connection error to peer {:?}: {:?}",
                    peer_id,
                    error
                );
                if let Some(peer_id) = peer_id {
                    self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                }
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                tracing::debug!("Dialing peer {:?}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::info!("Connection closed for peer {:?}: {:?}", peer_id, cause);
                self.bootstrap_connection_time.remove(&peer_id);
                self.light_nodes.remove(&peer_id);
                self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
            }
            _ => {}
        }
    }
}
