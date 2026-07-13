use crate::behavior::KineticBehaviorEvent;
use crate::event_loop::utils::*;
use kinetic_core::error::ResolutionError;
use kinetic_core::traits::StorageEngine;
use libp2p::kad::store::RecordStore;
use libp2p::{kad, swarm::SwarmEvent};

impl super::core::NetworkEventLoop {
    pub(crate) async fn handle_swarm_event(&mut self, event: SwarmEvent<KineticBehaviorEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if self.banned_peers.contains(&peer_id) {
                    tracing::warn!(
                        "Banned peer {} attempted to connect, disconnecting immediately.",
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                tracing::info!("Connection established with {:?}", peer_id);
                let is_bootstrap = self.bootstrap_peers.contains(&peer_id);
                if is_bootstrap {
                    self.bootstrap_connection_time
                        .insert(peer_id, web_time::Instant::now());
                }

                if self.current_drand_pulse == 0 && !is_bootstrap {
                    tracing::debug!(
                        "Peer {} connected during uninitialized drand pulse, disconnecting",
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                let pow_valid = self.current_drand_pulse > 0
                    && crate::pow::is_valid_sybil_pow(
                        &peer_id,
                        self.current_drand_pulse,
                        crate::pow::DEFAULT_DIFFICULTY_BITS,
                    );

                if !pow_valid && !is_bootstrap {
                    tracing::debug!("Peer {} failed S/Kademlia PoW for epoch, disconnecting them to prevent connection slot exhaustion", peer_id);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                } else if !pow_valid && is_bootstrap {
                    tracing::debug!(
                        "Bootstrap peer {} failed PoW — permitted initially",
                        peer_id
                    );
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) => match e {
                kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
                    kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                        if let Some(mapped_name) = self.query_id_to_name.get(&id) {
                            if mapped_name.starts_with("quorum_") {
                                let actual_name = mapped_name.trim_start_matches("quorum_");
                                if let Some(pending) = self.pending_quorums.get_mut(actual_name) {
                                    if peer_record.record.value == pending.target_payload {
                                        pending.match_count += 1;
                                    }
                                }
                            } else {
                                if let Some(pending) = self.pending_gets.get_mut(mapped_name) {
                                    pending.received_payloads.push(peer_record.record.value);
                                }
                            }
                        }
                    }
                    kad::QueryResult::GetRecord(Ok(
                        kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                    ))
                    | kad::QueryResult::GetRecord(Err(_)) => {
                        if let Some(mapped_name) = self.query_id_to_name.remove(&id) {
                            if mapped_name.starts_with("quorum_") {
                                let actual_name =
                                    mapped_name.trim_start_matches("quorum_").to_string();
                                let mut complete = false;
                                if let Some(pending) = self.pending_quorums.get_mut(&actual_name) {
                                    pending.expected_responses -= 1;
                                    if pending.expected_responses == 0 {
                                        complete = true;
                                    }
                                }
                                if complete {
                                    if let Some(pending) = self.pending_quorums.remove(&actual_name)
                                    {
                                        let _ = pending.responder.send(Ok(pending.match_count));
                                    }
                                }
                            } else {
                                let mut complete = false;
                                if let Some(pending) = self.pending_gets.get_mut(&mapped_name) {
                                    pending.expected_responses -= 1;
                                    if pending.expected_responses == 0 {
                                        complete = true;
                                    }
                                }
                                if complete {
                                    if let Some(pending) = self.pending_gets.remove(&mapped_name) {
                                        let name_clean =
                                            mapped_name.trim_end_matches('.').to_string();
                                        let peers_q = pending.peers_queried;
                                        match Self::xor_tie_breaker(
                                            &mapped_name,
                                            pending.received_payloads,
                                            self.current_drand_pulse,
                                        ) {
                                            Some(payload) => {
                                                tracing::debug!(
                                                    name = %name_clean,
                                                    peers_queried = %peers_q,
                                                    "DHT resolution succeeded"
                                                );
                                                let _ = pending.responder.send(Ok(payload));
                                            }
                                            None => {
                                                tracing::warn!(
                                                    error_code = "KIN-RES-002",
                                                    name = %name_clean,
                                                    peers_queried = %peers_q,
                                                    "DHT resolution: name not found in network"
                                                );
                                                let _ = pending.responder.send(Err(
                                                    ResolutionError::NotFound {
                                                        name: name_clean,
                                                        peers_queried: peers_q,
                                                    },
                                                ));
                                            }
                                        }
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
                    let put_result = libp2p::kad::store::RecordStore::put(
                        self.swarm.behaviour_mut().kademlia.store_mut(),
                        record.clone(),
                    );

                    if put_result.is_err() {
                        let is_commitment =
                            serde_json::from_slice::<kinetic_core::types::Commitment>(
                                &record.value,
                            )
                            .is_ok();

                        if is_commitment {
                            let entry = self.commitment_miss_counts.entry(source).or_insert(0);
                            *entry += 1;
                        } else {
                            let now = web_time::Instant::now();
                            let entry = self.bad_vdf_counts.entry(source).or_insert((0, now));
                            if now.duration_since(entry.1) > web_time::Duration::from_secs(60) {
                                *entry = (1, now);
                            } else {
                                entry.0 += 1;
                            }

                            if entry.0 >= 3 {
                                tracing::warn!("Peer {} sent 3 invalid records within 60s — disconnecting and banning", source);
                                let _ = self.swarm.disconnect_peer_id(source);
                                self.banned_peers.insert(source);
                                let expire_time = web_time::SystemTime::now()
                                    .duration_since(web_time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                                    + 86400;
                                let key = format!("kinetic_banned_peer:{}", source);
                                let _ = self
                                    .swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .store_mut()
                                    .storage
                                    .put(key.as_bytes(), &expire_time.to_be_bytes());
                            }
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
                                _ => crate::client::ProxyError::Other(format!("{:?}", error)),
                            };
                            let _ = responder.send(Err(proxy_err));
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Gossipsub(
                libp2p::gossipsub::Event::Message { message, .. },
            )) => {
                if let Some(tx) = &self.gossip_tx {
                    let _ = tx.try_send((message.topic.into_string(), message.data));
                }
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
                let pow_valid = self.current_drand_pulse > 0
                    && crate::pow::is_valid_sybil_pow(
                        &peer_id,
                        self.current_drand_pulse,
                        crate::pow::DEFAULT_DIFFICULTY_BITS,
                    );

                if !pow_valid && is_bootstrap {
                    if let Some(conn_time) = self.bootstrap_connection_time.get(&peer_id) {
                        if conn_time.elapsed() > web_time::Duration::from_secs(24 * 3600) {
                            tracing::warn!("Bootstrap peer {} failed to provide valid PoW after 24 hours. Disconnecting.", peer_id);
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            return;
                        }
                    }
                }

                if pow_valid || is_bootstrap {
                    for addr in info.listen_addrs {
                        if !is_routable_multiaddr(&addr) {
                            tracing::debug!(
                                "Ignoring unroutable/private address {:?} from peer {:?}",
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
                    let pow_valid = self.current_drand_pulse > 0
                        && crate::pow::is_valid_sybil_pow(
                            &peer_id,
                            self.current_drand_pulse,
                            crate::pow::DEFAULT_DIFFICULTY_BITS,
                        );

                    if (pow_valid || is_bootstrap) && is_routable_multiaddr(&multiaddr) {
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
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                tracing::debug!("Dialing peer {:?}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::debug!("Connection closed for peer {:?}: {:?}", peer_id, cause);

                // Case 189: Mass Peer Disconnect
                let active_peers = self.swarm.network_info().num_peers();
                if active_peers == 0 && !self.bootstrap_nodes.is_empty() {
                    tracing::warn!(
                        "Mass Peer Disconnect: 0 active peers. Re-dialing bootstrap nodes..."
                    );
                    for node_str in &self.bootstrap_nodes {
                        if let Ok(addr) = node_str.parse::<libp2p::Multiaddr>() {
                            let _ = self.swarm.dial(addr);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
