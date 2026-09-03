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
        self.current_kyn > 0
            && crate::pow::is_valid_sybil_pow(
                peer_id,
                self.current_kyn,
                kinetic_core::constants::POW_DIFFICULTY_BITS,
            )
    }

    pub(crate) fn handle_quorum_completion(&mut self, name: std::sync::Arc<str>) {
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

    pub(crate) fn handle_get_completion(&mut self, name: std::sync::Arc<str>) {
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
                    kinetic_core::constants::NETWORK_SALT,
                );
                let mut local_fallback = None;
                for key_bytes in &keys {
                    let k = kad::RecordKey::new(key_bytes);
                    if let Some(record) = self.swarm.behaviour_mut().kademlia.store_mut().get(&k) {
                        local_fallback = Some(record.value.clone());
                        break;
                    }
                }

                let current_kyn = self.current_kyn;

                // Spawn a blocking task to do heavy VDF processing
                crate::event_loop::utils::spawn(async move {
                    let tie_breaker_result = crate::event_loop::utils::spawn_blocking(move || {
                        Self::xor_tie_breaker(&name, p.received_payloads, current_kyn)
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
                                let err = kinetic_core::error::ResolutionError::NotFound {
                                    name: name_clean.clone(),
                                    peers_queried: peers_q,
                                };
                                tracing::warn!(
                                    error_code = err.code(),
                                    name = %name_clean,
                                    peers_queried = %peers_q,
                                    "{}", err
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

                // TODO: BUG - mismatched current_kyn and unix_now
                // banned_peers stores expiry as a `kyn` round, but we are comparing it to Unix seconds (`now`).
                // This causes bans to expire immediately. We need to compare against `self.current_kyn` instead.
                if let Some(&expire_time) = self.banned_peers.peek(&peer_id) {
                    if expire_time > now {
                        let err = kinetic_core::error::P2pError::BannedPeerConnectionAttempt(peer_id.to_string());
                        tracing::warn!(error_code = err.code(), "{}", err);
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

                if self.current_kyn == 0 && !is_bootstrap && !self.disable_pow {
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
                    let current_kyn = self.current_kyn;
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
            SwarmEvent::Behaviour(KineticBehaviorEvent::Kademlia(e)) => {
                crate::event_loop::handlers::kademlia::handle(self, e).await;
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Proxy(e)) => {
                crate::event_loop::handlers::proxy::handle(self, e).await;
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Cdn(e)) => {
                crate::event_loop::handlers::cdn::handle(self, e).await;
            }
            SwarmEvent::Behaviour(KineticBehaviorEvent::Gossipsub(e)) => {
                crate::event_loop::handlers::gossipsub::handle(self, e).await;
            }
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

                if !pow_valid
                    && is_bootstrap
                    && let Some(conn_time) = self.bootstrap_connection_time.get(&peer_id)
                    && conn_time.elapsed() > web_time::Duration::from_secs(24 * 3600)
                {
                    let err = kinetic_core::error::P2pError::BootstrapPowTimeout(peer_id.to_string());
                    tracing::warn!(error_code = err.code(), "{}", err);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                if self.disable_pow || pow_valid || is_bootstrap {
                    for addr in info.listen_addrs {
                        if !is_routable_multiaddr(&addr, self.disable_pow, is_bootstrap) {
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
                let err = kinetic_core::error::P2pError::OutgoingConnectionError(format!("{:?}", peer_id), format!("{:?}", error));
                tracing::warn!(error_code = err.code(), "{}", err);
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
