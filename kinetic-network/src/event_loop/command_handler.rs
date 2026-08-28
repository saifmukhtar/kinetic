//! Outbound command handling for publishing, resolving, and proxying requests across the swarm.

use crate::client::Command;

use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use libp2p::kad;
use libp2p::kad::store::RecordStore;

impl super::core::NetworkEventLoop {
    fn enqueue_dht_puts(
        &mut self,
        name: std::sync::Arc<str>,
        keys: Vec<[u8; 32]>,
        payload: Vec<u8>,
        responder: tokio::sync::oneshot::Sender<Result<(), kinetic_core::error::PublishError>>,
    ) {
        if self.pending_puts.contains_key(&name) {
            let _ = responder.send(Err(kinetic_core::error::PublishError::Rejected(
                "A publish operation for this domain is already in progress".to_string(),
            )));
            return;
        }

        let mut expected = 0;
        let mut _validation_failures = 0;
        for key_bytes in &keys {
            let record_key = kad::RecordKey::new(key_bytes);
            let record = kad::Record::new(record_key, payload.clone());

            // Validate locally first. If local store rejects it (e.g. invalid signature),
            // the network will too, so don't even bother publishing.
            if let Err(e) = self
                .swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .put(record.clone())
            {
                tracing::debug!("Local store put_record failed: {:?}", e);
                let _ = responder.send(Err(PublishError::Rejected(e.to_string())));
                return;
            }

            // Queue outbound network request
            match self
                .swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, kad::Quorum::One)
            {
                Ok(query_id) => {
                    self.query_id_to_name.insert(
                        query_id,
                        crate::event_loop::core::QueryType::Put(name.clone()),
                    );
                    expected += 1;
                }
                Err(e) => {
                    tracing::debug!("kademlia.put_record failed: {:?}", e);
                }
            }
        }

        if expected > 0 {
            self.pending_puts.insert(
                name.clone(),
                crate::event_loop::utils::PendingPut {
                    responder,
                    expected_responses: expected,
                    success_count: 0,
                },
            );
        } else {
            tracing::warn!(error_code = "KIN-PUB-004", name = %name, total = %keys.len(), "Publish: all DHT puts failed immediately");
            let _ = responder.send(Err(PublishError::AllFailed { count: keys.len() }));
        }
    }

    fn dispatch_dht_queries(
        &mut self,
        name: std::sync::Arc<str>,
        keys: Vec<[u8; 32]>,
        query_type_ctor: fn(std::sync::Arc<str>) -> crate::event_loop::core::QueryType,
    ) -> usize {
        let mut expected = 0;
        for key_bytes in keys {
            let record_key = kad::RecordKey::new(&key_bytes);
            let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
            self.query_id_to_name
                .insert(query_id, query_type_ctor(name.clone()));
            expected += 1;
        }
        expected
    }

    pub(crate) async fn handle_command(&mut self, command: Command) {
        match command {
            Command::GetCurrentKyn { responder } => {
                let _ = responder.send(self.current_kyn);
            }
            Command::PublishRedundant {
                name,
                payload,
                responder,
            } => {
                let keys = kinetic_core::types::derive_storage_keys(
                    &name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                self.enqueue_dht_puts(name, keys, payload, responder);
            }
            Command::Bootstrap { responder } => {
                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                // We should also re-dial the hardcoded bootstrap peers in case the TCP connections dropped
                for peer in &self.bootstrap_peers {
                    let _ = self.swarm.dial(*peer);
                }
                let _ = responder.send(Ok(()));
            }
            Command::PublishHeartbeat {
                name,
                payload,
                responder,
            } => {
                let keys = kinetic_core::types::derive_heartbeat_keys(
                    &name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                self.enqueue_dht_puts(name, keys, payload, responder);
            }
            Command::ResolveRedundant { name, responder } => {
                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    let name_clean = name.trim_end_matches('.').to_string();
                    tracing::warn!(
                        error_code = "KIN-QRY-001",
                        name = %name_clean,
                        "Resolution failed: node is offline (0 peers)"
                    );

                    // Fallback to local store as a last resort since we're offline
                    let keys = kinetic_core::types::derive_storage_keys(
                        &name,
                        kinetic_core::constants::NETWORK_SALT,
                    );
                    for key_bytes in &keys {
                        let k = kad::RecordKey::new(key_bytes);
                        if let Some(record) =
                            self.swarm.behaviour_mut().kademlia.store_mut().get(&k)
                        {
                            tracing::info!(
                                "Resolved {} locally from own store (offline fallback)",
                                name
                            );
                            let _ = responder.send(Ok(record.value.clone()));
                            return;
                        }
                    }

                    let _ = responder.send(Err(ResolutionError::Offline));
                    return;
                }

                if let Some(pending) = self.pending_gets.get_mut(&name) {
                    pending.responders.push(responder);
                    return;
                }

                // Race Kademlia with the CDN layer: Blast a CDN request to up to 3 connected peers
                let peers: Vec<_> = self.swarm.connected_peers().copied().take(3).collect();
                for peer in peers {
                    let req_id = self
                        .swarm
                        .behaviour_mut()
                        .cdn
                        .send_request(&peer, kinetic_types::cdn::CdnRequest { name: name.clone() });
                    self.pending_cdn_requests.insert(req_id, name.clone());
                }

                let keys = kinetic_core::types::derive_storage_keys(
                    &name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                let expected = self.dispatch_dht_queries(
                    name.clone(),
                    keys,
                    crate::event_loop::core::QueryType::Get,
                );

                self.pending_gets.insert(
                    name.clone(),
                    crate::event_loop::utils::PendingGet {
                        responders: vec![responder],
                        expected_responses: expected,
                        received_payloads: Vec::new(),
                        peers_queried: expected,
                    },
                );
            }
            Command::VerifyQuorum {
                name,
                payload,
                responder,
            } => {
                if self.pending_quorums.contains_key(&name) {
                    let _ = responder.send(Err(kinetic_core::error::NetworkClientError::Other(
                        "A quorum verification for this domain is already in progress".to_string(),
                    )));
                    return;
                }

                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    tracing::warn!("Offline mode: Failing fast for VerifyQuorum (0 peers)");
                    let _ = responder.send(Ok(0));
                    return;
                }

                let keys = kinetic_core::types::derive_storage_keys(
                    &name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                let expected = self.dispatch_dht_queries(
                    name.clone(),
                    keys,
                    crate::event_loop::core::QueryType::Quorum,
                );

                self.pending_quorums.insert(
                    name.clone(),
                    crate::event_loop::utils::PendingQuorum {
                        responder,
                        expected_responses: expected,
                        target_payload: payload,
                        match_count: 0,
                    },
                );
            }
            Command::SendProxyRequest {
                peer,
                req,
                responder,
            } => {
                let req_id = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_request(&peer, *req);
                self.pending_proxy_requests.insert(req_id, responder);
            }
            Command::SendProxyResponse { channel, res } => {
                let res = *res;
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_response(channel, res);
            }
            Command::GetNetworkStatus { responder } => {
                let info = self.swarm.network_info();
                let peers = info.num_peers();
                let status = if peers > 0 {
                    "Online"
                } else {
                    "Offline (Bootstrap/Local)"
                };
                let _uptime = format!("{} seconds", self.startup_time.elapsed().as_secs());

                // Return the actual number of known DNS zones in our local DHT shard
                let _dht_size = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .store_mut()
                    .reveals_by_name
                    .len();

                let _ = responder.send(Ok(serde_json::json!({
                    "status": status,
                    "peer_id": self.swarm.local_peer_id().to_string(),
                    "connected_peers": peers,
                    "listen_addrs": self.swarm.listeners().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "nat_status": self.nat_status,
                    "bytes_sent": 0, // libp2p connection_counters doesn't store total bandwidth in this version, so we fallback to 0
                    "bytes_received": 0,
                })));
            }
            Command::SubscribeGossip { topic, responder } => {
                let ident_topic = libp2p::gossipsub::IdentTopic::new(topic.to_string());
                let res = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&ident_topic)
                    .map(|_| ())
                    .map_err(|e| NetworkClientError::GossipSubError(e.to_string()));
                let _ = responder.send(res);
            }
            Command::BroadcastGossip {
                topic,
                payload,
                responder,
            } => {
                let ident_topic = libp2p::gossipsub::IdentTopic::new(topic.to_string());
                let res = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(ident_topic, payload)
                    .map(|_| ())
                    .map_err(|e| NetworkClientError::GossipSubError(e.to_string()));
                let _ = responder.send(res);
            }
            Command::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&message_id, &propagation_source, acceptance);
            }
        }
    }
}
