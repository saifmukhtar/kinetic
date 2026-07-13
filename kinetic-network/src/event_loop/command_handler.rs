use crate::client::Command;
use crate::event_loop::utils::*;
use kinetic_core::error::{NetworkClientError, PublishError, ResolutionError};
use libp2p::kad::store::RecordStore;
use libp2p::kad;

impl super::core::NetworkEventLoop {
    pub(crate) async fn handle_command(&mut self, command: Command) {
        match command {
            Command::PublishRedundant {
                name,
                payload,
                responder,
            } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);
                let total = keys.len();
                let mut success_count = 0usize;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(record_key, payload.clone());
                    let kad_ok = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .put_record(record.clone(), kad::Quorum::One)
                        .is_ok();
                    let store_ok = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .put(record)
                        .is_ok();
                    if kad_ok || store_ok {
                        success_count += 1;
                    }
                }
                if success_count > 0 {
                    tracing::debug!(name = %name, success = %success_count, total = %total, "PublishRedundant succeeded");
                    let _ = responder.send(Ok(()));
                } else {
                    tracing::warn!(error_code = "KIN-PUB-004", name = %name, total = %total, "PublishRedundant: all DHT puts failed");
                    let _ = responder.send(Err(PublishError::AllFailed { count: total }));
                }
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
                // Use the dedicated heartbeat keyspace — completely separate from Reveal keys.
                // Peer nodes' KRS will receive these records, validate the heartbeat signature,
                // refresh the Reveal's TTL in their MemoryStore, and update liveness metadata.
                let keys = kinetic_core::types::derive_heartbeat_keys(&name);
                let total = keys.len();
                let mut success_count = 0usize;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(record_key, payload.clone());
                    let kad_ok = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .put_record(record.clone(), kad::Quorum::One)
                        .is_ok();
                    let store_ok = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .put(record)
                        .is_ok();
                    if kad_ok || store_ok {
                        success_count += 1;
                    }
                }
                if success_count > 0 {
                    tracing::debug!(name = %name, success = %success_count, total = %total, "PublishHeartbeat succeeded");
                    let _ = responder.send(Ok(()));
                } else {
                    tracing::warn!(error_code = "KIN-PUB-004", name = %name, total = %total, "PublishHeartbeat: all DHT puts failed");
                    let _ = responder.send(Err(PublishError::AllFailed { count: total }));
                }
            }
            Command::ResolveRedundant { name, responder } => {
                let keys = kinetic_core::types::derive_storage_keys(&name);

                // First check our own local store. This guarantees we can resolve our own publications
                // even in offline mode (0 peers) or before the DHT is fully bootstrapped.
                for key_bytes in &keys {
                    let k = kad::RecordKey::new(key_bytes);
                    if let Some(record) = self.swarm.behaviour_mut().kademlia.store_mut().get(&k) {
                        tracing::info!("Resolved {} locally from own store", name);
                        let _ = responder.send(Ok(record.value.clone()));
                        return;
                    }
                }

                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    let name_clean = name.trim_end_matches('.').to_string();
                    tracing::warn!(
                        error_code = "KIN-RES-001",
                        name = %name_clean,
                        "Resolution failed: node is offline (0 peers)"
                    );
                    let _ = responder.send(Err(ResolutionError::Offline));
                    return;
                }

                let keys = kinetic_core::types::derive_storage_keys(&name);

                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name.insert(query_id, name.clone());
                    expected += 1;
                }

                self.pending_gets.insert(
                    name.clone(),
                    PendingGet {
                        responder,
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
                let info = self.swarm.network_info();
                if info.num_peers() == 0 {
                    tracing::warn!("Offline mode: Failing fast for VerifyQuorum (0 peers)");
                    let _ = responder.send(Ok(0));
                    return;
                }

                let keys = kinetic_core::types::derive_storage_keys(&name);
                let mut expected = 0;
                for key_bytes in keys {
                    let record_key = kad::RecordKey::new(&key_bytes);
                    let query_id = self.swarm.behaviour_mut().kademlia.get_record(record_key);
                    self.query_id_to_name
                        .insert(query_id, format!("quorum_{}", name));
                    expected += 1;
                }

                self.pending_quorums.insert(
                    name.clone(),
                    PendingQuorum {
                        responder,
                        expected_responses: expected,
                        target_payload: payload,
                        match_count: 0,
                    },
                );
            }
            Command::SendProxyRequest {
                peer,
                request,
                responder,
            } => {
                let req_id = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_request(&peer, request);
                self.pending_proxy_requests.insert(req_id, responder);
            }
            Command::SendProxyResponse { channel, response } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .proxy
                    .send_response(channel, response);
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
                    "connected_peers": peers,
                    "listen_addrs": self.swarm.listeners().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "nat_status": self.nat_status,
                })));
            }
            Command::SubscribeGossip { topic, responder } => {
                let ident_topic = libp2p::gossipsub::IdentTopic::new(topic);
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
                let ident_topic = libp2p::gossipsub::IdentTopic::new(topic);
                let res = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(ident_topic, payload)
                    .map(|_| ())
                    .map_err(|e| NetworkClientError::GossipSubError(e.to_string()));
                let _ = responder.send(res);
            }
        }
    }
}
