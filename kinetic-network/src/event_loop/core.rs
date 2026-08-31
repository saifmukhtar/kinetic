//! Core `NetworkEventLoop` definition and main event loop execution thread.
//!
//! This module houses the primary async reactor for all libp2p P2P networking in Kinetic.
//! It maintains the Kademlia DHT, Gossipsub mesh, AutoNAT traversals, and background
//! verification workers for inbound blocks.

use libp2p::{PeerId, Swarm, kad};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::Command;

use crate::event_loop::utils::*;

/// Internal identifier mapping a Kademlia query ID back to the requested domain name and intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueryType {
    Get(std::sync::Arc<str>),
    Quorum(std::sync::Arc<str>),
    Put(std::sync::Arc<str>),
}

/// Internal loopback messages sent from spawned blocking tasks back to the main event loop thread.
pub(crate) enum LoopbackCommand {
    CommitVerifiedRecord {
        source: libp2p::PeerId,
        record: libp2p::kad::Record,
        verdict: Result<(), crate::error::KineticStoreError>,
    },
    CommitGossipValidation {
        message_id: libp2p::gossipsub::MessageId,
        source: libp2p::PeerId,
        is_valid: Option<bool>,
    },
    ConnectionPoWVerified {
        peer_id: libp2p::PeerId,
        valid: bool,
        is_bootstrap: bool,
        remote_addr: libp2p::Multiaddr,
    },
    DialResolvedSeed(libp2p::Multiaddr),
    CdnResolutionVerified {
        domain: std::sync::Arc<str>,
        record_bytes: Vec<u8>,
        peer: libp2p::PeerId,
    },
}

/// The central event loop that drives the libp2p swarm and handles networking events.
///
/// This struct holds the state of all ongoing network operations, handles inbound RPCs,
/// processes DHT records, maintains connection limits, and enforces Proof-of-Work checks
/// against connecting peers to thwart Sybil attacks.
pub struct NetworkEventLoop {
    pub(crate) swarm: Swarm<KineticBehavior>,
    pub(crate) command_receiver: mpsc::Receiver<Command>,
    pub(crate) pending_gets: FxHashMap<std::sync::Arc<str>, PendingGet>,
    pub(crate) pending_quorums: FxHashMap<std::sync::Arc<str>, PendingQuorum>,
    pub(crate) pending_puts: FxHashMap<std::sync::Arc<str>, PendingPut>,
    pub(crate) pending_reveals: FxHashMap<kad::QueryId, (libp2p::PeerId, kad::Record)>,
    pub(crate) query_id_to_name: FxHashMap<kad::QueryId, QueryType>,
    pub(crate) pending_proxy_requests: FxHashMap<
        libp2p::request_response::OutboundRequestId,
        oneshot::Sender<
            std::result::Result<crate::client::ProxyResponse, crate::client::ProxyError>,
        >,
    >,
    pub(crate) pending_cdn_requests: FxHashMap<
        libp2p::request_response::OutboundRequestId,
        std::sync::Arc<str>, // The domain name being requested
    >,
    pub(crate) incoming_proxy_tx: Option<
        mpsc::Sender<(
            crate::client::ProxyRequest,
            libp2p::request_response::ResponseChannel<crate::client::ProxyResponse>,
        )>,
    >,
    pub(crate) gossip_tx: Option<
        tokio::sync::broadcast::Sender<(
            String,
            Vec<u8>,
            libp2p::gossipsub::MessageId,
            libp2p::PeerId,
        )>,
    >,
    pub(crate) bad_vdf_counts: lru::LruCache<PeerId, (u32, web_time::Instant)>,
    pub(crate) current_kyn: u64,
    pub(crate) kyn_rx: watch::Receiver<u64>,
    pub(crate) bootstrap_nodes: Vec<libp2p::Multiaddr>,
    pub(crate) seed_domain: Vec<std::sync::Arc<str>>,
    pub(crate) bootstrap_peers: FxHashSet<libp2p::PeerId>,
    pub(crate) startup_time: web_time::Instant,
    pub(crate) disable_pow: bool,
    pub(crate) banned_peers: lru::LruCache<libp2p::PeerId, u64>,

    pub(crate) bootstrap_connection_time: FxHashMap<PeerId, web_time::Instant>,
    pub(crate) nat_status: String,
    pub(crate) loopback_tx: Option<tokio::sync::mpsc::UnboundedSender<LoopbackCommand>>,
    pub(crate) pow_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    /// Caps concurrent in-flight gossip verifications to prevent thread pool exhaustion from flood attacks.
    pub gossip_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    pub(crate) light_nodes: FxHashSet<libp2p::PeerId>,
    pub(crate) light_node_ips: rustc_hash::FxHashMap<String, usize>,
    pub(crate) bootstrapped: bool,
    pub(crate) proxy_cdn_usage: (usize, web_time::Instant),
}

impl NetworkEventLoop {
    /// Returns true if the Kademlia bootstrap has been triggered
    pub fn bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    /// Checks if a peer is currently banned
    pub fn is_banned(&mut self, peer_id: &libp2p::PeerId) -> bool {
        self.banned_peers.peek(peer_id).is_some()
    }

    /// Records one invalid gossip message from `source`, incrementing its strike count.
    ///
    /// If the peer accumulates 3 invalid messages within 60 seconds, it is added to
    /// `banned_peers` and should be disconnected by the caller. Extracted to be testable
    /// without a live swarm.
    pub fn ban_gossip(&mut self, source: libp2p::PeerId) {
        let now = web_time::Instant::now();
        let (count, last_time) = self
            .bad_vdf_counts
            .get(&source)
            .copied()
            .unwrap_or((0, now));
        let new_val = if now.duration_since(last_time) > web_time::Duration::from_secs(60) {
            (1, now)
        } else {
            (count + 1, now)
        };
        self.bad_vdf_counts.put(source, new_val);
        if new_val.0 >= 3 {
            let err = kinetic_core::error::P2pError::GossipSpamBan(source.to_string());
            tracing::warn!(error_code = err.code(), "{}", err);
            let expire_kyn = self.current_kyn + 28800;
            self.banned_peers.put(source, expire_kyn);
        }
    }

    /// Starts the event loop. Blocks indefinitely until the command channel is closed.
    ///
    /// The event loop continuously multiplexes between:
    /// - Periodic background tasks (e.g., pruning Sled storage, redialing bootstraps).
    /// - External commands coming from the `NetworkClient` (e.g., publish, resolve).
    /// - Loopback results from CPU-intensive cryptographic validations (e.g., VDF, PoW).
    /// - Raw network events surfaced by `libp2p::Swarm`.
    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");

        let (loopback_tx, mut loopback_rx) = tokio::sync::mpsc::unbounded_channel();
        self.loopback_tx = Some(loopback_tx);

        #[cfg(not(target_arch = "wasm32"))]
        for domain in &self.seed_domain {
            let addrs = crate::dns_tree::resolve_dns_tree(domain.as_ref()).await;
            if addrs.is_empty() {
                let err = kinetic_core::error::NrsError::SeedDomainResolutionFailed(domain.to_string());
                tracing::warn!(error_code = err.code(), "{}", err);
            }
            for multiaddr in addrs {
                if self.swarm.dial(multiaddr.clone()).is_ok() {
                    tracing::info!("Dialing resolved DNS TXT seed node: {}", multiaddr);
                }
            }
        }

        let initial_prune_jitter = (web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            % 60) as u64;
        let mut prune_delay = futures_timer::Delay::new(web_time::Duration::from_secs(
            kinetic_core::constants::TIMEOUTS_NETWORK_PRUNE_INTERVAL_SECONDS + initial_prune_jitter,
        ));
        let initial_redial_jitter = (web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            % 5) as u64;
        let mut redial_delay =
            futures_timer::Delay::new(web_time::Duration::from_secs(15 + initial_redial_jitter));

        loop {
            tokio::select! {
                _ = &mut prune_delay => {
                    let jitter = (web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).unwrap_or_default().as_millis() % 60) as u64;
                    prune_delay = futures_timer::Delay::new(web_time::Duration::from_secs(kinetic_core::constants::TIMEOUTS_NETWORK_PRUNE_INTERVAL_SECONDS + jitter));
                    tracing::info!("Running periodic Sled pruning...");
                    self.swarm.behaviour_mut().kademlia.store_mut().prune();
                    let storage = self.swarm.behaviour_mut().kademlia.store_mut().storage.clone();
                    let current_kyn = self.current_kyn;
                    crate::event_loop::utils::spawn(async move {
                        let _ = crate::event_loop::utils::spawn_blocking(move || {
                            if let Ok(iter) = storage.scan_prefix(kinetic_core::constants::DB_PREFIX_BANNED_PEER.as_bytes(), None) {
                                for (key_bytes, val_bytes) in iter {
                                    if val_bytes.len() == 8 {
                                        let expire = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0; 8]));
                                        if expire <= current_kyn {
                                            let _ = storage.delete(&key_bytes);
                                        }
                                    }
                                }
                            }
                        }).await;
                    });
                }
                _ = &mut redial_delay => {
                    let jitter = (web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).unwrap_or_default().as_millis() % 5) as u64;
                    redial_delay = futures_timer::Delay::new(web_time::Duration::from_secs(15 + jitter));
                    let info = self.swarm.network_info();
                    let num_peers = info.num_peers();
                    if num_peers == 0 {
                        let err = kinetic_core::error::P2pError::ZeroPeersDetected;
                        tracing::warn!(error_code = err.code(), "{}", err);
                        for addr in &self.bootstrap_nodes {
                            let _ = self.swarm.dial(addr.clone());
                        }

                        #[cfg(not(target_arch = "wasm32"))]
                        if let Some(tx) = &self.loopback_tx {
                            let tx_clone = tx.clone();
                            let domains = self.seed_domain.clone();
                            let disable_pow = self.disable_pow;
                            tokio::spawn(async move {
                                for domain in &domains {
                                    let addrs = crate::dns_tree::resolve_dns_tree(domain.as_ref()).await;
                                    if addrs.is_empty() {
                                        let err = kinetic_core::error::NrsError::SeedDomainResolutionFailed(domain.to_string());
                                        tracing::warn!(error_code = err.code(), "{}", err);
                                    }
                                    for multiaddr in addrs {
                                        if crate::event_loop::utils::is_routable_multiaddr(&multiaddr, disable_pow, true) {
                                            let _ = tx_clone.send(LoopbackCommand::DialResolvedSeed(multiaddr));
                                        } else {
                                            let err = kinetic_core::error::P2pError::UnroutableSeedMultiaddr(multiaddr.to_string());
                                            tracing::warn!(error_code = err.code(), "{}", err);
                                        }
                                    }
                                }
                            });
                        }
                    } else if num_peers > 20 {
                        // Case 184: Disconnect from bootstrap nodes to reduce load once safely in the mesh
                        let mut disconnected = false;
                        self.bootstrap_peers.retain(|peer| {
                            if self.swarm.disconnect_peer_id(*peer).is_ok() {
                                disconnected = true;
                                false // remove from set
                            } else {
                                true // keep in set
                            }
                        });
                        if disconnected {
                            tracing::info!("Disconnected from bootstrap nodes to reduce load (Case 184). Active mesh peers: {}", num_peers);
                        }
                    }
                }
                Ok(()) = self.kyn_rx.changed() => {
                    let new_kyn = *self.kyn_rx.borrow();
                    if new_kyn > self.current_kyn {
                        tracing::debug!("NetworkEventLoop: drand kyn updated {} -> {}", self.current_kyn, new_kyn);
                        self.current_kyn = new_kyn;
                        self.swarm.behaviour_mut().kademlia.store_mut().current_kyn = new_kyn;
                    }
                }
                event = libp2p::futures::StreamExt::select_next_some(&mut self.swarm) => self.handle_swarm_event(event).await,
                command = self.command_receiver.recv() => match command {
                    Some(c) => self.handle_command(c).await,
                    None => {
                        info!("Network client dropped, exiting loop");
                        break;
                    }
                },
                Some(cmd) = loopback_rx.recv() => {
                    self.handle_loopback(cmd).await;
                }
            }
        }
    }

    pub(crate) async fn handle_loopback(&mut self, cmd: LoopbackCommand) {
        match cmd {
            LoopbackCommand::CommitVerifiedRecord {
                source,
                record,
                verdict,
            } => {
                match verdict {
                    Err(crate::error::KineticStoreError::MissingCommitment { commit_key }) => {
                        tracing::debug!(
                            "Commitment missing locally. Querying DHT to verify reveal..."
                        );
                        let key = libp2p::kad::RecordKey::new(&commit_key);
                        let query_id = self.swarm.behaviour_mut().kademlia.get_record(key);
                        self.pending_reveals.insert(query_id, (source, record));
                        return;
                    }
                    Err(e) => {
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
                                let err = kinetic_core::error::P2pError::RecordSpamBan(source.to_string());
                                tracing::warn!(error_code = err.code(), "{}", err);
                                let _ = self.swarm.disconnect_peer_id(source);
                                let expire_kyn = self.current_kyn + 28800;
                                self.banned_peers.put(source, expire_kyn);
                            }
                        }
                    }
                    Ok(()) => {
                        tracing::debug!(
                            "Offloaded DHT record verification succeeded for peer {}",
                            source
                        );
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .store_mut()
                            .put_verified(record.clone());

                        // Advertise that we are caching this record (Edge Caching / Option 3)
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .start_providing(record.key.clone());
                    }
                }
            }
            LoopbackCommand::CommitGossipValidation {
                message_id,
                source,
                is_valid,
            } => {
                let acceptance = match is_valid {
                    Some(true) => libp2p::gossipsub::MessageAcceptance::Accept,
                    Some(false) => libp2p::gossipsub::MessageAcceptance::Reject,
                    None => libp2p::gossipsub::MessageAcceptance::Ignore,
                };

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&message_id, &source, acceptance);

                if let Some(false) = is_valid {
                    self.ban_gossip(source);
                    // Disconnect after recording — banned_peers is updated inside record_invalid_gossip.
                    if self.is_banned(&source) {
                        let _ = self.swarm.disconnect_peer_id(source);
                    }
                }
            }
            LoopbackCommand::ConnectionPoWVerified {
                peer_id,
                valid,
                is_bootstrap,
                remote_addr,
            } => {
                if !valid && !is_bootstrap {
                    let mut ip = None;
                    for protocol in remote_addr.iter() {
                        if let libp2p::multiaddr::Protocol::Ip4(ipv4) = protocol {
                            ip = Some(std::net::IpAddr::V4(ipv4));
                            break;
                        } else if let libp2p::multiaddr::Protocol::Ip6(ipv6) = protocol {
                            ip = Some(std::net::IpAddr::V6(ipv6));
                            break;
                        }
                    }

                    let identifier = if let Some(ip_addr) = ip {
                        ip_addr.to_string()
                    } else {
                        let mut stripped = remote_addr.clone();
                        if let Some(libp2p::multiaddr::Protocol::P2p(_)) = stripped.iter().last() {
                            stripped.pop();
                        }
                        stripped.to_string()
                    };

                    if self.light_nodes.len() >= 50 {
                        let err = kinetic_core::error::P2pError::LightNodePowFailureLimit(peer_id.to_string());
                        tracing::warn!(error_code = err.code(), "{}", err);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    } else {
                        let count = self.light_node_ips.entry(identifier.clone()).or_insert(0);
                        if *count >= 3 {
                            let err = kinetic_core::error::P2pError::LightNodeIdentityLimit(identifier.to_string(), peer_id.to_string());
                            tracing::warn!(error_code = err.code(), "{}", err);
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                        } else {
                            *count += 1;
                            tracing::debug!(
                                "Peer {} failed PoW, classifying as Light Node.",
                                peer_id
                            );
                            self.light_nodes.insert(peer_id);
                        }
                    }
                } else if !valid && is_bootstrap {
                    tracing::debug!(
                        "Bootstrap peer {} failed PoW — permitted initially",
                        peer_id
                    );
                }
            }
            LoopbackCommand::DialResolvedSeed(multiaddr) => {
                if self.swarm.network_info().num_peers() < 20
                    && self.swarm.dial(multiaddr.clone()).is_ok()
                {
                    tracing::info!("Dialing resolved fallback DNS seed node: {}", multiaddr);
                }
            }
            LoopbackCommand::CdnResolutionVerified {
                domain,
                record_bytes,
                peer,
            } => {
                if let Ok(record) =
                    serde_json::from_slice::<kinetic_core::types::NameRecord>(&record_bytes)
                {
                    if self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .handle_put_record(&record, true)
                        .is_ok()
                    {
                        tracing::info!(
                            "CDN Hit! Accelerated resolution of {} via {}",
                            domain,
                            peer
                        );
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
}
