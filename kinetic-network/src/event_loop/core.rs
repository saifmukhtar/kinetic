//! Core `NetworkEventLoop` definition and main event loop execution thread.
//!
//! This module houses the primary async reactor for all libp2p P2P networking in Kinetic.
//! It maintains the Kademlia DHT, Gossipsub mesh, AutoNAT traversals, and background
//! verification workers for inbound blocks.

use libp2p::{kad, PeerId, Swarm};
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
    ConnectionPoWVerified {
        peer_id: libp2p::PeerId,
        valid: bool,
        is_bootstrap: bool,
    },
    DialResolvedSeed(libp2p::Multiaddr),
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
    pub(crate) query_id_to_name: FxHashMap<kad::QueryId, QueryType>,
    pub(crate) pending_proxy_requests: FxHashMap<
        libp2p::request_response::OutboundRequestId,
        oneshot::Sender<
            std::result::Result<crate::client::ProxyResponse, crate::client::ProxyError>,
        >,
    >,
    pub(crate) incoming_proxy_tx: Option<
        mpsc::Sender<(
            crate::client::ProxyRequest,
            libp2p::request_response::ResponseChannel<crate::client::ProxyResponse>,
        )>,
    >,
    pub(crate) gossip_tx: Option<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
    pub(crate) bad_vdf_counts: lru::LruCache<PeerId, (u32, web_time::Instant)>,
    pub(crate) current_drand_pulse: u64,
    pub(crate) drand_pulse_rx: watch::Receiver<u64>,
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
    pub(crate) light_clients: FxHashSet<libp2p::PeerId>,
}

impl NetworkEventLoop {
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
                tracing::warn!(
                    "Failed to resolve DNS TXT seed domain or found no multiaddrs: {}",
                    domain
                );
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
                }
                _ = &mut redial_delay => {
                    let jitter = (web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).unwrap_or_default().as_millis() % 5) as u64;
                    redial_delay = futures_timer::Delay::new(web_time::Duration::from_secs(15 + jitter));
                    let info = self.swarm.network_info();
                    let num_peers = info.num_peers();
                    if num_peers == 0 {
                        tracing::warn!("0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...");
                        for addr in &self.bootstrap_nodes {
                            let _ = self.swarm.dial(addr.clone());
                        }

                        #[cfg(not(target_arch = "wasm32"))]
                        if let Some(tx) = &self.loopback_tx {
                            let tx_clone = tx.clone();
                            let domains = self.seed_domain.clone();
                            tokio::spawn(async move {
                                for domain in &domains {
                                    let addrs = crate::dns_tree::resolve_dns_tree(domain.as_ref()).await;
                                    if addrs.is_empty() {
                                        tracing::warn!("Failed to resolve DNS TXT seed domain or found no multiaddrs: {}", domain);
                                    }
                                    for multiaddr in addrs {
                                        let _ = tx_clone.send(LoopbackCommand::DialResolvedSeed(multiaddr));
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
                Ok(()) = self.drand_pulse_rx.changed() => {
                    let new_round = *self.drand_pulse_rx.borrow();
                    if new_round > self.current_drand_pulse {
                        tracing::debug!("NetworkEventLoop: drand pulse updated {} -> {}", self.current_drand_pulse, new_round);
                        self.current_drand_pulse = new_round;
                        self.swarm.behaviour_mut().kademlia.store_mut().current_drand_round = new_round;
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
                if let Err(e) = verdict {
                    if e.severity() == kinetic_core::error::Severity::Error {
                        let now = web_time::Instant::now();
                        let (count, last_time) = self
                            .bad_vdf_counts
                            .get(&source)
                            .copied()
                            .unwrap_or((0, now));
                        let new_val =
                            if now.duration_since(last_time) > web_time::Duration::from_secs(60) {
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
                        }
                    }
                } else {
                    tracing::debug!(
                        "Offloaded DHT record verification succeeded for peer {}",
                        source
                    );
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .put_verified_record(record);
                }
            }
            LoopbackCommand::ConnectionPoWVerified {
                peer_id,
                valid,
                is_bootstrap,
            } => {
                if !valid && !is_bootstrap {
                    if self.light_clients.len() >= 50 {
                        tracing::warn!("Light Client limit reached. Peer {} failed PoW, disconnecting them to prevent connection slot exhaustion", peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    } else {
                        tracing::debug!("Peer {} failed PoW, classifying as Light Client.", peer_id);
                        self.light_clients.insert(peer_id);
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
        }
    }
}
