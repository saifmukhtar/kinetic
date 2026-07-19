use libp2p::{kad, PeerId, Swarm};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::Command;

use crate::event_loop::utils::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueryType {
    Get(std::sync::Arc<str>),
    Quorum(std::sync::Arc<str>),
    Put(std::sync::Arc<str>),
}

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
}

/// The central event loop that drives the libp2p swarm and handles networking events.
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
    pub(crate) gossip_tx: Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
    pub(crate) bad_vdf_counts: FxHashMap<PeerId, (u32, web_time::Instant)>,
    pub(crate) current_drand_pulse: u64,
    pub(crate) drand_pulse_rx: watch::Receiver<u64>,
    pub(crate) bootstrap_nodes: Vec<libp2p::Multiaddr>,
    pub(crate) seed_domains: Vec<std::sync::Arc<str>>,
    pub(crate) bootstrap_peers: FxHashSet<libp2p::PeerId>,
    pub(crate) startup_time: web_time::Instant,
    pub(crate) disable_pow: bool,
    pub(crate) banned_peers: FxHashMap<libp2p::PeerId, u64>,

    pub(crate) bootstrap_connection_time: FxHashMap<PeerId, web_time::Instant>,
    pub(crate) nat_status: String,
    pub(crate) loopback_tx: Option<tokio::sync::mpsc::UnboundedSender<LoopbackCommand>>,
}

impl NetworkEventLoop {
    /// Starts the event loop. Blocks indefinitely until the command channel is closed.
    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");

        let (loopback_tx, mut loopback_rx) = tokio::sync::mpsc::unbounded_channel();
        self.loopback_tx = Some(loopback_tx);

        #[cfg(not(target_arch = "wasm32"))]
        for domain in &self.seed_domains {
            let host_port = format!("{}:6070", domain);
            if let Ok(mut addrs) = tokio::net::lookup_host(host_port).await {
                for addr in addrs.by_ref() {
                    let ip = addr.ip();
                    let multiaddr = libp2p::Multiaddr::empty()
                        .with(match ip {
                            std::net::IpAddr::V4(v4) => libp2p::multiaddr::Protocol::Ip4(v4),
                            std::net::IpAddr::V6(v6) => libp2p::multiaddr::Protocol::Ip6(v6),
                        })
                        .with(libp2p::multiaddr::Protocol::Tcp(addr.port()));
                    if self.swarm.dial(multiaddr.clone()).is_ok() {
                        info!("Dialing resolved DNS seed node: {}", multiaddr);
                    }
                }
            } else {
                tracing::warn!("Failed to resolve DNS seed domain: {}", domain);
            }
        }

        let initial_prune_jitter = (web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            % 60) as u64;
        let mut prune_delay =
            futures_timer::Delay::new(web_time::Duration::from_secs(3600 + initial_prune_jitter));
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
                    prune_delay = futures_timer::Delay::new(web_time::Duration::from_secs(3600 + jitter));
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
                        let entry = self.bad_vdf_counts.entry(source).or_insert((0, now));
                        if now.duration_since(entry.1) > web_time::Duration::from_secs(60) {
                            *entry = (1, now);
                        } else {
                            entry.0 += 1;
                        }

                        if entry.0 >= 3 {
                            tracing::warn!("Peer {} sent 3 invalid records within 60s — disconnecting and banning", source);
                            let _ = self.swarm.disconnect_peer_id(source);
                            let expire_time = web_time::SystemTime::now()
                                .duration_since(web_time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                + 86400;
                            // Enforce LRU bounding on banned peers if over 10_000
                            if self.banned_peers.len() >= 10_000 {
                                // Find the oldest expiry
                                if let Some(&oldest_peer) = self
                                    .banned_peers
                                    .iter()
                                    .min_by_key(|&(_, &exp)| exp)
                                    .map(|(p, _)| p)
                                {
                                    self.banned_peers.remove(&oldest_peer);
                                }
                            }
                            self.banned_peers.insert(source, expire_time);
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
                    tracing::debug!("Peer {} failed S/Kademlia PoW for epoch, disconnecting them to prevent connection slot exhaustion", peer_id);
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                } else if !valid && is_bootstrap {
                    tracing::debug!(
                        "Bootstrap peer {} failed PoW — permitted initially",
                        peer_id
                    );
                }
            }
        }
    }
}
