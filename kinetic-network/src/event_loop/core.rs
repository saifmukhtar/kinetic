use libp2p::{kad, PeerId, Swarm};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::info;

use crate::behavior::KineticBehavior;
use crate::client::Command;

use crate::event_loop::utils::*;

/// The central event loop that drives the libp2p swarm and handles networking events.
pub struct NetworkEventLoop {
    pub(crate) swarm: Swarm<KineticBehavior>,
    pub(crate) command_receiver: mpsc::Receiver<Command>,
    pub(crate) pending_gets: HashMap<String, PendingGet>,
    pub(crate) pending_quorums: HashMap<String, PendingQuorum>,
    pub(crate) query_id_to_name: HashMap<kad::QueryId, String>,
    pub(crate) pending_proxy_requests: HashMap<
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
    pub(crate) bad_vdf_counts: HashMap<PeerId, (u32, std::time::Instant)>,
    pub(crate) current_drand_pulse: u64,
    pub(crate) drand_pulse_rx: watch::Receiver<u64>,
    pub(crate) bootstrap_nodes: Vec<String>,
    pub(crate) bootstrap_peers: std::collections::HashSet<libp2p::PeerId>,
    pub(crate) startup_time: std::time::Instant,
    pub(crate) banned_peers: std::collections::HashSet<libp2p::PeerId>,
    pub(crate) commitment_miss_counts: HashMap<PeerId, u32>,
    pub(crate) bootstrap_connection_time: HashMap<PeerId, std::time::Instant>,
}

impl NetworkEventLoop {
    /// Starts the event loop. Blocks indefinitely until the command channel is closed.
    pub async fn run(mut self) {
        info!("Starting Kinetic P2P event loop");

        let mut prune_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        prune_interval.tick().await; // skip first tick

        let mut redial_interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        redial_interval.tick().await; // skip first tick

        loop {
            tokio::select! {
                _ = prune_interval.tick() => {
                    tracing::info!("Running periodic Sled pruning...");
                    self.swarm.behaviour_mut().kademlia.store_mut().prune();
                }
                _ = redial_interval.tick() => {
                    let info = self.swarm.network_info();
                    let num_peers = info.num_peers();
                    if num_peers == 0 {
                        tracing::warn!("0 peers detected! Aggressively redialing bootstrap nodes to rejoin mesh...");
                        for peer in &self.bootstrap_peers {
                            let _ = self.swarm.dial(*peer);
                        }
                    } else if num_peers > 20 {
                        // Case 184: Disconnect from bootstrap nodes to reduce load once safely in the mesh
                        let mut disconnected = false;
                        for peer in &self.bootstrap_peers {
                            // disconnect_peer_id returns an error if the peer is not connected, which is fine
                            if self.swarm.disconnect_peer_id(*peer).is_ok() {
                                disconnected = true;
                            }
                        }
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
                }
            }
        }
    }
}
