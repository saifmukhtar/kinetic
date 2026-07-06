//! # kinetic-node
//!
//! The Kinetic infrastructure node binary (`kinetic-node`).
//!
//! An infrastructure node is a long-lived, always-on participant in the Kinetic
//! P2P network. It is not a user-facing daemon — it does not expose a DNS
//! resolver or an HTTP registration API. Its sole responsibilities are:
//!
//! - Maintaining a stable Kademlia DHT peer identity (static keypair on disk).
//! - Participating in record storage and routing for the `.kin` namespace.
//! - Relaying governance gossip messages across the network.
//! - Exposing a health-check HTTP API on port 16003.
//!
//! Multiple infrastructure nodes run as part of the Kinetic bootstrap
//! infrastructure. They provide the initial routing table entries that new
//! peers connect to when joining the network.

mod api;
mod gossip;
mod identity;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use kinetic_core::config::KineticConfig;
use kinetic_core::drand::{DrandClient, DrandPulse};
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;

#[tokio::main]
async fn main() -> Result<()> {
    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let storage_path = config
        .daemon
        .storage_dir
        .to_str()
        .unwrap_or("/tmp/kinetic_db");
    let storage = Arc::new(SledStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    // 3. Initialize Drand client for PoW validation of ephemeral clients
    let drand_client = Arc::new(DrandClient::new(Some(storage.clone())));

    let initial_pulse = match drand_client.fetch_latest().await {
        Ok(pulse) => {
            info!("Drand beacon connected — pulse #{}", pulse.round);
            pulse
        }
        Err(e) => {
            warn!("Drand beacon unavailable on startup: {}", e);
            DrandPulse::unavailable()
        }
    };

    let initial_drand_pulse = initial_pulse.round;
    let (drand_pulse_tx, drand_pulse_rx) = watch::channel(initial_drand_pulse);

    // 4. Load Static Network Identity
    let key_path = kinetic_core::config::get_base_dir().join("static_network_key.bin");
    let local_key = identity::load_or_generate_key(&key_path);
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());

    tracing::info!(
        "Infrastructure Node starting with Static Peer ID: {}",
        local_peer_id
    );

    // 5. Initialize P2P Network
    let network_config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.node_port),
        bootstrap_nodes: config.network.bootstrap_nodes.clone(),
        seed_domains: config.network.seed_domains.clone(),
        enable_mdns: false,
        initial_drand_pulse,
        external_address: config.network.external_address.clone(),
    };

    let base_config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic");
    std::fs::create_dir_all(&base_config_dir)?;

    let gov_state_path = std::sync::Arc::new(base_config_dir.join("governance_state.bin"));
    {
        let mut gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(32);
    let (gossip_tx, mut gossip_rx) = tokio::sync::mpsc::channel(100);
    let (_network_client, network_loop) = NetworkEventLoop::new(
        network_config,
        local_key,
        storage.clone(),
        drand_pulse_rx,
        Some(incoming_tx),
        Some(gossip_tx),
    )?;
    tokio::spawn(async move {
        network_loop.run().await;
        tracing::warn!("Network loop exited");
    });
    info!("P2P Network architecture wired");

    let gossip_gov_path = gov_state_path.clone();
    tokio::spawn(async move {
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if topic == "kinetic_governance" {
                gossip::handle_kinetic_governance_gossip(&payload, gossip_gov_path.clone());
            }
        }
    });

    // 6. Start Drand Heartbeat
    let hb_drand = drand_client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Ok(pulse) = hb_drand.fetch_latest().await {
                if !pulse.is_unavailable && !pulse.is_from_cache {
                    let _ = drand_pulse_tx.send(pulse.round);
                }
            }
        }
    });

    // 7. Start Health-check API
    let app = api::build_router(local_peer_id);
    let api_port = 16003;
    let addr = SocketAddr::from(([0, 0, 0, 0], api_port));
    info!(
        "Node Health-check API listening on http://0.0.0.0:{}",
        api_port
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
