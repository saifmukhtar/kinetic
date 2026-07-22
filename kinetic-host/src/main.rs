#![deny(missing_docs)]
//! # kinetic-host
//!
//! The Kinetic host binary (`kinetic-host`).
//!
//! A host is a `.kin` domain owner that publicly serves content or services
//! through the Kinetic network. It acts simultaneously as a full P2P node and
//! as a reverse proxy — incoming P2P proxy requests for a registered domain are
//! transparently forwarded to a backend HTTP server running on the same machine.
//!
//! ## Key responsibilities
//!
//! - **Dynamic identity**: Unlike the infrastructure node, the host uses an
//!   epoch-bound PoW keypair (via S/Kademlia) that is automatically rotated
//!   each drand beacon epoch, providing Sybil resistance.
//! - **Static host identity**: A separate, long-lived Ed25519 keypair
//!   (`host.key`) uniquely identifies this host across epochs.
//!   It is used to sign [`HostRoutingRecord`](kinetic_core::types::HostRoutingRecord)s
//!   that are published to the DHT so clients can always locate the current
//!   ephemeral peer ID.
//! - **Hot-swap network loop**: When the drand epoch advances, the host
//!   automatically aborts the old network loop, mines a new PoW keypair, and
//!   restarts the loop without any downtime.
//! - **Health API**: Exposed on port 16004.

/// Health-check REST API.
pub mod api;
/// P2P Gossipsub network handlers.
pub mod gossip;
/// Drand heartbeat and dynamic routing publisher.
pub mod heartbeat;
/// Host identity key management.
pub mod identity;
/// P2P reverse proxy logic.
pub mod proxy;
/// Background system service installer.
pub mod service;

#[cfg(test)]
mod proxy_tests;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use kinetic_core::config::KineticConfig;
use kinetic_core::drand::{DrandClient, DrandPulse};
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;

#[derive(Parser)]
#[command(name = "kinetic-host", version, about = "Kinetic Infrastructure Host")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the host as a system service
    Install,
    /// Uninstall the host system service
    Uninstall,
    /// Start the host (foreground)
    Run,
    /// Start the host service (background)
    Start,
    /// Stop the host service (background)
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install) => service::install_service()?,
        Some(Commands::Uninstall) => service::uninstall_service()?,
        Some(Commands::Start) => service::start_background_service()?,
        Some(Commands::Stop) => service::stop_background_service()?,
        Some(Commands::Run) | None => {
            run_host().await?;
        }
    }
    Ok(())
}

async fn run_host() -> Result<()> {
    if let Err(e) = kinetic_core::governance::logic::validate_keys_initialized() {
        tracing::error!("FATAL: Governance keys are not initialized (using placeholders).");
        tracing::error!(
            "The network cannot boot in production mode with a bricked governance plane."
        );
        tracing::error!("Please generate and configure production keys in kinetic-core/src/constants.rs. Error: {:?}", e);
        std::process::exit(1);
    }

    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let storage_path = kinetic_core::config::get_base_dir().join("host_db");
    let storage = Arc::new(SledStorage::new(
        storage_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid storage path"))?,
    )?);
    info!("Storage engine initialized at {:?}", storage_path);

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

    // 4. Load Static Network Identity (The Permanent Host Key)
    let key_path = kinetic_core::config::get_base_dir().join("host.key");
    let host_key = identity::load_or_generate_host_key(&key_path);
    let host_peer_id = libp2p::PeerId::from_public_key(&host_key.public());
    info!("Infrastructure Node static Host Identity: {}", host_peer_id);

    // 4.5. Mine the Epoch-Bound Ephemeral PoW Key
    info!("Mining PoW S/Kademlia identity for current epoch...");
    let local_key = tokio::task::spawn_blocking(move || {
        kinetic_network::pow::mine_sybil_keypair(
            initial_drand_pulse,
            kinetic_core::constants::POW_DIFFICULTY_BITS,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("PoW mining task failed: {}", e))?;
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());
    info!(
        "Infrastructure Node ephemeral PoW Identity: {}",
        local_peer_id
    );

    let p2p_port = std::env::var(kinetic_core::constants::ENV_KINETIC_HOST_P2P_PORT)
        .unwrap_or_else(|_| config.network.host_port.to_string())
        .parse::<u16>()
        .unwrap_or(config.network.host_port);

    let network_config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", p2p_port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse listen_addr: {}", e))?,
        quic_listen_addr: Some(format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port).parse().unwrap()),
        bootstrap_nodes: config
            .network
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        seed_domains: config
            .network
            .seed_domains
            .clone()
            .into_iter()
            .map(Into::into)
            .collect(),
        enable_mdns: config.network.enable_mdns,
        initial_drand_pulse,
        external_address: config
            .network
            .external_address
            .as_ref()
            .and_then(|a| a.parse().ok()),
        max_reveals_per_hour: 100,
        lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
        disable_pow: false,
    };

    let base_config_dir = kinetic_core::config::get_base_dir();
    std::fs::create_dir_all(&base_config_dir)?;

    let gov_state_path = std::env::var(kinetic_core::constants::ENV_KINETIC_GOVERNANCE_PATH)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| base_config_dir.join("governance.key"));
    let gov_state_path = std::sync::Arc::new(gov_state_path);
    {
        let mut gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .map_err(|e| anyhow::anyhow!("Poison error: {}", e))?;
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(32);
    let (gossip_tx, gossip_rx) = tokio::sync::mpsc::channel(100);

    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
        Arc::new(kinetic_vdf::ChiaVdfEngine::new());

    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config.clone(),
        local_key.clone(),
        storage.clone(),
        drand_pulse_rx.clone(),
        Some(incoming_tx.clone()),
        Some(gossip_tx.clone()),
        vdf_engine.clone(),
    )?;

    let network_loop_handle = Arc::new(tokio::sync::Mutex::new(tokio::spawn(async move {
        network_loop.run().await;
    })));
    info!("P2P Network architecture wired");

    tokio::spawn(gossip::start_gossip_listener(
        gossip_rx,
        gov_state_path.clone(),
    ));

    let backend_port = std::env::var(kinetic_core::constants::ENV_KINETIC_HOST_BACKEND_PORT)
        .unwrap_or_else(|_| "80".to_string())
        .parse::<u16>()
        .unwrap_or(80);
    let backend_host = std::env::var(kinetic_core::constants::ENV_KINETIC_HOST_BACKEND_HOST)
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    tokio::spawn(proxy::handle_incoming_proxy_requests(
        network_client.clone(),
        incoming_rx,
        backend_port,
        backend_host,
    ));
    info!(
        "Proxy handler started. Proxying P2P traffic to local port {}",
        backend_port
    );

    // 6. Start Drand Heartbeat & Dynamic Routing Publisher
    let local_peer_id_str = Arc::new(std::sync::RwLock::new(local_peer_id.to_string()));

    tokio::spawn(heartbeat::start_dynamic_routing_publisher(
        host_key.clone(),
        local_peer_id_str.clone(),
        host_peer_id.to_string(),
        network_client.clone(),
    ));

    tokio::spawn(heartbeat::start_drand_heartbeat(
        drand_client.clone(),
        drand_pulse_tx,
        local_peer_id,
        local_peer_id_str.clone(),
        network_loop_handle.clone(),
        network_client.clone(),
        drand_pulse_rx.clone(),
        network_config.clone(),
        storage.clone(),
        incoming_tx.clone(),
        gossip_tx.clone(),
        vdf_engine.clone(),
    ));

    // 7. Start Health-check API
    api::start_health_api(host_peer_id).await?;

    Ok(())
}
