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
use clap::{Parser, Subcommand};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;
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

#[derive(Parser)]
#[command(name = "kinetic-node", version, about = "Kinetic Infrastructure Node")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the node as a system service
    Install,
    /// Uninstall the node system service
    Uninstall,
    /// Start the node (foreground)
    Start,
    /// Start the node service (background)
    StartService,
    /// Stop the node service (background)
    StopService,
}

fn install_service() -> Result<()> {
    println!("Installing Kinetic Node service...");
    let label: ServiceLabel = "com.kinetic.node".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["start"
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse start"))?],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-node start-service' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.node".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.node".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.node".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install) => {
            install_service()?;
        }
        Some(Commands::Uninstall) => {
            uninstall_service()?;
        }
        Some(Commands::StartService) => {
            start_background_service()?;
        }
        Some(Commands::StopService) => {
            stop_background_service()?;
        }
        Some(Commands::Start) | None => {
            run_node().await?;
        }
    }

    Ok(())
}

async fn run_node() -> Result<()> {
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
    let key_path = kinetic_core::config::get_base_dir().join("node.key");
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
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config,
        local_key,
        storage.clone(),
        drand_pulse_rx,
        Some(incoming_tx),
        Some(gossip_tx),
    )?;

    // Subscribe to Quicknet Pulse Gossip
    let _ = network_client
        .subscribe_gossip("drand_pulse_quicknet")
        .await;
    tokio::spawn(async move {
        network_loop.run().await;
        tracing::warn!("Network loop exited");
    });
    info!("P2P Network architecture wired");

    let gossip_gov_path = gov_state_path.clone();
    let drand_client_gossip = drand_client.clone();
    let drand_pulse_tx_gossip = drand_pulse_tx.clone();
    tokio::spawn(async move {
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if topic == "kinetic_governance" {
                gossip::handle_kinetic_governance_gossip(&payload, gossip_gov_path.clone());
            } else if topic == "drand_pulse_quicknet" {
                if let Ok(pulse) = serde_json::from_slice::<DrandPulse>(&payload) {
                    if pulse.verify() {
                        if let Ok(latest) = drand_client_gossip.load_cached_pulse() {
                            if (pulse.round > latest.round || latest.is_unavailable)
                                && drand_client_gossip.cache_pulse(&pulse).is_ok()
                            {
                                let _ = drand_pulse_tx_gossip.send(pulse.round);
                            }
                        }
                    }
                }
            }
        }
    });

    // 6. Start Drand Heartbeat
    let hb_drand = drand_client.clone();
    let hb_network = network_client.clone();
    let p2p_only = config.drand.p2p_only;
    tokio::spawn(async move {
        // Quicknet produces a block every 3 seconds.
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;

            let mut should_fetch_http = !p2p_only;

            if p2p_only {
                if let Ok(latest) = hb_drand.load_cached_pulse() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let expected_round = now.saturating_sub(1691584200) / 3;

                    if expected_round > latest.round + 5 {
                        tracing::warn!(
                            "P2P Drand fallback triggered! We are behind by {} rounds.",
                            expected_round.saturating_sub(latest.round)
                        );
                        should_fetch_http = true;
                    }
                } else {
                    should_fetch_http = true;
                }
            }

            if should_fetch_http {
                if let Ok(pulse) = hb_drand.fetch_latest().await {
                    if !pulse.is_unavailable && !pulse.is_from_cache {
                        let _ = drand_pulse_tx.send(pulse.round);
                        // Broadcast to P2P network if we are fetching HTTP
                        if !p2p_only {
                            if let Ok(payload) = serde_json::to_vec(&pulse) {
                                let _ = hb_network
                                    .broadcast_gossip("drand_pulse_quicknet", payload)
                                    .await;
                            }
                        }
                    }
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
