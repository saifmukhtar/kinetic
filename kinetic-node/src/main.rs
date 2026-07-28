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
    Run,
    /// Start the node service (background)
    Start,
    /// Stop the node service (background)
    Stop,
}

fn install_service() -> Result<()> {
    println!("Installing Kinetic Node service...");
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["run".into()],
        contents: None,
        username: std::env::var("SUDO_USER")
            .ok()
            .or_else(|| Some("nobody".to_string())),
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-node start' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
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
        Some(Commands::Start) => {
            start_background_service()?;
        }
        Some(Commands::Stop) => {
            stop_background_service()?;
        }
        Some(Commands::Run) | None => {
            run_node().await?;
        }
    }

    Ok(())
}

/// Executes the main logic for the Kinetic Infrastructure Node.
///
/// Unlike the daemon, the infrastructure node does not run the HTTP proxy, PAC server, or local DNS.
/// Instead, it focuses on:
/// - Maintaining a stable Kademlia DHT peer identity (using a static key on disk).
/// - Providing high-availability routing for the `.kin` namespace.
/// - Relaying and persisting governance state updates.
///
/// # Errors
///
/// Returns an `anyhow::Error` if fundamental networking, storage, or key generation fails.
async fn run_node() -> Result<()> {
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
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let default_storage = kinetic_core::config::get_base_dir().join("node_db");
    let storage_path = config
        .daemon
        .storage_dir
        .to_str()
        .unwrap_or(default_storage.to_str().unwrap_or("./kinetic_db"));
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
        listen_addrs: vec![
            format!("/ip4/0.0.0.0/tcp/{}", config.network.node_port)
                .parse()
                .unwrap(),
            format!("/ip6/::/tcp/{}", config.network.node_port)
                .parse()
                .unwrap(),
        ],
        quic_listen_addrs: vec![
            format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.network.node_quic_port)
                .parse()
                .unwrap(),
            format!("/ip6/::/udp/{}/quic-v1", config.network.node_quic_port)
                .parse()
                .unwrap(),
        ],
        bootstrap_nodes: config
            .network
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        seed_domain: config
            .network
            .seed_domain
            .clone()
            .into_iter()
            .map(Into::into)
            .collect(),
        enable_mdns: false,
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
            .unwrap_or_else(|e| e.into_inner());
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (gossip_tx, mut gossip_rx) = tokio::sync::broadcast::channel(100);
    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
        Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config,
        local_key,
        storage.clone(),
        drand_pulse_rx,
        None,
        Some(gossip_tx),
        vdf_engine.clone(),
    )?;

    // Subscribe to Quicknet Pulse Gossip
    let _ = network_client
        .subscribe_gossip(kinetic_core::constants::GOSSIP_TOPIC_DRAND)
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
        loop {
            let (topic, payload) = match gossip_rx.recv().await {
                Ok(msg) => msg,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if topic == kinetic_core::constants::GOSSIP_TOPIC_GOVERNANCE {
                gossip::handle_kinetic_governance_gossip(&payload, gossip_gov_path.clone());
            } else if topic == kinetic_core::constants::GOSSIP_TOPIC_DRAND {
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
                    let estimated_round = (now - kinetic_core::constants::DRAND_GENESIS_TIME)
                        / kinetic_core::constants::DRAND_PERIOD;

                    if estimated_round > latest.round + 5 {
                        tracing::warn!(
                            "P2P Drand fallback triggered! We are behind by {} rounds.",
                            estimated_round.saturating_sub(latest.round)
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
                                    .broadcast_gossip(
                                        kinetic_core::constants::GOSSIP_TOPIC_DRAND,
                                        payload,
                                    )
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
    let bind_ip = config
        .daemon
        .bind_ip
        .parse::<std::net::IpAddr>()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let addr = std::net::SocketAddr::new(bind_ip, api_port);
    info!(
        "Node Health-check API listening on http://{}:{}",
        bind_ip, api_port
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(kinetic_core::shutdown::shutdown_signal())
        .await?;

    Ok(())
}
