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
mod node_key;

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
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

use kinetic_core::config::KineticConfig;
use kinetic_core::drand::{DrandClient, RawKyn};
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::KineticStorage;

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
    /// Start the node (foregkyn)
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
        .map_err(|_| anyhow::Error::from(kinetic_core::error::SystemError::ServiceManagerError("Failed to detect native service manager".into())))?;
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
        .map_err(|_| anyhow::Error::from(kinetic_core::error::SystemError::ServiceManagerError("Failed to detect native service manager".into())))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::Error::from(kinetic_core::error::SystemError::ServiceManagerError("Failed to detect native service manager".into())))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-node", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::Error::from(kinetic_core::error::SystemError::ServiceManagerError("Failed to detect native service manager".into())))?;
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
        tracing::error!(
            error_code = e.code(),
            "FATAL: Network cannot boot with a bricked governance plane: {}",
            e
        );
        std::process::exit(1);
    }

    let config = KineticConfig::load_ctx(kinetic_core::config::ConfigContext::Node);

    // 1. Initialize structured tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
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
    let storage = Arc::new(KineticStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    // 3. Initialize Drand client for PoW validation of ephemeral clients
    let drand_client = Arc::new(DrandClient::new(Some(storage.clone())));

    let initial_kyn = match drand_client.fetch_latest().await {
        Ok(kyn) => {
            info!("Drand beacon connected — kyn #{}", kyn.kyn);
            kyn
        }
        Err(e) => {
            let err = kinetic_core::error::DrandError::UnavailableOnStartup(e.to_string());
            warn!(error_code = err.code(), "{}", err);
            RawKyn::unavailable()
        }
    };

    let initial_kyn = initial_kyn.kyn;
    let (kyn_tx, kyn_rx) = watch::channel(initial_kyn);

    // 4. Load Static Network Identity
    let key_path = kinetic_core::config::get_base_dir().join("node.key");
    let local_key = node_key::load_or_generate_key(&key_path);
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
        enable_mdns: config.network.enable_mdns,
        enable_upnp: config.network.enable_upnp,
        enable_relay_server: config.network.enable_relay_server,
        initial_kyn,
        external_address: config
            .network
            .external_address
            .as_ref()
            .and_then(|a| a.parse().ok()),
        max_reveals_per_hour: 100,
        lru_cache_size: std::num::NonZeroUsize::new(kinetic_core::constants::LIMITS_LRU_CACHE_SIZE)
            .unwrap_or(std::num::NonZeroUsize::new(10_000).unwrap()),
        disable_pow: false,
        test_mode: false,
        disable_storage_sync: false,
    };

    let base_config_dir = kinetic_core::config::get_base_dir();
    std::fs::create_dir_all(&base_config_dir)?;

    let gov_state_path = std::env::var(kinetic_core::constants::ENV_GOVERNANCE_PATH)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| base_config_dir.join("governance.db"));
    let gov_state_path = std::sync::Arc::new(gov_state_path);
    {
        let mut gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (gossip_tx, mut gossip_rx) = tokio::sync::broadcast::channel(100);
    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
        Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config,
        local_key,
        storage.clone(),
        kyn_rx,
        None,
        Some(gossip_tx),
        vdf_engine.clone(),
    )?;

    tokio::spawn(async move {
        network_loop.run().await;
        tracing::warn!(
            error = ?kinetic_core::error::SystemError::ServerCrashed("Network loop exited".into()),
            "Network loop exited"
        );
    });

    // Subscribe to Global Gossip
    let _ = network_client
        .subscribe_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL)
        .await;
    info!("P2P Network architecture wired");

    let gossip_gov_path = gov_state_path.clone();
    let drand_client_gossip = drand_client.clone();
    let kyn_tx_gossip = kyn_tx.clone();
    let gossip_storage = storage.clone();

    kinetic_network::client::telemetry::start_telemetry_service(
        network_client.clone(),
        drand_client.clone(),
        config.clone(),
        kinetic_types::network::NodeType::Node,
    );

    tokio::spawn(async move {
        loop {
            let (topic, payload, _, _) = match gossip_rx.recv().await {
                Ok(msg) => msg,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if topic == kinetic_core::constants::GOSSIP_TOPIC_GLOBAL {
                if payload.is_empty() {
                    continue;
                }
                let opcode = payload[0];
                let actual_payload = &payload[1..];

                if opcode == kinetic_types::network::NetworkOpcode::Governance as u8 {
                    use kinetic_core::types::clock::KynNetworkExt;
                    let current_kyn = match drand_client_gossip.fetch_latest().await {
                        Ok(kyn) => kyn.kyn,
                        Err(_) => kinetic_core::types::Kyn::now_local().0,
                    };
                    gossip::handle_governance_gossip(
                        actual_payload,
                        gossip_gov_path.clone(),
                        Some(gossip_storage.clone()),
                        current_kyn,
                    );
                } else if opcode == kinetic_types::network::NetworkOpcode::Drand as u8 {
                    if let Ok(kyn) = serde_json::from_slice::<RawKyn>(actual_payload) {
                        if kyn.verify() {
                            let latest_kyn = match drand_client_gossip.load_cached_kyn() {
                                Ok(latest) => {
                                    if latest.is_unavailable { 0 } else { latest.kyn }
                                },
                                Err(e) => {
                                    if !matches!(e, kinetic_core::error::DrandError::NoCachedKyn) {
                                        tracing::error!(error_code = e.code(), "Failed to load cached kyn in node gossip handler: {}", e);
                                    }
                                    0
                                }
                            };

                            if kyn.kyn > latest_kyn {
                                if let Err(e) = drand_client_gossip.cache_kyn(&kyn) {
                                    tracing::error!(error_code = e.code(), "Failed to cache drand kyn in node gossip handler: {}", e);
                                }
                                let _ = kyn_tx_gossip.send(kyn.kyn);
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
                if let Ok(latest) = hb_drand.load_cached_kyn() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let estimated_kyn = now
                        .saturating_sub(kinetic_core::constants::DRAND_GENESIS_TIME)
                        / kinetic_core::constants::DRAND_PERIOD;

                    if estimated_kyn > latest.kyn + 5 {
                        let err = kinetic_core::error::DrandError::P2pFallbackTriggered { behind: estimated_kyn.saturating_sub(latest.kyn) };
                        tracing::warn!(error_code = err.code(), "{}", err);
                        should_fetch_http = true;
                    }
                } else {
                    should_fetch_http = true;
                }
            }

            if should_fetch_http
                && let Ok(kyn) = hb_drand.fetch_latest().await
                && !kyn.is_unavailable
                && !kyn.is_from_cache
            {
                let _ = kyn_tx.send(kyn.kyn);
                // Broadcast to P2P network if we are fetching HTTP
                if !p2p_only && let Ok(payload) = serde_json::to_vec(&kyn) {
                    let mut envelope = vec![kinetic_types::network::NetworkOpcode::Drand as u8];
                    envelope.extend(payload);
                    let _ = hb_network
                        .broadcast_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL, envelope)
                        .await;
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
