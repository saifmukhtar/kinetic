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
/// Configuration for the host proxy backend.
pub mod config;
/// Drand epoch manager and dynamic routing publisher.
pub mod epoch;
/// P2P Gossipsub network handlers.
pub mod gossip;
/// Host identity key management.
pub mod host_key;
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
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

use kinetic_core::config::KineticConfig;
use kinetic_core::drand::{DrandClient, RawKyn};
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::KineticStorage;

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
    /// Configure the backend proxy port interactively
    Port { port: Option<u16> },
    /// Print the static Host PeerID for DNS configuration
    Id,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install) => service::install_service()?,
        Some(Commands::Uninstall) => service::uninstall_service()?,
        Some(Commands::Start) => service::start_background_service()?,
        Some(Commands::Stop) => service::stop_background_service()?,
        Some(Commands::Port { port }) => configure_port(*port).await?,
        Some(Commands::Id) => {
            let key_path = kinetic_core::config::get_base_dir().join("host.key");
            let host_key = host_key::load_or_generate_host_key(&key_path);
            let host_peer_id = libp2p::PeerId::from_public_key(&host_key.public());
            println!("============================================================");
            println!("Your Static Host PeerID: {}", host_peer_id);
            println!("(Paste this PeerID into your .kin DNS records)");
            println!("============================================================");
        }
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
        tracing::error!(
            "Please generate and configure production keys in kinetic-core/src/constants.rs. Error: {:?}",
            e
        );
        std::process::exit(1);
    }

    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let storage_path = kinetic_core::config::get_base_dir().join("host_db");
    let storage = Arc::new(KineticStorage::new(
        storage_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid storage path"))?,
    )?);
    info!("Storage engine initialized at {:?}", storage_path);

    // 3. Initialize Drand client for PoW validation of ephemeral clients
    let drand_client = Arc::new(DrandClient::new(Some(storage.clone())));

    let initial_kyn = match drand_client.fetch_latest().await {
        Ok(kyn) => {
            info!("Drand beacon connected — kyn #{}", kyn.kyn);
            kyn
        }
        Err(e) => {
            warn!("Drand beacon unavailable on startup: {}", e);
            RawKyn::unavailable()
        }
    };

    let initial_kyn = initial_kyn.kyn;
    let (kyn_tx, kyn_rx) = watch::channel(initial_kyn);

    // 4. Load Static Network Identity (The Permanent Host Key)
    let key_path = kinetic_core::config::get_base_dir().join("host.key");
    let host_key = host_key::load_or_generate_host_key(&key_path);
    let host_peer_id = libp2p::PeerId::from_public_key(&host_key.public());
    info!("Infrastructure Node static Host Identity: {}", host_peer_id);

    // 4.5. Mine the Epoch-Bound Ephemeral PoW Key
    info!("Mining PoW S/Kademlia identity for current epoch...");
    let local_key = tokio::task::spawn_blocking(move || {
        kinetic_network::pow::mine_sybil_keypair(
            initial_kyn,
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

    let p2p_port = std::env::var(kinetic_core::constants::ENV_HOST_P2P_PORT)
        .unwrap_or_else(|_| config.network.host_port.to_string())
        .parse::<u16>()
        .unwrap_or(config.network.host_port);

    let network_config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addrs: vec![
            format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse().unwrap(),
            format!("/ip6/::/tcp/{}", p2p_port).parse().unwrap(),
        ],
        quic_listen_addrs: vec![
            format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port)
                .parse()
                .unwrap(),
            format!("/ip6/::/udp/{}/quic-v1", p2p_port).parse().unwrap(),
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
        enable_relay_server: false,
        enable_upnp: false,
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
            .map_err(|e| anyhow::anyhow!("Poison error: {}", e))?;
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(32);
    let (gossip_tx, gossip_rx) = tokio::sync::broadcast::channel(100);
    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
        Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());

    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config.clone(),
        local_key.clone(),
        storage.clone(),
        kyn_rx.clone(),
        Some(incoming_tx.clone()),
        Some(gossip_tx.clone()),
        vdf_engine.clone(),
    )?;

    let network_loop_handle = Arc::new(tokio::sync::Mutex::new(tokio::spawn(async move {
        network_loop.run().await;
    })));
    info!("P2P Network architecture wired");

    kinetic_network::client::telemetry::start_telemetry_service(
        network_client.clone(),
        drand_client.clone(),
        config.clone(),
        kinetic_types::network::NodeType::Host,
    );

    tokio::spawn(gossip::start_gossip_listener(
        gossip_rx,
        gov_state_path.clone(),
    ));

    let backend_port = std::env::var(kinetic_core::constants::ENV_HOST_BACKEND_PORT)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(80);

    tokio::spawn(proxy::handle_incoming_proxy_requests(
        network_client.clone(),
        incoming_rx,
    ));
    info!(
        "Proxy handler started. Proxying P2P traffic to local port {}",
        backend_port
    );

    let local_peer_id_str = Arc::new(std::sync::RwLock::new(local_peer_id.to_string()));

    tokio::spawn(epoch::start_dynamic_routing_publisher(
        host_key.clone(),
        local_peer_id_str.clone(),
        host_peer_id.to_string(),
        network_client.clone(),
        kyn_rx.clone(),
    ));

    tokio::spawn(epoch::start_drand_heartbeat(
        drand_client.clone(),
        kyn_tx,
        local_peer_id,
        local_peer_id_str.clone(),
        network_loop_handle.clone(),
        network_client.clone(),
        kyn_rx.clone(),
        network_config.clone(),
        storage.clone(),
        incoming_tx.clone(),
        gossip_tx.clone(),
        vdf_engine.clone(),
    ));

    // 7. Start Health-check API
    let bind_ip = config
        .daemon
        .bind_ip
        .parse::<std::net::IpAddr>()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    api::start_health_api(host_peer_id, bind_ip).await?;

    Ok(())
}

async fn configure_port(arg_port: Option<u16>) -> Result<()> {
    let port = if let Some(p) = arg_port {
        p
    } else {
        println!("What port is your web server running on? [80]");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if input.is_empty() {
            80
        } else {
            input.parse().unwrap_or(80)
        }
    };

    println!("Checking if anything is running on localhost:{}...", port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    match client
        .get(format!("http://127.0.0.1:{}", port))
        .send()
        .await
    {
        Ok(_) => {
            println!(
                "[SUCCESS] Detected a running web server on port {}. Traffic will be routed here.",
                port
            );
        }
        Err(_) => {
            println!(
                "[WARNING] We couldn't detect anything running on port {}.",
                port
            );
            println!("If you are running a server, there might be a connection issue.");
            println!(
                "If not, please start your web server. The port has been saved successfully regardless."
            );
        }
    }

    let config_path = kinetic_core::config::get_base_dir().join("host_config.json");
    let config = crate::config::HostConfig {
        backend_port: port,
        backend_host: "127.0.0.1".to_string(),
    };
    config.save(&config_path)?;
    println!("Configuration saved to {:?}", config_path);

    Ok(())
}
