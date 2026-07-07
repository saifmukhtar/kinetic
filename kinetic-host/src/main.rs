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
//!   (`static_network_key.bin`) uniquely identifies this host across epochs.
//!   It is used to sign [`HostRoutingRecord`](kinetic_core::types::HostRoutingRecord)s
//!   that are published to the DHT so clients can always locate the current
//!   ephemeral peer ID.
//! - **Hot-swap network loop**: When the drand epoch advances, the host
//!   automatically aborts the old network loop, mines a new PoW keypair, and
//!   restarts the loop without any downtime.
//! - **Health API**: Exposed on port 16004.

pub mod proxy;

use anyhow::Result;
use axum::{routing::get, Router};
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
    Start,
    /// Start the host service (background)
    StartService,
    /// Stop the host service (background)
    StopService,
}

fn install_service() -> Result<()> {
    println!("Installing Kinetic Host service...");
    let label: ServiceLabel = "com.kinetic.host".parse()?;
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

    println!("Service installed successfully. Run 'kinetic-host start-service' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
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
            run_host().await?;
        }
    }

    Ok(())
}

async fn run_host() -> Result<()> {
    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let storage_path = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic/host_db");
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
    let key_path = kinetic_core::config::get_base_dir().join("static_network_key.bin");
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let host_key = if let Ok(bytes) = std::fs::read(&key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
            .unwrap_or_else(|_| libp2p::identity::Keypair::generate_ed25519())
    } else {
        let k = libp2p::identity::Keypair::generate_ed25519();
        if let Ok(encoded) = k.to_protobuf_encoding() {
            if let Err(e) = std::fs::write(&key_path, encoded) {
                tracing::warn!("Failed to save static infrastructure identity: {}", e);
            }
        }
        tracing::info!("Generated new static infrastructure identity");
        k
    };

    let host_peer_id = libp2p::PeerId::from_public_key(&host_key.public());
    tracing::info!("Infrastructure Node static Host Identity: {}", host_peer_id);

    // 4.5. Mine the Epoch-Bound Ephemeral PoW Key
    tracing::info!("Mining PoW S/Kademlia identity for current epoch...");
    let local_key = kinetic_network::pow::mine_sybil_keypair(
        initial_drand_pulse,
        kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
    );
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());
    tracing::info!(
        "Infrastructure Node ephemeral PoW Identity: {}",
        local_peer_id
    );

    let p2p_port = std::env::var("KINETIC_HOST_P2P_PORT")
        .unwrap_or_else(|_| config.network.host_port.to_string())
        .parse::<u16>()
        .unwrap_or(config.network.host_port);

    let network_config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", p2p_port),
        bootstrap_nodes: config.network.bootstrap_nodes.clone(),
        seed_domains: config.network.seed_domains.clone(),
        enable_mdns: config.network.enable_mdns,
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
            .map_err(|e| anyhow::anyhow!("Poison error: {}", e))?;
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(32);
    let (gossip_tx, mut gossip_rx) = tokio::sync::mpsc::channel(100);
    let current_local_key = local_key;
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config.clone(),
        current_local_key.clone(),
        storage.clone(),
        drand_pulse_rx.clone(),
        Some(incoming_tx.clone()),
        Some(gossip_tx.clone()),
    )?;

    let network_loop_handle =
        std::sync::Arc::new(tokio::sync::Mutex::new(tokio::spawn(async move {
            network_loop.run().await;
        })));
    info!("P2P Network architecture wired");

    let gossip_gov_path = gov_state_path.clone();
    tokio::spawn(async move {
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if topic == "kinetic_governance" {
                if let Ok(signed_msg) = serde_json::from_slice::<
                    kinetic_core::governance::SignedGovernanceMessage,
                >(&payload)
                {
                    let Ok(mut state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
                    else {
                        continue;
                    };
                    match kinetic_core::governance::process_governance_message(
                        &mut state,
                        &signed_msg,
                    ) {
                        Ok(Some(effect)) => {
                            tracing::info!(
                                "Governance state updated via gossip. Effect: {:?}",
                                effect
                            );
                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Ok(None) => {
                            tracing::info!(
                                "Governance state updated via gossip. No immediate effect."
                            );
                            let _ = state.save_to_disk(&gossip_gov_path);
                        }
                        Err(e) => {
                            tracing::debug!("Governance gossip message rejected: {:?}", e);
                        }
                    }
                }
            }
        }
    });

    let backend_port = std::env::var("KINETIC_HOST_BACKEND_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse::<u16>()
        .unwrap_or(80);

    let backend_host =
        std::env::var("KINETIC_HOST_BACKEND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

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
    let hb_drand = drand_client.clone();
    let publisher_client = network_client.clone();
    let publisher_host_key = host_key.clone();

    let local_peer_id_str = std::sync::Arc::new(std::sync::RwLock::new(local_peer_id.to_string()));
    let host_peer_id_str = host_peer_id.to_string();

    // Publish HostRoutingRecord periodically to ensure it stays alive and propagates
    let local_peer_id_str_for_publisher = local_peer_id_str.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let Ok(ed_key) = publisher_host_key.try_into_ed25519() else {
            tracing::error!("Host key is not ed25519");
            return;
        };
        let ed_bytes = ed_key.to_bytes();
        let Ok(dalek_kp) = ed25519_dalek::SigningKey::try_from(&ed_bytes[0..32]) else {
            tracing::error!("Failed to create dalek key");
            return;
        };

        loop {
            interval.tick().await;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut record = kinetic_core::types::HostRoutingRecord {
                host_id: host_peer_id_str.clone(),
                current_peer_id: local_peer_id_str_for_publisher
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
                timestamp,
                signature: vec![],
            };

            use ed25519_dalek::Signer;
            let signature = dalek_kp.sign(&record.signable_bytes());
            record.signature = signature.to_bytes().to_vec();

            if let Err(e) = publisher_client.publish_host_routing_record(record).await {
                tracing::warn!("Failed to publish HostRoutingRecord: {}", e);
            } else {
                tracing::info!("Published dynamic HostRoutingRecord to DHT");
            }
        }
    });

    let mut hb_local_peer_id = local_peer_id;
    let hc_client = network_client.clone();
    let hc_drand_rx = drand_pulse_rx.clone();
    let hc_config = network_config.clone();
    let hc_storage = storage.clone();
    let hc_inc_tx = incoming_tx.clone();
    let hc_gossip_tx = gossip_tx.clone();
    let loop_handle_ref = network_loop_handle.clone();
    let shared_peer_id = local_peer_id_str.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if let Ok(pulse) = hb_drand.fetch_latest().await {
                if !pulse.is_unavailable && !pulse.is_from_cache {
                    let _ = drand_pulse_tx.send(pulse.round);

                    let pow_valid = kinetic_network::pow::is_valid_sybil_pow(
                        &hb_local_peer_id,
                        pulse.round,
                        kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                    );
                    if !pow_valid {
                        tracing::info!("PoW epoch expired for ephemeral identity. Hot-swapping network loop...");
                        let current_local_key = kinetic_network::pow::mine_sybil_keypair(
                            pulse.round,
                            kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                        );
                        hb_local_peer_id =
                            libp2p::PeerId::from_public_key(&current_local_key.public());

                        if let Ok(mut lock) = shared_peer_id.write() {
                            *lock = hb_local_peer_id.to_string();
                        }

                        let mut handle = loop_handle_ref.lock().await;
                        handle.abort();

                        if let Ok((new_client, new_loop)) = NetworkEventLoop::new(
                            hc_config.clone(),
                            current_local_key.clone(),
                            hc_storage.clone(),
                            hc_drand_rx.clone(),
                            Some(hc_inc_tx.clone()),
                            Some(hc_gossip_tx.clone()),
                        ) {
                            hc_client.update_backend(
                                new_client.get_sender(),
                                new_client.stream_control(),
                            );
                            *handle = tokio::spawn(async move {
                                new_loop.run().await;
                            });
                            tracing::info!("Successfully hot-swapped P2P backend with new PoW identity in Host mode.");
                        }
                    }
                }
            }
        }
    });

    // 7. Start Health-check API (Port 16004)
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peer_id",
            get(move || async move { host_peer_id.to_string() }),
        );

    let api_port = 16004;
    let addr = SocketAddr::from(([0, 0, 0, 0], api_port));
    info!(
        "Node Health-check API listening on http://0.0.0.0:{}",
        api_port
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
