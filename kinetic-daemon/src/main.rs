//! # kinetic-daemon
//!
//! The primary user-facing Kinetic daemon binary (`kinetic-daemon`).
//!
//! The daemon is the central coordinator of a Kinetic network participant's
//! local stack. It manages the full lifecycle of domain name registration,
//! renewal, and resolution, and exposes an authenticated HTTP API that the
//! `kinetic-cli` and desktop app interact with.
//!
//! ## Responsibilities
//!
//! - **P2P networking**: Runs a full Kademlia DHT node for publishing and
//!   resolving `.kin` DNS records.
//! - **VDF engine**: Drives the Chia VDF to produce time-lock proofs for
//!   domain registration and ownership transfers.
//! - **DNS resolver**: Embeds `kinetic-dns` to answer system-level DNS queries
//!   for `.kin` domains on the loopback interface.
//! - **HTTP API**: Authenticated REST API on port 16002 for CLI and UI clients.
//! - **Service manager**: Can install, start, stop, and uninstall itself as a
//!   system service (systemd on Linux, launchd on macOS, SCM on Windows).
//!
//! ## Authentication
//!
//! A random API token is written to `~/.config/kinetic/api.token` on first
//! run. All mutating API calls must include this token in the
//! `X-Kinetic-Token` header.

use anyhow::Result;
use clap::{Parser, Subcommand};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ed25519_dalek::Signer;
use kinetic_core::config::KineticConfig;
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::{load_keypair, Heartbeat};
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;
use kinetic_vdf::ChiaVdfEngine;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

mod api;
mod api_tests;
mod ca;
mod ca_tests;
mod nostr;
mod nostr_tests;
mod pac;
mod proxy;
mod proxy_tests;

#[derive(Parser)]
#[command(
    name = "kinetic-daemon",
    version = "0.1.0",
    author = "Kinetic Protocol"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the daemon as a system service and setup CA
    Install,
    /// Uninstall the daemon system service
    Uninstall,
    /// Start the daemon (foreground)
    Start,
    /// Start the daemon service (background)
    StartService,
    /// Stop the daemon service (background)
    StopService,
}

fn trust_ca(cert_path: &std::path::Path) -> Result<()> {
    if cfg!(target_os = "linux") {
        let status = std::process::Command::new("sudo")
            .arg("cp")
            .arg(cert_path)
            .arg("/usr/local/share/ca-certificates/kinetic.crt")
            .status()?;
        if status.success() {
            std::process::Command::new("sudo")
                .arg("update-ca-certificates")
                .status()?;
        }
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("sudo")
            .args([
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
            ])
            .arg(cert_path)
            .status()?;
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("certutil")
            .args(["-addstore", "-f", "Root"])
            .arg(cert_path)
            .status()?;
    }
    Ok(())
}

fn install_service() -> Result<()> {
    let base_config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic");
    std::fs::create_dir_all(&base_config_dir)?;

    println!("Generating root CA...");
    let _ = ca::load_or_create_root_ca(&base_config_dir)?;
    let cert_path = base_config_dir.join("ca_cert.pem");

    println!("Trusting root CA...");
    if let Err(e) = trust_ca(&cert_path) {
        println!(
            "Warning: Could not automatically trust CA. Please trust it manually. Error: {}",
            e
        );
        println!("  To enable HTTPS for .kin domains, install it manually:");
        println!("  {}", cert_path.display());
    } else {
        println!("CA Trusted successfully.");
    }

    println!("Installing Kinetic Daemon service...");
    let label: ServiceLabel = "com.kinetic.daemon".parse()?;
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

    println!("Service installed successfully. Run 'kinetic-daemon start-service' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.daemon".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.daemon".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.daemon".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

async fn run_daemon() -> Result<()> {
    let config = KineticConfig::load();

    if config.daemon.backend_port == config.daemon.api_port
        || config.daemon.backend_port == config.daemon.proxy_port
        || config.daemon.backend_port == config.daemon.dns_port
        || config.daemon.backend_port == config.network.daemon_port
    {
        tracing::error!(
            "FATAL: config.daemon.backend_port ({}) conflicts with an internal daemon port!",
            config.daemon.backend_port
        );
        tracing::error!("This opens the node to infinite loops and SSRF proxy exploits. Please change backend_port in config.toml.");
        std::process::exit(1);
    }

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    info!("Starting Kinetic Daemon...");

    let storage_path = config
        .daemon
        .storage_dir
        .to_str()
        .unwrap_or("/tmp/kinetic_db");
    let storage = Arc::new(SledStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    let _vdf_engine = ChiaVdfEngine::new();
    info!("VDF Engine initialized");

    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let daemon_keypair = load_keypair(&identity_path.to_string_lossy())?;
    info!(
        "Daemon identity loaded: {:?}",
        hex::encode(daemon_keypair.verifying_key().as_bytes())
    );

    let drand_client = Arc::new(kinetic_core::drand::DrandClient::new(Some(storage.clone())));
    let initial_pulse = match drand_client.fetch_latest().await {
        Ok(pulse) => {
            info!("Drand beacon connected — pulse #{}", pulse.round);
            pulse
        }
        Err(e) => {
            warn!("Drand beacon unavailable on startup: {}", e);
            warn!("P2P swarm and proxy will start — registration disabled until beacon reachable");
            kinetic_core::drand::DrandPulse::unavailable()
        }
    };
    let initial_drand_pulse = initial_pulse.round;

    let (drand_pulse_tx, drand_pulse_rx) = watch::channel(initial_drand_pulse);
    let local_key = kinetic_network::pow::mine_sybil_keypair(
        initial_drand_pulse,
        kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
    );
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());
    tracing::info!("Daemon starting with Peer ID: {}", local_peer_id);

    let mode = match config.daemon.network_mode.as_str() {
        "LightClient" => NetworkMode::LightClient,
        _ => NetworkMode::FullNode,
    };
    let network_config = NetworkConfig {
        mode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.daemon_port),
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
    let mut current_local_key = local_key;
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config.clone(),
        current_local_key.clone(),
        storage.clone(),
        drand_pulse_rx.clone(),
        Some(incoming_tx.clone()),
        Some(gossip_tx.clone()),
    )?;
    info!("P2P Network architecture wired");

    let mut network_loop_handle = tokio::spawn(async move {
        network_loop.run().await;
    });

    let hc_client = network_client.clone();
    let hc_drand_rx = drand_pulse_rx.clone();
    let hc_config = network_config.clone();
    let hc_storage = storage.clone();
    let hc_inc_tx = incoming_tx.clone();
    let hc_gossip_tx = gossip_tx.clone();
    tokio::spawn(async move {
        let mut rx = hc_drand_rx.clone();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let pulse = *rx.borrow();
            if pulse == 0 {
                continue;
            }
            let peer_id = libp2p::PeerId::from_public_key(&current_local_key.public());
            if !kinetic_network::pow::is_valid_sybil_pow(
                &peer_id,
                pulse,
                kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
            ) {
                tracing::info!("PoW epoch expired. Remining identity seamlessly...");
                current_local_key = kinetic_network::pow::mine_sybil_keypair(
                    pulse,
                    kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                );

                network_loop_handle.abort();

                if let Ok((new_client, new_loop)) = NetworkEventLoop::new(
                    hc_config.clone(),
                    current_local_key.clone(),
                    hc_storage.clone(),
                    hc_drand_rx.clone(),
                    Some(hc_inc_tx.clone()),
                    Some(hc_gossip_tx.clone()),
                ) {
                    hc_client.update_backend(new_client.get_sender(), new_client.stream_control());
                    network_loop_handle = tokio::spawn(async move {
                        new_loop.run().await;
                    });
                    tracing::info!("Successfully hot-swapped P2P backend with new PoW identity");
                }
            }
        }
    });

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

    let base_config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic");
    std::fs::create_dir_all(&base_config_dir)?;

    let root_ca = match ca::load_or_create_root_ca(&base_config_dir) {
        Ok((root_ca, _is_new)) => std::sync::Arc::new(root_ca),
        Err(e) => {
            tracing::error!("Failed to initialize Root CA: {}", e);
            return Err(anyhow::anyhow!("CA Init Failed: {}", e));
        }
    };

    let leaf_cache = std::sync::Arc::new(tokio::sync::Mutex::new(ca::LeafCertCache::new()));
    let proxy_client = network_client.clone();
    let ca_clone = std::sync::Arc::clone(&root_ca);
    let cache_clone = std::sync::Arc::clone(&leaf_cache);
    tokio::spawn(async move {
        if let Err(e) = proxy::start_proxy_server(
            proxy_client,
            config.daemon.proxy_port,
            ca_clone,
            cache_clone,
        )
        .await
        {
            tracing::error!("Proxy server crashed: {}", e);
        }
    });

    let handler_client = network_client.clone();
    tokio::spawn(async move {
        proxy::handle_incoming_proxy_requests(
            handler_client,
            incoming_rx,
            config.daemon.backend_port,
        )
        .await;
    });

    let mempool = Arc::new(std::sync::Mutex::new(kinetic_core::mempool::Mempool::new(
        1000,
        std::time::Duration::from_secs(3600),
    )));
    let api_future = api::start_server(
        network_client.clone(),
        storage.clone(),
        config.daemon.api_port,
        mempool.clone(),
    );

    info!("Kinetic Daemon architecture successfully bootstrapped. Spawning loops...");

    let republish_network = network_client.clone();
    let republish_storage = storage.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(43200)); // 12 hours
        loop {
            interval.tick().await;
            let owned_key = b"kinetic_owned_names";
            if let Ok(Some(bytes)) = republish_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for name in names {
                        let reveal_key = format!("kinetic_reveal:{}", name);
                        if let Ok(Some(reveal_bytes)) = republish_storage.get(reveal_key.as_bytes()) {
                            let rn = republish_network.clone();
                            let n = name.clone();
                            tokio::spawn(async move {
                                let _ = rn.publish_redundant_payload(&n, reveal_bytes).await;
                            });
                        }
                    }
                }
            }
        }
    });

    let hb_storage = storage.clone();
    let hb_network = network_client.clone();
    let hb_drand = drand_client.clone();
    let last_known_live_round = Arc::new(AtomicU64::new(initial_drand_pulse));
    let lklr = last_known_live_round.clone();
    let daemon_keypair_hb = daemon_keypair.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let pulse = match hb_drand.fetch_latest().await {
                Ok(p) => {
                    if !p.is_from_cache {
                        lklr.store(p.round, Ordering::Relaxed);
                    }
                    let current_live = lklr.load(Ordering::Relaxed);
                    if !p.is_usable_for_heartbeat(current_live) {
                        continue;
                    }
                    p
                }
                Err(_) => {
                    continue;
                }
            };

            let _ = drand_pulse_tx.send(pulse.round);
            let owned_key = b"kinetic_owned_names";
            if let Ok(Some(bytes)) = hb_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for name in names {
                        let mut heartbeat = Heartbeat {
                            name: name.clone(),
                            latest_drand_pulse: pulse.round,
                            signature: vec![],
                        };

                        let sig = daemon_keypair_hb.sign(&heartbeat.signable_bytes());
                        heartbeat.signature = sig.to_vec();

                        let name_clone = name.clone();
                        let hb_network_clone = hb_network.clone();
                        let pulse_round = pulse.round;

                        tokio::spawn(async move {
                            if let Ok(bytes) = hb_network_clone
                                .resolve_redundant_payload(&name_clone)
                                .await
                            {
                                if let Ok(reveal) =
                                    serde_json::from_slice::<kinetic_core::types::Reveal>(&bytes)
                                {
                                    let age = pulse_round.saturating_sub(reveal.drand_pulse);
                                    let max_age_rounds = 1_000_000;
                                    let ninety_percent = (max_age_rounds as f64 * 0.9) as u64;
                                    if age > ninety_percent {
                                        tracing::warn!("⚠️ REVEAL VDF EXPIRING FOR {}", name_clone);
                                    }
                                }
                            }
                            if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                let _ = hb_network_clone
                                    .publish_heartbeat(&name_clone, payload)
                                    .await;
                            }
                        });
                    }
                }
            }

            let watchtower_path = kinetic_core::config::get_base_dir().join("watchtower.json");
            if let Ok(bytes) = std::fs::read(&watchtower_path) {
                if let Ok(mut tokens) = serde_json::from_slice::<Vec<Heartbeat>>(&bytes) {
                    tokens.retain(|t| t.latest_drand_pulse <= pulse.round);
                    tokens.sort_by_key(|t| std::cmp::Reverse(t.latest_drand_pulse));

                    let mut best_by_name = std::collections::HashMap::new();
                    for t in tokens {
                        best_by_name.entry(t.name.clone()).or_insert(t);
                    }

                    for (name, heartbeat) in best_by_name {
                        if pulse.round - heartbeat.latest_drand_pulse <= 10 {
                            let name_clone = name.clone();
                            let hb_network_clone = hb_network.clone();

                            tokio::spawn(async move {
                                let mut sig_valid = false;
                                if let Ok(payload) = hb_network_clone
                                    .resolve_redundant_payload(&name_clone)
                                    .await
                                {
                                    if let Ok(reveal) =
                                        serde_json::from_slice::<kinetic_core::types::Reveal>(
                                            &payload,
                                        )
                                    {
                                        use ed25519_dalek::Verifier as _;
                                        if let Ok(vk) = ed25519_dalek::VerifyingKey::try_from(
                                            reveal.pubkey.as_slice(),
                                        ) {
                                            let signable = heartbeat.signable_bytes();
                                            if let Ok(sig) = ed25519_dalek::Signature::from_slice(
                                                &heartbeat.signature,
                                            ) {
                                                sig_valid = vk.verify(&signable, &sig).is_ok();
                                            }
                                        }
                                    }
                                }

                                if sig_valid {
                                    if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                        let _ = hb_network_clone
                                            .publish_heartbeat(&name_clone, payload)
                                            .await;
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    });

    let daemon_keypair_nostr = daemon_keypair.clone();
    let mempool_nostr = mempool.clone();
    let storage_nostr = storage.clone();
    tokio::spawn(async move {
        if let Err(e) = nostr::start_nostr_listener(
            daemon_keypair_nostr,
            mempool_nostr,
            storage_nostr,
            config.daemon.network_mode == "PublicMiner",
        )
        .await
        {
            tracing::error!("Nostr Listener error: {}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = pac::start_pac_server(16001, config.daemon.proxy_port).await {
            tracing::error!("PAC server crashed: {}", e);
        }
    });

    let pac_manager = pac::PacManager::new(&base_config_dir);
    if let Err(e) = pac_manager.install("http://127.0.0.1:16001/proxy.pac") {
        tracing::error!("Failed to install OS proxy configuration: {}", e);
    }

    if config.daemon.enable_dns {
        let api_url = format!("http://127.0.0.1:{}", config.daemon.api_port);
        let dns_handler = kinetic_dns::KineticDnsHandler::new(api_url);
        let mut server = hickory_server::ServerFuture::new(dns_handler);

        let udp_socket =
            tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", config.daemon.dns_port)).await?;
        server.register_socket(udp_socket);

        let tcp_listener =
            tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.daemon.dns_port)).await?;
        server.register_listener(tcp_listener, std::time::Duration::from_secs(5));

        tokio::spawn(async move {
            info!(
                "Built-in DNS Server starting on port {}",
                config.daemon.dns_port
            );
            if let Err(e) = server.block_until_done().await {
                tracing::error!("DNS Server error: {}", e);
            }
        });
    }

    tokio::select! {
        res = api_future => {
            tracing::error!("API Server exited unexpectedly: {:?}", res);
        },
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received. Commencing graceful shutdown...");
            if let Err(e) = pac_manager.uninstall() {
                tracing::error!("Failed to uninstall OS proxy configuration: {}", e);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

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
            run_daemon().await?;
        }
    }

    Ok(())
}
