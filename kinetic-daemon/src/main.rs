//! # kinetic-daemon
//!
//! The primary user-facing Kinetic daemon binary (`kinetic-daemon`).
//!
//! The daemon is the central coordinator of a Kinetic network participant's
//! local stack. It manages the full lifecycle of name registration,
//! renewal, and resolution, and exposes an authenticated HTTP API that the
//! `kinetic-cli` and desktop app interact with.
//!
//! ## Responsibilities
//!
//! - **P2P networking**: Runs a full Kademlia DHT node for publishing and
//!   resolving `.kin` DNS records.
//! - **VDF engine**: Drives the Chia VDF to produce time-lock proofs for
//!   name registration and ownership transfers.
//! - **DNS resolver**: Embeds `kinetic-dns` to answer system-level DNS queries
//!   for `.kin` names on the loopback interface.
//! - **HTTP API**: Authenticated REST API on port 16002 for CLI and UI clients.
//! - **Service manager**: Can install, start, stop, and uninstall itself as a
//!   system service (systemd on Linux, launchd on macOS, SCM on Windows).
//!
//! ## Authentication
//!
//! A random API token is written to `~/.local/share/kinetic/api.token` on first
//! run. All mutating API calls must include this token in the
//! `X-Kinetic-Token` header.

use anyhow::Result;
use clap::{Parser, Subcommand};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

use kinetic_core::config::KineticConfig;
use kinetic_core::types::load_keypair;
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::KineticStorage;
use kinetic_vdf_rsa::RsaVdfEngine;
use std::env;
use std::sync::Arc;
use tokio::sync::watch;

use kinetic_daemon::{api, ca, proxy};

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
    Install {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        config_dir: Option<String>,
    },
    /// Uninstall the daemon system service
    Uninstall,
    /// Start the daemon (foregkyn)
    Run,
    /// Start the daemon service (background)
    Start,
    /// Stop the daemon service (background)
    Stop,
}

fn trust_ca(cert_path: &std::path::Path) -> Result<()> {
    if cfg!(target_os = "linux") {
        std::process::Command::new("sudo")
            .arg("mkdir")
            .arg("-p")
            .arg("/usr/local/share/ca-certificates")
            .status()?;

        let status = std::process::Command::new("sudo")
            .arg("cp")
            .arg(cert_path)
            .arg(format!(
                "/usr/local/share/ca-certificates/{}.crt",
                kinetic_core::constants::NETWORK_ID
            ))
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

fn install_service(mut user: Option<String>, config_dir_opt: Option<String>) -> Result<()> {
    user = user.or_else(|| std::env::var("SUDO_USER").ok());
    let base_config_dir = if let Some(dir) = config_dir_opt {
        std::path::PathBuf::from(dir)
    } else {
        kinetic_core::config::get_base_dir()
    };
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

    if let Some(ref u) = user {
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("chown")
                .arg("-R")
                .arg(format!("{}:{}", u, u))
                .arg(&base_config_dir)
                .status();
        }
    }

    println!("Installing Kinetic Daemon service...");
    let label: ServiceLabel = format!("{}-daemon", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec![
            "run"
                .parse()
                .map_err(|_| anyhow::anyhow!("Failed to parse run"))?,
        ],
        contents: None,
        username: user,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-daemon start' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-daemon", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-daemon", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-daemon", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

/// Executes the main logic for the Kinetic Daemon.
///
/// This function is responsible for:
/// - Validating the governance key state.
/// - Initializing Sled storage and the VDF engine.
/// - Starting the Drand heartbeat and PoW sybil mining loop.
/// - Establishing the Kademlia P2P Swarm.
/// - Starting the API server, PAC server, DNS proxy, and HTTP proxy.
///
/// # Errors
///
/// Returns an `anyhow::Error` if any fundamental networking or storage components fail to bind/initialize.
async fn run_daemon() -> Result<()> {
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

    if config.daemon.backend_port == config.daemon.api_port
        || config.daemon.backend_port == config.daemon.proxy_port
        || config.daemon.backend_port == config.daemon.nrs_port
        || config.daemon.backend_port == config.network.daemon_port
    {
        tracing::error!(
            "FATAL: config.daemon.backend_port ({}) conflicts with an internal daemon port!",
            config.daemon.backend_port
        );
        tracing::error!(
            "This opens the node to infinite loops and SSRF proxy exploits. Please change backend_port in config.toml."
        );
        std::process::exit(1);
    }

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    info!("Starting Kinetic Daemon (PID: {})...", std::process::id());

    let storage_path = config
        .daemon
        .storage_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 path in storage_dir"))?;
    let storage = Arc::new(KineticStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> = Arc::new(RsaVdfEngine::new());
    info!("VDF Engine initialized");

    let daemon_keypair = load_keypair(std::path::Path::new("identity.key"))?;
    info!(
        "Daemon identity loaded: {:?}",
        hex::encode(daemon_keypair.pubkey_bytes())
    );

    let drand_client = Arc::new(kinetic_core::drand::DrandClient::new(Some(storage.clone())));
    let initial_kyn = match drand_client.fetch_latest().await {
        Ok(kyn) => {
            info!("Drand beacon connected — kyn #{}", kyn.kyn);
            kyn
        }
        Err(e) => {
            warn!("Drand beacon unavailable on startup: {}", e);
            warn!("P2P swarm and proxy will start — registration disabled until beacon reachable");
            kinetic_core::drand::RawKyn::unavailable()
        }
    };
    let initial_kyn = initial_kyn.kyn;

    // Generate API token early so CLI commands (e.g. `kinetic status`) work immediately
    // without having to wait for the 30-40 second PoW mining loop to finish.
    if let Err(e) = kinetic_daemon::api::ensure_api_tokens() {
        tracing::error!("Failed to generate or read API tokens: {}", e);
        std::process::exit(1);
    }

    let (kyn_tx, kyn_rx) = watch::channel(initial_kyn);
    let local_key = kinetic_network::pow::mine_sybil_keypair(
        initial_kyn,
        kinetic_core::constants::POW_DIFFICULTY_BITS,
    );
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());
    tracing::info!("Daemon starting with Peer ID: {}", local_peer_id);

    let mode = match config.daemon.network_mode.as_str() {
        "LightNode" => NetworkMode::LightNode,
        _ => NetworkMode::FullNode,
    };
    let network_config = NetworkConfig {
        mode,
        listen_addrs: vec![
            format!("/ip4/0.0.0.0/tcp/{}", config.network.daemon_port)
                .parse()
                .unwrap(),
            format!("/ip6/::/tcp/{}", config.network.daemon_port)
                .parse()
                .unwrap(),
        ],
        quic_listen_addrs: vec![
            format!(
                "/ip4/0.0.0.0/udp/{}/quic-v1",
                config.network.daemon_quic_port
            )
            .parse()
            .unwrap(),
            format!("/ip6/::/udp/{}/quic-v1", config.network.daemon_quic_port)
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
        initial_kyn: initial_kyn,
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

    if !gov_state_path.exists() {
        tracing::info!(
            "Governance state file not found locally. Attempting to bootstrap from seed nodes..."
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let mut success = false;

        let mut target_ips = Vec::new();
        for addr in &config.network.bootstrap_nodes {
            if let Some(ip) = addr.split('/').nth(2) {
                target_ips.push(ip.to_string());
            }
        }

        for domain in &config.network.seed_domain {
            let addrs = kinetic_network::dns_tree::resolve_dns_tree(domain.as_str()).await;
            for multiaddr in addrs {
                if let Some(ip) = multiaddr.to_string().split('/').nth(2) {
                    target_ips.push(ip.to_string());
                }
            }
        }

        for ip in target_ips {
            let url = format!(
                "http://{}:{}/api/governance",
                ip,
                kinetic_core::config::ports::API_DAEMON
            );
            tracing::info!("Trying to fetch governance state from {}...", url);
            if let Ok(resp) = client.get(&url).send().await
                && resp.status().is_success()
                && let Ok(bytes) = resp.bytes().await
            {
                if let Ok(downloaded_state) =
                    bincode::deserialize::<kinetic_core::governance::GovernanceState>(&bytes)
                {
                    // Enforce strict content validation to prevent MITM attacks over HTTP
                    if downloaded_state.genesis_kyn
                        != kinetic_core::constants::KINETIC_GENESIS_KYN
                    {
                        tracing::warn!(
                            "Seed node provided governance state for wrong network genesis."
                        );
                        continue;
                    }

                    if let Err(e) = downloaded_state.save_to_disk(&gov_state_path) {
                        tracing::warn!("Failed to save downloaded governance state to disk: {}", e);
                    } else {
                        tracing::info!(
                            "Successfully bootstrapped governance state from seed node."
                        );
                        success = true;
                        break;
                    }
                } else {
                    tracing::warn!("Seed node provided invalid governance state bytes.");
                }
            }
        }

        if !success {
            tracing::warn!(
                "Failed to fetch governance state from any bootstrap node. Initializing a default genesis state."
            );
        }
    }

    let gov_state_path = std::sync::Arc::new(gov_state_path);
    {
        let mut gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .map_err(|e| anyhow::anyhow!("KIN-DAEMON-005: Governance state lock poisoned: {}", e))?;
        *gov = kinetic_core::governance::GovernanceState::load_from_disk(&gov_state_path);
    }

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(32);
    let (gossip_tx, gossip_rx) = tokio::sync::broadcast::channel::<(
        String,
        Vec<u8>,
        libp2p::gossipsub::MessageId,
        libp2p::PeerId,
    )>(100);
    let current_local_key = local_key;
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config.clone(),
        current_local_key.clone(),
        storage.clone(),
        kyn_rx.clone(),
        Some(incoming_tx.clone()),
        Some(gossip_tx.clone()),
        vdf_engine.clone(),
    )?;

    let network_loop_handle = tokio::spawn(async move {
        network_loop.run().await;
    });

    // Subscribe to Global Gossip
    let _ = network_client
        .subscribe_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL)
        .await;
    info!("P2P Network architecture wired");

    kinetic_daemon::services::network::start_pow_miner_loop(
        network_client.clone(),
        kyn_rx.clone(),
        network_config.clone(),
        storage.clone(),
        incoming_tx.clone(),
        gossip_tx.clone(),
        network_loop_handle,
        current_local_key,
        vdf_engine.clone(),
    );

    kinetic_daemon::services::gossip::start_gossip_processor(
        network_client.clone(),
        gossip_rx,
        gov_state_path.clone(),
        drand_client.clone(),
        kyn_tx.clone(),
        Some(storage.clone()),
    );

    kinetic_network::client::telemetry::start_telemetry_service(
        network_client.clone(),
        drand_client.clone(),
        config.clone(),
        kinetic_types::network::NodeType::Daemon,
    );

    let base_config_dir = kinetic_core::config::get_base_dir();
    std::fs::create_dir_all(&base_config_dir)?;

    let root_ca = match ca::load_or_create_root_ca(&base_config_dir) {
        Ok((root_ca, _is_new)) => std::sync::Arc::new(root_ca),
        Err(e) => {
            tracing::error!("KIN-DAEMON-001: Failed to initialize Root CA: {}", e);
            return Err(anyhow::anyhow!("CA Init Failed: {}", e));
        }
    };

    let leaf_cache = std::sync::Arc::new(tokio::sync::Mutex::new(ca::LeafCertCache::new()));
    let proxy_client = network_client.clone();
    let ca_clone = std::sync::Arc::clone(&root_ca);
    let cache_clone = std::sync::Arc::clone(&leaf_cache);
    let config_arc = std::sync::Arc::new(config.clone());
    let proxy_peer_id = local_peer_id.to_string();
    tokio::spawn(async move {
        if let Err(e) = proxy::start_proxy_server(
            proxy_client,
            config.daemon.proxy_port,
            ca_clone,
            cache_clone,
            config_arc,
            proxy_peer_id,
        )
        .await
        {
            tracing::error!("KIN-DAEMON-002: Proxy server crashed: {}", e);
        }
    });

    let handler_client = network_client.clone();
    let handler_bind_ip = config.daemon.bind_ip.clone();
    tokio::spawn(async move {
        proxy::handle_incoming_proxy_requests(
            handler_client,
            incoming_rx,
            handler_bind_ip,
            config.daemon.backend_port,
        )
        .await;
    });

    let atlas_nsps = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));

    let api_future = api::start_server(
        network_client.clone(),
        storage.clone(),
        gossip_tx.clone(),
        config.daemon.bind_ip.clone(),
        config.daemon.api_port,
        atlas_nsps.clone(),
    );

    info!("Kinetic Daemon architecture successfully bootstrapped. Spawning loops...");

    kinetic_daemon::services::network::start_republisher(network_client.clone(), storage.clone());

    kinetic_daemon::services::heartbeat::start_heartbeat_loop(
        storage.clone(),
        network_client.clone(),
        drand_client.clone(),
        config.drand.p2p_only,
        initial_kyn,
        daemon_keypair.clone(),
        kyn_tx.clone(),
    );

    // Register with kinetic-pac by dropping our proxy config into the global proxies directory
    let global_base = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic_global");
    let proxies_dir = global_base.join("proxies");
    let _ = std::fs::create_dir_all(&proxies_dir);

    let nsp_clean = kinetic_core::constants::NSP_SUFFIX.trim_start_matches('.');
    let proxy_json_path = proxies_dir.join(format!("{}.json", nsp_clean));

    let proxy_info = serde_json::json!({
        "nsp": kinetic_core::constants::NSP_SUFFIX,
        "proxy_ip": config.daemon.pac_bind_ip,
        "proxy_port": config.daemon.proxy_port,
    });

    if let Ok(file) = std::fs::File::create(&proxy_json_path) {
        let _ = serde_json::to_writer(file, &proxy_info);
        tracing::info!(
            "Registered proxy port {} with kinetic-pac",
            config.daemon.proxy_port
        );
    }

    if config.daemon.enable_nrs {
        let api_url = format!(
            "http://{}:{}",
            config.daemon.bind_ip, config.daemon.api_port
        );
        let dns_handler = kinetic_nrs::KineticNrsHandler::new(
            api_url,
            atlas_nsps.clone(),
            config.daemon.atlas_port,
        );
        let mut server = hickory_server::ServerFuture::new(dns_handler);

        let udp_bind = tokio::net::UdpSocket::bind(format!(
            "{}:{}",
            config.daemon.bind_ip, config.daemon.nrs_port
        ))
        .await;
        
        let tcp_bind = tokio::net::TcpListener::bind(format!(
            "{}:{}",
            config.daemon.bind_ip, config.daemon.nrs_port
        ))
        .await;

        match (udp_bind, tcp_bind) {
            (Ok(udp_socket), Ok(tcp_listener)) => {
                server.register_socket(udp_socket);
                server.register_listener(tcp_listener, std::time::Duration::from_secs(5));

                tokio::spawn(async move {
                    info!(
                        "Built-in DNS Server starting on port {}",
                        config.daemon.nrs_port
                    );
                    if let Err(e) = server.block_until_done().await {
                        tracing::error!("KIN-DAEMON-003: DNS Server error: {}", e);
                    }
                });
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!("KIN-DAEMON-006: Failed to bind built-in DNS server to port {} (likely EADDRINUSE from systemd-resolved). DNS server disabled, but daemon will continue running! Error: {}", config.daemon.nrs_port, e);
            }
        }
    }

    tokio::select! {
        res = api_future => {
            tracing::error!("KIN-DAEMON-004: API Server exited unexpectedly: {:?}", res);
        },
        _ = kinetic_core::shutdown::shutdown_signal() => {
            info!("Shutdown signal received. Commencing graceful shutdown...");
        }
    }

    // Guaranteed OS PAC Proxy cleanup on exit (Fixes Orphaned Proxy Blackhole)
    let _ = std::fs::remove_file(&proxy_json_path);
    info!("Safely removed PAC proxy registration from OS.");

    Ok(())
}

fn main() -> anyhow::Result<()> {
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        eprintln!(
            "Rustls crypto provider already installed or failed: {:?}",
            e
        );
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install { user, config_dir }) => {
            install_service(user.clone(), config_dir.clone())?;
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
            run_daemon().await?;
        }
    }

    Ok(())
}
