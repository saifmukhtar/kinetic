use anyhow::Result;
use hickory_server::ServerFuture;
use tokio::net::UdpSocket;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ed25519_dalek::Signer;
use kinetic_core::config::KineticConfig;
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::{load_or_create_keypair, Heartbeat};
use kinetic_dns::KineticDnsHandler;
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;
use kinetic_vdf::ChiaVdfEngine;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

mod api;
mod api_tests;
mod ca;
mod nostr;
mod pac;
mod proxy;

#[tokio::main]
async fn main() -> Result<()> {
    let config = KineticConfig::load();

    // Prevent Edge Case 51: Port conflicts
    if config.daemon.backend_port == config.daemon.api_port
        || config.daemon.backend_port == config.daemon.proxy_port
        || config.daemon.backend_port == config.daemon.dns_port
        || config.daemon.backend_port == config.network.p2p_port
    {
        tracing::error!(
            "FATAL: config.daemon.backend_port ({}) conflicts with an internal daemon port!",
            config.daemon.backend_port
        );
        tracing::error!("This opens the node to infinite loops and SSRF proxy exploits. Please change backend_port in config.toml.");
        std::process::exit(1);
    }

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting Kinetic Daemon...");

    // 2. Initialize embedded storage
    let storage_path = config
        .daemon
        .storage_dir
        .to_str()
        .unwrap_or("/tmp/kinetic_db");
    let storage = Arc::new(SledStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    // 3. Initialize VDF Engine
    let _vdf_engine = ChiaVdfEngine::new();
    info!("VDF Engine initialized");

    // 4. Load Daemon Identity Keypair
    let daemon_keypair = load_or_create_keypair()?;
    info!(
        "Daemon identity loaded: {:?}",
        hex::encode(daemon_keypair.verifying_key().as_bytes())
    );

    // 4.5 Fetch initial Drand pulse for PoW
    let drand_client = Arc::new(kinetic_core::drand::DrandClient::new(storage.clone()));

    let initial_pulse = match drand_client.fetch_latest().await {
        Ok(pulse) => {
            info!("Drand beacon connected — pulse #{}", pulse.round);
            pulse
        }
        Err(e) => {
            warn!("Drand beacon unavailable on startup: {}", e);
            warn!("P2P swarm and proxy will start — registration disabled until beacon reachable");
            // Use a sentinel value — heartbeat loop will retry on next tick
            kinetic_core::drand::DrandPulse::unavailable()
        }
    };

    let initial_drand_pulse = initial_pulse.round;

    // 4.6 Create drand pulse watch channel — heartbeat loop pushes real rounds; network event
    // loop receives them so current_drand_pulse stays tethered to the actual beacon.
    let (drand_pulse_tx, drand_pulse_rx) = watch::channel(initial_drand_pulse);

    // 5. Initialize P2P Network (DHT + Gossipsub)
    // We explicitly decouple the DHT routing identity from the Kinetic registrant identity.
    // The libp2p Keypair is an ephemeral identity that must satisfy the S/Kademlia PoW for the current epoch.
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
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.p2p_port),
        bootstrap_nodes: config.network.bootstrap_nodes.clone(),
        seed_domains: config.network.seed_domains.clone(),
        enable_mdns: config.network.enable_mdns,
        initial_drand_pulse,
        external_address: config.network.external_address.clone(),
    };

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(32);
    let (network_client, network_loop) = NetworkEventLoop::new(
        network_config,
        local_key,
        storage.clone(),
        drand_pulse_rx,
        Some(incoming_tx),
    )?;
    info!("P2P Network architecture wired");

    // Base config dir for CA and lockfiles
    let base_config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("kinetic");
    std::fs::create_dir_all(&base_config_dir)?;

    // Initialize Root CA
    let root_ca = match ca::load_or_create_root_ca(&base_config_dir) {
        Ok((root_ca, is_new)) => {
            if is_new {
                let cert_path = base_config_dir.join("ca_cert.pem");
                println!("\n{}", "=".repeat(60));
                println!("  KINETIC: ONE-TIME SETUP REQUIRED");
                println!("{}", "=".repeat(60));
                println!("  A local Root CA has been generated at:");
                println!("  {}", cert_path.display());
                println!();
                println!("  To enable HTTPS for .kin domains, install it:");
                println!("  Linux (Chrome): Settings > Privacy > Manage Certs");
                println!("                  > Authorities > Import");
                println!("  Linux (Firefox): about:preferences#privacy");
                println!("                   > View Certificates > Import");
                println!("  Or run: certutil -d sql:$HOME/.pki/nssdb \\");
                println!("          -A -t 'C,,' -n 'Kinetic' \\");
                println!("          -i {}", cert_path.display());
                println!("{}", "=".repeat(60));
                println!();
            } else {
                tracing::info!("Root CA loaded from {}", base_config_dir.display());
            }
            std::sync::Arc::new(root_ca)
        }
        Err(e) => {
            tracing::error!("Failed to initialize Root CA: {}", e);
            return Err(anyhow::anyhow!("CA Init Failed"));
        }
    };

    let leaf_cache = std::sync::Arc::new(tokio::sync::Mutex::new(ca::LeafCertCache::new()));

    // 5. Initialize the Local HTTP Proxy
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

    // 5.b Initialize the incoming P2P Proxy Handler
    let handler_client = network_client.clone();
    tokio::spawn(async move {
        proxy::handle_incoming_proxy_requests(
            handler_client,
            incoming_rx,
            config.daemon.backend_port,
        )
        .await;
    });

    // 5. Initialize DNS Proxy
    let dns_handler = KineticDnsHandler::new(network_client.clone());

    // Create and bind the Hickory DNS Server
    let mut server = ServerFuture::new(dns_handler.clone());
    let bind_ip = if cfg!(target_os = "linux") {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    };

    // Warning: Binding to port 53 requires elevated privileges (sudo/CAP_NET_BIND_SERVICE)
    match UdpSocket::bind(format!("{}:{}", bind_ip, config.daemon.dns_port)).await {
        Ok(socket) => {
            server.register_socket(socket);

            // Case 198: IPv6 Only Network Support. Try binding to IPv6 loopback as well
            if let Ok(ipv6_socket) =
                UdpSocket::bind(format!("[::1]:{}", config.daemon.dns_port)).await
            {
                server.register_socket(ipv6_socket);
            }

            tokio::spawn(async move {
                if let Err(e) = server.block_until_done().await {
                    tracing::error!("DNS Server error: {:?}", e);
                }
            });
            info!(
                "DNS proxy ready on {}:{} (and [::1])",
                bind_ip, config.daemon.dns_port
            );
        }
        Err(e) => {
            warn!(
                "Failed to bind DNS proxy to {}:{}: {}",
                bind_ip, config.daemon.dns_port, e
            );
            warn!("Falling back to non-privileged port. Use sudo for native DNS interception.");
            let fallback_port = if config.daemon.dns_port == 53 {
                5353
            } else {
                config.daemon.dns_port + 1000
            };
            match UdpSocket::bind(format!("{}:{}", bind_ip, fallback_port)).await {
                Ok(socket) => {
                    server.register_socket(socket);

                    if let Ok(ipv6_socket) =
                        UdpSocket::bind(format!("[::1]:{}", fallback_port)).await
                    {
                        server.register_socket(ipv6_socket);
                    }
                    tokio::spawn(async move {
                        if let Err(e) = server.block_until_done().await {
                            tracing::error!("DNS Server fallback error: {:?}", e);
                        }
                    });
                    info!(
                        "DNS proxy ready (fallback) on {}:{}",
                        bind_ip, fallback_port
                    );
                }
                Err(e2) => {
                    warn!(
                        "Failed to bind DNS proxy to fallback port {}: {}",
                        fallback_port, e2
                    );
                    warn!(
                        "HTTPS .kin resolution via proxy (port {}) remains fully functional",
                        config.daemon.proxy_port
                    );
                }
            }
        }
    }

    // 6. Initialize Local API Server
    let mempool = std::sync::Arc::new(std::sync::Mutex::new(kinetic_core::mempool::Mempool::new(
        100,
        std::time::Duration::from_secs(3 * 3600),
    )));
    let api_future = api::start_server(
        network_client.clone(),
        storage.clone(),
        config.daemon.api_port,
        Some(dns_handler.clone()),
        mempool.clone(),
    );

    info!("Kinetic Daemon architecture successfully bootstrapped. Spawning loops...");

    // 6.5 Re-publish owned Reveals on boot (Fix for Edge Case 25)
    let republish_network = network_client.clone();
    let republish_storage = storage.clone();
    tokio::spawn(async move {
        // Wait for DHT to bootstrap and discover peers
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;

        let owned_key = b"kinetic_owned_names";
        if let Ok(Some(bytes)) = republish_storage.get(owned_key) {
            if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                for name in names {
                    let reveal_key = format!("kinetic_reveal:{}", name);
                    if let Ok(Some(reveal_bytes)) = republish_storage.get(reveal_key.as_bytes()) {
                        tracing::info!("Boot sync: Re-publishing Reveal for {} to DHT...", name);
                        let rn = republish_network.clone();
                        let n = name.clone();
                        tokio::spawn(async move {
                            let _ = rn.publish_redundant_payload(&n, reveal_bytes).await;
                        });
                    }
                }
            }
        }
    });
    // 7. Background Heartbeat Loop
    let hb_storage = storage.clone();
    let hb_network = network_client.clone();
    let hb_drand = drand_client.clone();
    // Tracks the most recent *live* (non-cached) drand round seen. Used to detect stale cache.
    let last_known_live_round = Arc::new(AtomicU64::new(initial_drand_pulse));
    let lklr = last_known_live_round.clone();
    let daemon_keypair_hb = daemon_keypair.clone();
    tokio::spawn(async move {
        // 3.5: Align heartbeat interval to Drand pulse (30 seconds)
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            // 7a. Fetch latest drand pulse using the resilient client
            let pulse = match hb_drand.fetch_latest().await {
                Ok(p) => {
                    if p.is_from_cache {
                        warn!(
                            "Heartbeat using cached Drand pulse #{} — beacon may be unreachable",
                            p.round
                        );
                    } else {
                        // Update the live-round watermark
                        lklr.store(p.round, Ordering::Relaxed);
                    }
                    // Compare cached round against the last confirmed live round for staleness
                    let current_live = lklr.load(Ordering::Relaxed);
                    if !p.is_usable_for_heartbeat(current_live) {
                        tracing::warn!(
                            "Heartbeat loop: Drand cache (round {}) too stale vs last live round {} — skipping.",
                            p.round, current_live
                        );
                        continue;
                    }
                    p
                }
                Err(e) => {
                    tracing::warn!("Heartbeat loop: Failed to fetch drand: {}", e);
                    continue;
                }
            };

            // 7a.5 Push the real drand round into the watch channel so the network event loop
            // stays anchored to the actual beacon (fixes 3.13).
            let _ = drand_pulse_tx.send(pulse.round);

            // 7b. Iterate over owned names and send heartbeats
            let owned_key = b"kinetic_owned_names";
            if let Ok(Some(bytes)) = hb_storage.get(owned_key) {
                if let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes) {
                    for name in names {
                        tracing::debug!("Generating Heartbeat for owned name: {}", name);

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
                            // Check if the original Reveal VDF is expiring
                            if let Ok(Some(bytes)) = hb_network_clone
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
                                        tracing::warn!("⚠️ REVEAL VDF EXPIRING FOR {}: Exhausted {}/{} rounds. Renew immediately using `kinetic renew {}`!", name_clone, age, max_age_rounds, name_clone);
                                    }
                                }
                            }

                            // Publish to the dedicated heartbeat keyspace — never overwrites the Reveal.
                            if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                if let Err(e) = hb_network_clone
                                    .publish_heartbeat(&name_clone, payload)
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to publish heartbeat for {}: {}",
                                        name_clone,
                                        e
                                    );
                                } else {
                                    info!(
                                        "Successfully published heartbeat for {} at pulse {}",
                                        name_clone, pulse_round
                                    );
                                }
                            }
                        });
                    }
                }
            }

            // 7c. Check for delegated Watchtower tokens
            // Use an absolute config-dir path so this works correctly under systemd
            // (which sets CWD to "/", making relative paths silently miss the file).
            let watchtower_path = kinetic_core::config::get_base_dir().join("watchtower.json");
            if let Ok(bytes) = std::fs::read(&watchtower_path) {
                if let Ok(mut tokens) = serde_json::from_slice::<Vec<Heartbeat>>(&bytes) {
                    // Find the token with the highest pulse <= current pulse
                    tokens.retain(|t| t.latest_drand_pulse <= pulse.round);
                    tokens.sort_by_key(|t| std::cmp::Reverse(t.latest_drand_pulse));

                    // We might have tokens for multiple names. Group by name.
                    let mut best_by_name = std::collections::HashMap::new();
                    for t in tokens {
                        best_by_name.entry(t.name.clone()).or_insert(t);
                    }

                    for (name, heartbeat) in best_by_name {
                        // Only broadcast if the token is recent enough (within last 10 rounds = 5 mins)
                        if pulse.round - heartbeat.latest_drand_pulse <= 10 {
                            let name_clone = name.clone();
                            let hb_network_clone = hb_network.clone();

                            tokio::spawn(async move {
                                // Verify the Ed25519 signature before broadcasting by fetching the Reveal pubkey
                                let mut sig_valid = false;
                                if let Ok(Some(payload)) = hb_network_clone
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

                                if !sig_valid {
                                    warn!("Watchtower token for {} failed signature check (or missing Reveal) — dropping", name_clone);
                                    return;
                                }

                                if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                    // Publish to the heartbeat keyspace — keeps resolution path clean.
                                    if let Err(e) = hb_network_clone
                                        .publish_heartbeat(&name_clone, payload)
                                        .await
                                    {
                                        tracing::warn!("Failed to publish Watchtower delegated heartbeat for {}: {}", name_clone, e);
                                    } else {
                                        info!("Successfully published Watchtower delegated heartbeat for {} at pulse {}", name_clone, heartbeat.latest_drand_pulse);
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    });

    // 9.5 Spawn Nostr Listener Background Task
    let daemon_keypair_nostr = daemon_keypair.clone();
    let mempool_nostr = mempool.clone();
    let storage_nostr = storage.clone();
    tokio::spawn(async move {
        if let Err(e) =
            nostr::start_nostr_listener(daemon_keypair_nostr, mempool_nostr, storage_nostr).await
        {
            tracing::error!("Nostr Listener error: {}", e);
        }
    });

    // 10. Start HTTP API Server (port 16001)
    tokio::spawn(async move {
        if let Err(e) = pac::start_pac_server(16001).await {
            tracing::error!("PAC server crashed: {}", e);
        }
    });

    // Initialize OS Proxy Configuration
    let pac_manager = pac::PacManager::new(&base_config_dir);
    if let Err(e) = pac_manager.install("http://127.0.0.1:16001/proxy.pac") {
        tracing::error!("Failed to install OS proxy configuration: {}", e);
    }

    // Start P2P event loop and API Server
    tokio::select! {
        _ = network_loop.run() => {
            info!("P2P Network loop exited");
        },
        res = api_future => {
            info!("API Server exited: {:?}", res);
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
