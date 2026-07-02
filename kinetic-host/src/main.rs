pub mod proxy;

use anyhow::Result;
use axum::{routing::get, Router};
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

    // 4. Load Static Network Identity (The Permanent Host Key)
    let key_path = kinetic_core::config::get_base_dir().join("static_network_key.bin");
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let host_key = if let Ok(bytes) = std::fs::read(&key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|_| {
            libp2p::identity::Keypair::generate_ed25519()
        })
    } else {
        let k = libp2p::identity::Keypair::generate_ed25519();
        std::fs::write(&key_path, k.to_protobuf_encoding().unwrap()).unwrap();
        tracing::info!("Generated new static infrastructure identity");
        k
    };

    let host_peer_id = libp2p::PeerId::from_public_key(&host_key.public());
    tracing::info!(
        "Infrastructure Node static Host Identity: {}",
        host_peer_id
    );

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

    // 5. Initialize P2P Network (FullNode mode, no mDNS by default for cloud)
    let network_config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.p2p_port),
        bootstrap_nodes: config.network.bootstrap_nodes.clone(),
        seed_domains: config.network.seed_domains.clone(),
        enable_mdns: false, // Cloud infrastructure nodes don't need local mDNS
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
    tokio::spawn(async move {
        network_loop.run().await;
        tracing::warn!("Network loop exited");
    });
    info!("P2P Network architecture wired");

    let backend_port = std::env::var("KINETIC_HOST_BACKEND_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse::<u16>()
        .unwrap_or(80);

    tokio::spawn(proxy::handle_incoming_proxy_requests(
        network_client.clone(),
        incoming_rx,
        backend_port,
    ));
    info!("Proxy handler started. Proxying P2P traffic to local port {}", backend_port);

    // 6. Start Drand Heartbeat & Dynamic Routing Publisher
    let hb_drand = drand_client.clone();
    let publisher_client = network_client.clone();
    let publisher_host_key = host_key.clone();
    
    // Publish immediately on startup
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut record = kinetic_core::types::HostRoutingRecord {
            host_id: host_peer_id.to_string(),
            current_peer_id: local_peer_id.to_string(),
            timestamp,
            signature: vec![],
        };
        if let Ok(sig) = publisher_host_key.sign(&record.signable_bytes()) {
            record.signature = sig;
            tokio::spawn(async move {
                // Wait for DHT to populate
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Err(e) = publisher_client.publish_host_routing_record(record).await {
                    tracing::warn!("Failed to publish Host Routing Record: {}", e);
                } else {
                    tracing::info!("Published dynamic Host Routing Record to DHT");
                }
            });
        }
    }

    let hb_local_peer_id = local_peer_id;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Ok(pulse) = hb_drand.fetch_latest().await {
                if !pulse.is_unavailable && !pulse.is_from_cache {
                    let _ = drand_pulse_tx.send(pulse.round);
                    
                    // Check if our PoW identity is still valid for this pulse
                    let pow_valid = kinetic_network::pow::is_valid_sybil_pow(
                        &hb_local_peer_id,
                        pulse.round,
                        kinetic_network::pow::DEFAULT_DIFFICULTY_BITS,
                    );
                    if !pow_valid {
                        tracing::warn!("PoW epoch expired for ephemeral identity. Exiting so systemd can restart and remine.");
                        std::process::exit(0);
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
