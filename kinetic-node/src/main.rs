use anyhow::Result;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use std::sync::Arc;
use tokio::sync::watch;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use std::time::Duration;

use kinetic_core::config::KineticConfig;
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;
use kinetic_core::drand::{DrandClient, DrandPulse};

#[tokio::main]
async fn main() -> Result<()> {
    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting Kinetic Node (Infrastructure Mode)...");

    // 2. Initialize embedded storage
    let storage_path = config.daemon.storage_dir.to_str().unwrap_or("/tmp/kinetic_db");
    let storage = Arc::new(SledStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    // 3. Initialize Drand client for PoW validation of ephemeral clients
    let drand_client = Arc::new(DrandClient::new(storage.clone()));
    
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
    // Infrastructure nodes MUST have a static identity. We load/generate it here.
    let key_path = kinetic_core::config::get_base_dir().join("static_network_key.bin");
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let local_key = if let Ok(bytes) = std::fs::read(&key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|_| {
            // Fallback to random if corrupted (though we don't do PoW mining for nodes)
            libp2p::identity::Keypair::generate_ed25519()
        })
    } else {
        let k = libp2p::identity::Keypair::generate_ed25519();
        std::fs::write(&key_path, k.to_protobuf_encoding().unwrap()).unwrap();
        tracing::info!("Generated new static infrastructure identity");
        k
    };
    
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());
    tracing::info!("Infrastructure Node starting with Static Peer ID: {}", local_peer_id);

    // 5. Initialize P2P Network (FullNode mode, no mDNS by default for cloud)
    let network_config = NetworkConfig { 
        mode: NetworkMode::FullNode,
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.p2p_port),
        bootstrap_nodes: config.network.bootstrap_nodes.clone(),
        seed_domains: config.network.seed_domains.clone(),
        enable_mdns: false, // Cloud infrastructure nodes don't need local mDNS
        initial_drand_pulse,
    };
    
    let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(32);
    let (_network_client, mut network_loop) = NetworkEventLoop::new(network_config, local_key, storage.clone(), drand_pulse_rx, Some(incoming_tx))?;
    tokio::spawn(async move {
        if let Err(e) = network_loop.run().await {
            tracing::error!("Network loop crashed: {:?}", e);
        }
    });
    info!("P2P Network architecture wired");

    // 6. Start Drand Heartbeat (Every 30s)
    let hb_drand = drand_client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Ok(pulse) = hb_drand.fetch_latest().await {
                if !pulse.is_unavailable && !pulse.is_from_cache {
                    let _ = drand_pulse_tx.send(pulse.round);
                }
            }
        }
    });

    // 7. Start Health-check API (Port 16003)
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/peer_id", get(move || async move { local_peer_id.to_string() }));

    let api_port = 16003;
    let addr = SocketAddr::from(([0, 0, 0, 0], api_port));
    info!("Node Health-check API listening on http://0.0.0.0:{}", api_port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
