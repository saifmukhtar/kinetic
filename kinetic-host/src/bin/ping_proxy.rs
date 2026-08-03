//! P2P reverse proxy ping diagnostic CLI utility for Kinetic host nodes.

use anyhow::Result;
use clap::Parser;
use kinetic_network::{client::ProxyRequest, NetworkConfig, NetworkEventLoop, NetworkMode};
use kinetic_storage::SledStorage;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target peer ID to ping
    #[arg(short, long)]
    target_peer: String,

    /// Domain prefix to send in the Host header
    #[arg(short, long, default_value = "ping_proxy")]
    host_prefix: String,

    /// Custom path for the ping database
    #[arg(short, long)]
    db_path: Option<std::path::PathBuf>,
}

async fn fetch_drand_kyn() -> u64 {
    let client = reqwest::Client::new();
    let ping_endpoint = kinetic_core::constants::DRAND_HTTP_ENDPOINTS
        .first()
        .unwrap_or(&"");
    if let Ok(res) = client.get(*ping_endpoint).send().await {
        if let Ok(json) = res.json::<serde_json::Value>().await {
            if let Some(kyn) = json["round"].as_u64() {
                return kyn;
            }
        }
    }
    0
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let current_kyn = fetch_drand_kyn().await;
    println!("Fetched current Drand kyn: {}", current_kyn);

    println!("Mining PoW to satisfy kinetic-host anti-spam...");
    let key = kinetic_network::pow::mine_sybil_keypair(
        current_kyn,
        kinetic_core::constants::POW_DIFFICULTY_BITS,
    );
    println!("Mined PeerId: {}", key.public().to_peer_id());

    let db_path = args.db_path.unwrap_or_else(|| {
        kinetic_core::config::get_base_dir().join(kinetic_core::constants::DB_NAME_PING)
    });

    let storage = Arc::new(SledStorage::new(db_path)?);

    let config = NetworkConfig {
        mode: NetworkMode::LightNode,
        listen_addrs: vec![
            "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            "/ip6/::/tcp/0".parse().unwrap(),
        ],
        quic_listen_addrs: vec![],
        bootstrap_nodes: kinetic_core::constants::BOOTSTRAP_NODES
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        seed_domain: vec![],
        enable_mdns: false,
        initial_drand_kyn: 0,
        external_address: None,
        max_reveals_per_hour: 100,
        lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
        disable_pow: false,
    };

    let (incoming_tx, _) = tokio::sync::mpsc::channel(32);
    let (_, rx) = watch::channel(0);

    let vdf_engine = Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    let (client, loop_task) = NetworkEventLoop::new(
        config,
        key,
        storage,
        rx,
        Some(incoming_tx),
        None,
        vdf_engine,
    )?;
    tokio::spawn(loop_task.run());

    let target_peer = args
        .target_peer
        .parse()
        .expect("Invalid target peer ID format");

    println!("Dialing Kinetic Host ({})...", target_peer);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut headers = Vec::new();
    headers.push((
        "Host".into(),
        format!(
            "{}{}",
            args.host_prefix,
            kinetic_core::constants::TLD_SUFFIX
        )
        .into(),
    ));

    let req = ProxyRequest {
        method: "GET".into(),
        path: "/".into(),
        headers,
        body: bytes::Bytes::new(),
    };

    println!("Sending P2P Proxy Request...");
    match client.send_proxy_request(target_peer, req).await {
        Ok(response) => {
            println!("✅ SUCCESS! Received P2P Proxy Response from Python:");
            println!("Status: {}", response.status);
            println!("Body:\n{}", String::from_utf8_lossy(&response.body));
        }
        Err(e) => {
            println!("❌ Failed to proxy: {}", e);
        }
    }

    Ok(())
}
