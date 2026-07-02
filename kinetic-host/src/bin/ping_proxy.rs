use anyhow::Result;
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode, client::ProxyRequest};
use kinetic_storage::SledStorage;
use std::sync::Arc;
use tokio::sync::watch;

async fn fetch_drand_pulse() -> u64 {
    let client = reqwest::Client::new();
    let res = client.get("https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest")
        .send().await.unwrap();
    let json: serde_json::Value = res.json().await.unwrap();
    json["round"].as_u64().unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    

    let current_pulse = fetch_drand_pulse().await;
    println!("Fetched current Drand pulse: {}", current_pulse);
    
    println!("Mining PoW to satisfy kinetic-host anti-spam...");
    let key = kinetic_network::pow::mine_sybil_keypair(current_pulse, kinetic_network::pow::DEFAULT_DIFFICULTY_BITS);
    println!("Mined PeerId: {}", key.public().to_peer_id());
    let storage = Arc::new(SledStorage::new("/tmp/kinetic_ping_db")?);
    
    let config = NetworkConfig {
        mode: NetworkMode::LightClient,
        listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
        bootstrap_nodes: vec!["/ip4/127.0.0.1/tcp/6071/p2p/12D3KooWHQaKKkjWdHnnhK78CQkLVQRB9GYoLMAttTbJtdgyizWS".to_string()],
        seed_domains: vec![],
        enable_mdns: false,
        initial_drand_pulse: 0,
        external_address: None,
    };

    let (incoming_tx, _) = tokio::sync::mpsc::channel(32);
    let (_, rx) = watch::channel(0);
    
    let (client, loop_task) = NetworkEventLoop::new(config, key, storage, rx, Some(incoming_tx))?;
    tokio::spawn(loop_task.run());

    // The peer ID from your sandbox logs
    let target_peer = "12D3KooWHQaKKkjWdHnnhK78CQkLVQRB9GYoLMAttTbJtdgyizWS".parse().unwrap();

    println!("Dialing Kinetic Host (12D3KooWHQaKKkjWdHnnhK78CQkLVQRB9GYoLMAttTbJtdgyizWS)...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut headers = std::collections::HashMap::new();
    headers.insert("Host".to_string(), "saif.kin".to_string());

    let req = ProxyRequest {
        method: "GET".to_string(),
        path: "/".to_string(),
        headers,
        body: vec![],
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
