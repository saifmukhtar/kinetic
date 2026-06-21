use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use hickory_server::ServerFuture;
use tokio::net::UdpSocket;

use kinetic_dns::KineticDnsHandler;
use kinetic_network::network::{NetworkConfig, NetworkEventLoop};
use kinetic_storage::SledStorage;
use kinetic_vdf::ChiaVdfEngine;
use kinetic_core::config::KineticConfig;
use kinetic_core::traits::StorageEngine;
use kinetic_core::types::{Heartbeat, load_or_create_keypair};
use ed25519_dalek::Signer;
use std::sync::Arc;
use std::time::Duration;

mod api;

#[tokio::main]
async fn main() -> Result<()> {
    let config = KineticConfig::load();

    // 1. Initialize structured tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting Kinetic Daemon...");

    // 2. Initialize embedded storage
    let storage_path = config.daemon.storage_dir.to_str().unwrap_or("/tmp/kinetic_db");
    let storage = Arc::new(SledStorage::new(storage_path)?);
    info!("Storage engine initialized at {}", storage_path);

    // 3. Initialize VDF Engine
    let _vdf_engine = ChiaVdfEngine::new();
    info!("VDF Engine initialized");

    // 4. Load Daemon Identity Keypair
    let daemon_keypair = load_or_create_keypair()?;
    info!("Daemon identity loaded: {:?}", hex::encode(daemon_keypair.verifying_key().as_bytes()));

    // 5. Initialize P2P Network (DHT + Gossipsub)
    // We use the same ed25519 keypair for libp2p identity to ensure consistency
    let mut key_bytes = daemon_keypair.to_bytes();
    let local_key = libp2p::identity::Keypair::ed25519_from_bytes(&mut key_bytes).unwrap();
    let network_config = NetworkConfig { 
        listen_addr: format!("/ip4/0.0.0.0/tcp/{}", config.network.p2p_port),
        bootstrap_nodes: config.network.bootstrap_nodes,
    };
    let (network_client, network_loop) = NetworkEventLoop::new(network_config, local_key)?;
    info!("P2P Network architecture wired");

    // 5. Initialize DNS Proxy
    let dns_handler = KineticDnsHandler::new(network_client.clone());
    
    // Create and bind the Hickory DNS Server
    let mut server = ServerFuture::new(dns_handler);
    // Warning: Binding to port 53 requires elevated privileges (sudo)
    server.register_socket(UdpSocket::bind(format!("0.0.0.0:{}", config.daemon.dns_port)).await?);
    info!("DNS proxy ready on 0.0.0.0:{}", config.daemon.dns_port);

    // 6. Initialize Local API Server
    let api_future = api::start_server(network_client.clone(), storage.clone(), config.daemon.api_port);

    info!("Kinetic Daemon architecture successfully bootstrapped. Spawning loops...");

    // 7. Background Heartbeat Loop
    let hb_storage = storage.clone();
    let hb_network = network_client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let client = reqwest::Client::new();
        loop {
            interval.tick().await;
            
            // 7a. Fetch latest drand pulse
            let drand_url = "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest";
            let drand_resp = match client.get(drand_url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("Heartbeat loop: Failed to fetch drand: {}", e);
                    continue;
                }
            };
            
            #[derive(serde::Deserialize)]
            struct DrandPulse {
                round: u64,
            }
            
            let pulse = match drand_resp.json::<DrandPulse>().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Heartbeat loop: Failed to parse drand: {}", e);
                    continue;
                }
            };

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
                        
                        let sig = daemon_keypair.sign(&heartbeat.signable_bytes());
                        heartbeat.signature = sig.to_vec();
                        
                        // Publish the heartbeat under the heartbeat key hash
                        if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                            let heartbeat_topic = format!("{}-heartbeat", name);
                            if let Err(e) = hb_network.publish_redundant_payload(&heartbeat_topic, payload).await {
                                tracing::warn!("Failed to publish heartbeat for {}: {}", name, e);
                            } else {
                                info!("Successfully published heartbeat for {} at pulse {}", name, pulse.round);
                            }
                        }
                    }
                }
            }
            
            // 7c. Check for delegated Watchtower tokens
            if let Ok(bytes) = std::fs::read("watchtower.json") {
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
                            if let Ok(payload) = serde_json::to_vec(&heartbeat) {
                                let heartbeat_topic = format!("{}-heartbeat", name);
                                if let Err(e) = hb_network.publish_redundant_payload(&heartbeat_topic, payload).await {
                                    tracing::warn!("Failed to publish Watchtower delegated heartbeat for {}: {}", name, e);
                                } else {
                                    info!("Successfully published Watchtower delegated heartbeat for {} at pulse {}", name, heartbeat.latest_drand_pulse);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Start P2P event loop, DNS Server, and API Server
    tokio::select! {
        _ = network_loop.run() => {
            info!("P2P Network loop exited");
        },
        _ = server.block_until_done() => {
            info!("DNS Server exited");
        },
        res = api_future => {
            info!("API Server exited: {:?}", res);
        }
    }

    Ok(())
}
