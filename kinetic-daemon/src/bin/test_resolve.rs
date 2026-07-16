//! Test script for network resolution and P2P integration.
use anyhow::Result;
use kinetic_network::{NetworkConfig, NetworkEventLoop, NetworkMode};
use std::time::Duration;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    let (_tx, _rx) = watch::channel(30069417);

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
        bootstrap_nodes: kinetic_core::config::KineticConfig::default()
            .network
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        seed_domains: vec![],
        enable_mdns: false,
        initial_drand_pulse: 30069417,
        external_address: None,
        max_reveals_per_hour: 100,
        lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
        disable_pow: false,
    };

    let storage =
        std::sync::Arc::new(kinetic_storage::SledStorage::new("/tmp/test_resolve_db").unwrap());
    let (_tx, rx) = watch::channel(0);
    let vdf_engine = std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    let (client, event_loop) =
        NetworkEventLoop::new(config, keypair, storage, rx, None, None, vdf_engine).unwrap();

    tokio::spawn(async move {
        event_loop.run().await;
    });

    tokio::time::sleep(Duration::from_secs(20)).await;

    println!("Resolving host_route_12D3KooWQxKsyK8NkgVWHHMYaU2nmREmMyGycTjcyxcnQQxJ88zF ...");
    let res = client
        .resolve_redundant_payload(
            "host_route_12D3KooWQxKsyK8NkgVWHHMYaU2nmREmMyGycTjcyxcnQQxJ88zF",
        )
        .await;
    println!("Result: {:?}", res);

    if let Ok(payload) = res {
        let manifest: Result<kinetic_kid::CapabilityManifest, _> = serde_json::from_slice(&payload);
        println!("Manifest: {:?}", manifest);
    }

    Ok(())
}
