use anyhow::Result;
use kinetic_network::{NetworkConfig, NetworkMode, NetworkEventLoop};
use std::time::Duration;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    let (_tx, rx) = watch::channel(30069417);
    
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
        bootstrap_nodes: kinetic_core::config::KineticConfig::default().network.bootstrap_nodes,
        seed_domains: vec![],
        enable_mdns: false,
        initial_drand_pulse: 30069417,
        external_address: None,
    };
    
    let storage = std::sync::Arc::new(kinetic_storage::SledStorage::new("/tmp/test_resolve_db").unwrap());
    
    let (client, event_loop) = NetworkEventLoop::new(config, keypair, storage, rx, None).unwrap();
    
    tokio::spawn(async move {
        event_loop.run().await;
    });
    
    tokio::time::sleep(Duration::from_secs(20)).await;
    
    println!("Resolving host_route_12D3KooWQxKsyK8NkgVWHHMYaU2nmREmMyGycTjcyxcnQQxJ88zF ...");
    let res = client.resolve_redundant_payload("host_route_12D3KooWQxKsyK8NkgVWHHMYaU2nmREmMyGycTjcyxcnQQxJ88zF").await;
    println!("Result: {:?}", res);
    
    if let Ok(payload) = res {
        let manifest: Result<kinetic_kid::CapabilityManifest, _> = serde_json::from_slice(&payload);
        println!("Manifest: {:?}", manifest);
    }
    
    Ok(())
}
