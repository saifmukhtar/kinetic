use kinetic_network::NetworkEventLoop;
use kinetic_network::client::{NetworkClient, NetworkConfig, NetworkMode};
use kinetic_storage::SledStorage;
use libp2p::{Multiaddr, PeerId, identity};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::watch;
use tokio::task::JoinHandle;

async fn spawn_test_node(
    port: u16,
    bootstrap_nodes: Vec<Multiaddr>,
) -> (
    NetworkClient,
    PeerId,
    Multiaddr,
    JoinHandle<()>,
    tempfile::TempDir,
) {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    // Use loopback TCP port
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap();

    let config = NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addrs: vec![listen_addr.clone()],
        quic_listen_addrs: vec![],
        bootstrap_nodes,
        external_address: None,
        initial_drand_kyn: 1000,
        enable_mdns: false,
        lru_cache_size: std::num::NonZeroUsize::new(100).unwrap(),
        max_reveals_per_hour: 100,
        seed_domain: vec![],
        disable_pow: true,
        test_mode: true,
        disable_storage_sync: false,
    };

    let dir = tempdir().unwrap();
    let storage = Arc::new(SledStorage::new(dir.path()).unwrap());

    let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
        std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    let (client, event_loop) = NetworkEventLoop::new(
        config,
        keypair,
        storage,
        watch::channel(0).1,
        None,
        None,
        vdf_engine,
    )
    .unwrap();

    let handle = tokio::spawn(async move {
        event_loop.run().await;
    });

    // Allow time for swarm to start listening and bootstrap
    tokio::time::sleep(Duration::from_millis(150)).await;

    let p2p_addr = listen_addr.with(libp2p::multiaddr::Protocol::P2p(peer_id));

    (client, peer_id, p2p_addr, handle, dir)
}

#[tokio::test]
async fn test_chaos_routing_partition() {
    let _ = tracing_subscriber::fmt::try_init();

    let (client1, _peer1, addr1, _handle1, _dir1) = spawn_test_node(10010, vec![]).await;
    let (_client2, _peer2, addr2, handle2, _dir2) =
        spawn_test_node(10020, vec![addr1.clone()]).await;
    let (_client3, _peer3, addr3, handle3, _dir3) =
        spawn_test_node(10030, vec![addr1.clone(), addr2.clone()]).await;
    let (_client4, _peer4, addr4, _handle4, _dir4) =
        spawn_test_node(10040, vec![addr1.clone(), addr2.clone(), addr3.clone()]).await;
    let (client5, _peer5, _addr5, _handle5, _dir5) = spawn_test_node(
        10050,
        vec![addr1.clone(), addr2.clone(), addr3.clone(), addr4.clone()],
    )
    .await;

    // Allow mesh to fully connect and Kademlia routing tables to populate
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Node 5 publishes a payload (since Node 5 has all other nodes in its bootstrap list)
    let test_key = "chaos-key-test.kin";
    let test_payload = serde_json::to_vec(&kinetic_core::types::NameRecord::Standard(Box::new(
        kinetic_core::types::Reveal {
            protocol_version: 1,
            name: test_key.to_string(),
            payload: vec![],
            salt: [0; 32],
            drand_kyn: 1000,
            drand_signature: "0".repeat(192),
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: vec![0; 100],
            },
            iterations: 1000,
            pubkey: vec![0; 1952],
            signature: vec![0; 4627],
            previous_proof: None,
            miner_pubkey: None,
            authorization: None,
        },
    )))
    .unwrap();

    println!("Publishing payload from Node 5...");
    let mut publish_success = false;
    for _ in 0..10 {
        match client5
            .publish_redundant_payload(test_key, test_payload.clone())
            .await
        {
            Ok(_) => {
                publish_success = true;
                break;
            }
            Err(e) => {
                println!("Publish failed: {:?}", e);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(publish_success, "Failed to publish payload after retries");

    // Allow time for DHT replication
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Unleash Chaos: Kill Node 2 and Node 3 brutally.
    // This creates a large network partition between Node 1 and Node 5.
    println!("Unleashing Chaos: Dropping Node 2 and Node 3...");
    handle2.abort();
    handle3.abort();

    // Allow a moment for the network to realize peers are unreachable
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Node 1 attempts to resolve the record.
    // It will have to query Node 4, which might have it, or route around the dead nodes.
    println!("Attempting to resolve from Node 1...");
    let mut resolved = vec![];
    for _ in 0..15 {
        if let Ok(res) = client1.resolve_redundant_payload(test_key).await {
            resolved = res;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    assert!(!resolved.is_empty(), "Failed to resolve despite chaos");
    assert_eq!(resolved, test_payload);
}
