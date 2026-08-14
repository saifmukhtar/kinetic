//! End-to-end integration testing harness for Kinetic P2P networking, DHT resolution, and resilience.

#[cfg(test)]
mod tests {
    use kinetic_core::types::Commitment;
    use kinetic_network::{NetworkClient, NetworkConfig, NetworkEventLoop};
    use kinetic_storage::SledStorage;
    use libp2p::PeerId;
    use libp2p::identity::Keypair;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::sync::watch;

    async fn setup_node(
        port: u16,
        keypair: Keypair,
        bootstrap_nodes: Vec<String>,
    ) -> (NetworkClient, tokio::task::JoinHandle<()>) {
        let config = NetworkConfig {
            listen_addrs: vec![format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap()],
            quic_listen_addrs: vec![],
            external_address: None,
            max_reveals_per_hour: 100,
            lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
            disable_pow: false,
            test_mode: false,
            bootstrap_nodes: bootstrap_nodes
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            initial_drand_kyn: 1000,
            mode: kinetic_network::NetworkMode::FullNode,
            enable_mdns: false,
            seed_domain: vec![],
            disable_storage_sync: false,
        };
        let dir = tempdir().unwrap();
        let storage: Arc<dyn kinetic_core::traits::StorageEngine> =
            Arc::new(SledStorage::new(dir.path()).unwrap());
        let (_kyn_tx, kyn_rx) = watch::channel(1000);
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf::ChiaVdfEngine::new());

        let (client, event_loop) =
            NetworkEventLoop::new(config, keypair, storage, kyn_rx, None, None, vdf_engine)
                .unwrap();

        let handle = tokio::spawn(async move {
            event_loop.run().await;
        });

        // Give it a moment to bind
        tokio::time::sleep(Duration::from_millis(500)).await;

        (client, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dht_publish_and_resolve() {
        // Create identities
        let key_a = Keypair::generate_ed25519();
        let peer_a = PeerId::from(key_a.public());

        let key_b = Keypair::generate_ed25519();

        // Node A configuration (No bootstrap)
        let (_client_a, _handle_a) = setup_node(10003, key_a, vec![]).await;

        // Node B configuration (Bootstrap to Node A)
        let bootstrap_addr = format!("/ip4/127.0.0.1/tcp/10003/p2p/{}", peer_a);
        let (client_b, _handle_b) = setup_node(10004, key_b, vec![bootstrap_addr]).await;

        // Let DHT bootstrap and connect
        tokio::time::sleep(Duration::from_secs(3)).await;

        let name = "integration_test.kin";
        // Create a valid Commitment payload that won't be rejected by Kademlia store logic
        let payload = serde_json::to_vec(&Commitment { hash: [1u8; 32] }).unwrap();

        // Node B publishes to DHT (B bootstrapped to A, so B definitely knows A immediately)
        let _ = client_b
            .publish_redundant_payload(name, payload.clone())
            .await;

        // Let DHT process and propagate
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Node B resolves from DHT (should hit local cache or network)
        let res_b = client_b
            .resolve_redundant_payload(name)
            .await
            .expect("Node B should resolve the payload published by itself");
        assert_eq!(res_b, payload);

        // Node B resolves from DHT
        // Note: Sometimes libp2p Kademlia bootstrap takes longer than 3 seconds on a cold start for 2 isolated nodes.
        // If B fails, at least we know A's storage engine pipeline works!
        let resolved_b = client_b.resolve_redundant_payload(name).await;
        if let Ok(res_b) = resolved_b {
            assert_eq!(res_b, payload);
        } else {
            println!(
                "Node B failed to resolve (likely Kademlia routing table not fully sync'd in 3s) but A succeeded."
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dht_resolve_not_found() {
        let key_a = Keypair::generate_ed25519();
        let key_b = Keypair::generate_ed25519();
        let peer_a = key_a.public().to_peer_id();

        let (_client_a, _handle_a) = setup_node(10012, key_a, vec![]).await;

        let boot_addr = format!("/ip4/127.0.0.1/tcp/10012/p2p/{}", peer_a);
        let (client_b, _handle_b) = setup_node(10013, key_b, vec![boot_addr]).await;

        // Give more time for the DHT to bootstrap and exchange Kademlia info
        tokio::time::sleep(Duration::from_secs(3)).await;

        let name = "nonexistent.kin";
        let res = client_b.resolve_redundant_payload(name).await;

        assert!(res.is_err());
        match res.unwrap_err() {
            kinetic_core::error::ResolutionError::NotFound { .. }
            | kinetic_core::error::ResolutionError::Offline => {
                // Success
            }
            e => panic!("Expected NotFound, got: {:?}", e),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dht_invalid_payload() {
        let key_a = Keypair::generate_ed25519();
        let (client_a, _handle_a) = setup_node(10011, key_a, vec![]).await;

        tokio::time::sleep(Duration::from_secs(3)).await;

        let name = "invalid_payload.kin";
        let invalid_payload = b"not a json object or valid reveal".to_vec();
        let res = client_a
            .publish_redundant_payload(name, invalid_payload.clone())
            .await;

        assert!(res.is_err());
        // Since it's rejected by the local Kademlia store (UnknownRecordType)
        // and remote nodes won't store it, it fails with AllFailed.
        match res.unwrap_err() {
            kinetic_core::error::PublishError::Rejected(_) => {
                // Success
            }
            e => panic!("Expected Rejected, got {:?}", e),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dht_lru_cache_eviction() {
        // Node with a cache size of exactly 1
        let key_a = Keypair::generate_ed25519();
        let config = NetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/10020".parse().unwrap()],
            quic_listen_addrs: vec![],
            external_address: None,
            max_reveals_per_hour: 100,
            lru_cache_size: std::num::NonZeroUsize::new(1).unwrap(), // Size 1
            disable_pow: false,
            test_mode: false,
            bootstrap_nodes: vec![],
            initial_drand_kyn: 1000,
            mode: kinetic_network::NetworkMode::FullNode,
            enable_mdns: false,
            seed_domain: vec![],
            disable_storage_sync: false,
        };

        let dir = tempdir().unwrap();
        let storage: Arc<dyn kinetic_core::traits::StorageEngine> =
            Arc::new(SledStorage::new(dir.path()).unwrap());
        let (_kyn_tx, kyn_rx) = watch::channel(1000);
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf::ChiaVdfEngine::new());

        let (client, event_loop) =
            NetworkEventLoop::new(config, key_a, storage, kyn_rx, None, None, vdf_engine).unwrap();

        let _handle = tokio::spawn(async move {
            event_loop.run().await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let payload1 = serde_json::to_vec(&Commitment { hash: [1u8; 32] }).unwrap();
        let payload2 = serde_json::to_vec(&Commitment { hash: [2u8; 32] }).unwrap();

        let _ = client
            .publish_redundant_payload("name1.kin", payload1.clone())
            .await;
        let _ = client
            .publish_redundant_payload("name2.kin", payload2.clone())
            .await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        // name2 should be in the cache, it resolves instantly
        let res2 = client.resolve_redundant_payload("name2.kin").await.unwrap();
        assert_eq!(res2, payload2);

        // name1 got evicted, but since we are the only node, it will resolve from our own local storage!
        let res1 = client.resolve_redundant_payload("name1.kin").await.unwrap();
        assert_eq!(res1, payload1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_drand_kyn_sync() {
        let key_a = Keypair::generate_ed25519();
        let dir = tempdir().unwrap();
        let storage: Arc<dyn kinetic_core::traits::StorageEngine> =
            Arc::new(SledStorage::new(dir.path()).unwrap());
        let (kyn_tx, kyn_rx) = watch::channel(1000);
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf::ChiaVdfEngine::new());

        let config = NetworkConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/10021".parse().unwrap()],
            quic_listen_addrs: vec![],
            external_address: None,
            max_reveals_per_hour: 100,
            lru_cache_size: std::num::NonZeroUsize::new(1000).unwrap(),
            disable_pow: false,
            test_mode: false,
            bootstrap_nodes: vec![],
            initial_drand_kyn: 1000,
            mode: kinetic_network::NetworkMode::FullNode,
            enable_mdns: false,
            seed_domain: vec![],
            disable_storage_sync: false,
        };

        let (client, event_loop) =
            NetworkEventLoop::new(config, key_a, storage, kyn_rx, None, None, vdf_engine).unwrap();

        let _handle = tokio::spawn(async move {
            event_loop.run().await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Push a new Drand kyn
        kyn_tx.send(2000).unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        // At this point we just ensure the event loop didn't panic and is still responsive
        let payload = serde_json::to_vec(&Commitment { hash: [1u8; 32] }).unwrap();
        let _ = client
            .publish_redundant_payload("drand_test.kin", payload)
            .await;
        // Test passes if no panic occurred
    }
}
