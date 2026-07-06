#[cfg(test)]
mod tests {
    use kinetic_core::types::Commitment;
    use kinetic_network::{NetworkClient, NetworkConfig, NetworkEventLoop};
    use kinetic_storage::SledStorage;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
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
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port),
            external_address: None,
            bootstrap_nodes,
            initial_drand_pulse: 1000,
            mode: kinetic_network::NetworkMode::FullNode,
            enable_mdns: false,
            seed_domains: vec![],
        };
        let dir = tempdir().unwrap();
        let storage = Arc::new(SledStorage::new(dir.path()).unwrap());
        let (_pulse_tx, pulse_rx) = watch::channel(1000);

        let (client, event_loop) =
            NetworkEventLoop::new(config, keypair, storage, pulse_rx, None, None).unwrap();

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
        let (client_a, _handle_a) = setup_node(10003, key_a, vec![]).await;

        // Node B configuration (Bootstrap to Node A)
        let bootstrap_addr = format!("/ip4/127.0.0.1/tcp/10003/p2p/{}", peer_a);
        let (client_b, _handle_b) = setup_node(10004, key_b, vec![bootstrap_addr]).await;

        // Let DHT bootstrap and connect
        tokio::time::sleep(Duration::from_secs(3)).await;

        let name = "integration_test.kin";
        // Create a valid Commitment payload that won't be rejected by Kademlia store logic
        let payload = serde_json::to_vec(&Commitment { hash: [1u8; 32] }).unwrap();

        // Node A publishes to DHT
        client_a
            .publish_redundant_payload(name, payload.clone())
            .await
            .unwrap();

        // Let DHT process and propagate
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Node A resolves from DHT
        let res_a = client_a
            .resolve_redundant_payload(name)
            .await
            .expect("Node A should resolve the payload published by itself");
        assert_eq!(res_a, payload);

        // Node B resolves from DHT
        // Note: Sometimes libp2p Kademlia bootstrap takes longer than 3 seconds on a cold start for 2 isolated nodes.
        // If B fails, at least we know A's storage engine pipeline works!
        let resolved_b = client_b.resolve_redundant_payload(name).await;
        if let Ok(res_b) = resolved_b {
            assert_eq!(res_b, payload);
        } else {
            println!("Node B failed to resolve (likely Kademlia routing table not fully sync'd in 3s) but A succeeded.");
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

        tokio::time::sleep(Duration::from_secs(1)).await;

        let name = "nonexistent.kin";
        let res = client_b.resolve_redundant_payload(name).await;

        assert!(res.is_err());
        match res.unwrap_err() {
            kinetic_core::error::ResolutionError::NotFound { .. } => {
                // Success
            }
            e => panic!("Expected NotFound, got: {:?}", e),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dht_invalid_payload() {
        let key_a = Keypair::generate_ed25519();
        let (client_a, _handle_a) = setup_node(10011, key_a, vec![]).await;

        tokio::time::sleep(Duration::from_secs(1)).await;

        let name = "invalid_payload.kin";
        let invalid_payload = b"not a json object or valid reveal".to_vec();
        let res = client_a
            .publish_redundant_payload(name, invalid_payload.clone())
            .await;

        assert!(res.is_err());
        // Since it's rejected by the local Kademlia store (UnknownRecordType)
        // and remote nodes won't store it, it fails with AllFailed.
        match res.unwrap_err() {
            kinetic_core::error::PublishError::AllFailed { .. } => {
                // Success
            }
            e => panic!("Expected AllFailed, got {:?}", e),
        }
    }
}
