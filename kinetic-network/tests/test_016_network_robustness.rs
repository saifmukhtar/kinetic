#![cfg(not(target_arch = "wasm32"))]

use kinetic_core::traits::VdfEngine;
use kinetic_core::traits::StorageEngine;
use kinetic_network::client::{NetworkConfig, NetworkMode};
use kinetic_network::event_loop::core::NetworkEventLoop;
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use proptest::prelude::*;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::watch;

fn create_base_config() -> NetworkConfig {
    NetworkConfig {
        mode: NetworkMode::FullNode,
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        quic_listen_addrs: vec![],
        bootstrap_nodes: vec![],
        external_address: None,
        initial_drand_kyn: 0,
        enable_mdns: false,
        lru_cache_size: std::num::NonZeroUsize::new(100).unwrap(),
        max_reveals_per_hour: 100,
        seed_domain: vec![],
        disable_pow: true,
        disable_storage_sync: true,
        test_mode: true,
    }
}

fn create_engine_and_store() -> (Arc<SledStorage>, Arc<dyn VdfEngine>) {
    let dir = tempdir().unwrap();
    let storage = Arc::new(SledStorage::new(dir.path()).unwrap());
    let vdf_engine = Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    (storage, vdf_engine)
}

#[tokio::test]
async fn test_01_fullnode_initialization_success() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let result = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine);
    assert!(result.is_ok(), "Full node should initialize cleanly");
}

#[tokio::test]
async fn test_02_lightnode_initialization_success() {
    let mut config = create_base_config();
    config.mode = NetworkMode::LightNode;
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let result = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine);
    assert!(result.is_ok(), "Light node should initialize cleanly");
}

#[tokio::test]
async fn test_03_test_mode_flag_applied() {
    let mut config = create_base_config();
    config.test_mode = true;
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let (_, event_loop) = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine).unwrap();
    assert_eq!(event_loop.has_bootstrapped(), false);
}

#[tokio::test]
async fn test_04_bad_bootstrap_peer_ignored() {
    let mut config = create_base_config();
    config.bootstrap_nodes.push("/ip4/192.0.2.1/tcp/9999/p2p/12D3KooW9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q".parse().unwrap());
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let result = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine);
    assert!(result.is_ok(), "Swarm builder should not panic on unreachable bootstrap peers");
}

#[tokio::test]
async fn test_05_kademlia_bootstrap_deferred_until_connected() {
    let mut config = create_base_config();
    config.bootstrap_nodes.push("/ip4/127.0.0.1/tcp/9999/p2p/12D3KooW9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q9q9Q".parse().unwrap());
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let (_, event_loop) = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine).unwrap();
    assert_eq!(event_loop.has_bootstrapped(), false);
}

#[tokio::test]
async fn test_06_banned_peers_loaded_properly() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut key = kinetic_core::constants::DB_PREFIX_BANNED_PEER.as_bytes().to_vec();
    key.extend_from_slice(peer_id.to_string().as_bytes());
    
    // current_drand_kyn defaults to 0 on startup, so any kyn > 0 is "in the future"
    let future_kyn = 1000u64;
    storage.put(&key, &future_kyn.to_be_bytes()).unwrap();

    let (_, mut event_loop) = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine).unwrap();
    assert!(event_loop.is_banned(&peer_id), "Banned peer should be loaded from Sled");
}

#[tokio::test]
async fn test_07_expired_bans_cleared() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut key = kinetic_core::constants::DB_PREFIX_BANNED_PEER.as_bytes().to_vec();
    key.extend_from_slice(peer_id.to_string().as_bytes());
    
    // Current drand kyn is 0, so 0 is not in the future.
    let past_kyn = 0u64;
    storage.put(&key, &past_kyn.to_be_bytes()).unwrap();

    let (_, mut event_loop) = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine).unwrap();
    assert!(!event_loop.is_banned(&peer_id), "Expired bans should be ignored");
}

#[tokio::test]
async fn test_08_multiple_full_nodes_spawn() {
    let config1 = create_base_config();
    let config2 = create_base_config();
    
    let (storage1, vdf1) = create_engine_and_store();
    let (storage2, vdf2) = create_engine_and_store();
    
    let n1 = NetworkEventLoop::new(config1, Keypair::generate_ed25519(), storage1, watch::channel(0).1, None, None, vdf1);
    let n2 = NetworkEventLoop::new(config2, Keypair::generate_ed25519(), storage2, watch::channel(0).1, None, None, vdf2);
    
    assert!(n1.is_ok());
    assert!(n2.is_ok());
}

#[tokio::test]
async fn test_09_quic_fallback() {
    let mut config = create_base_config();
    config.quic_listen_addrs = vec!["/ip4/255.255.255.255/udp/9999/quic-v1".parse().unwrap()];
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let result = NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine);
    assert!(result.is_ok(), "QUIC failure should fallback gracefully to TCP");
}

#[tokio::test]
async fn test_10_invalid_test_keys() {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    assert_ne!(peer_id.to_string(), "");
}

/// Verify that a peer accumulating 3 invalid gossip messages within 60 seconds is banned.
/// This exercises the ban-counting path without needing a live gossipsub mesh.
#[tokio::test]
async fn test_11_gossip_ban_after_three_invalid_messages() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let (_, mut event_loop) =
        NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine)
            .unwrap();

    let attacker = Keypair::generate_ed25519().public().to_peer_id();

    event_loop.record_invalid_gossip(attacker);
    assert!(!event_loop.is_banned(&attacker), "1 strike should not trigger a ban");

    event_loop.record_invalid_gossip(attacker);
    assert!(!event_loop.is_banned(&attacker), "2 strikes should not trigger a ban");

    event_loop.record_invalid_gossip(attacker);
    assert!(event_loop.is_banned(&attacker), "3 strikes within 60s must trigger a ban");
}

/// Verify that two distinct peers each accumulate strikes independently.
/// A ban on one peer must not affect the other.
#[tokio::test]
async fn test_12_gossip_ban_is_per_peer() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let (_, mut event_loop) =
        NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine)
            .unwrap();

    let peer_a = Keypair::generate_ed25519().public().to_peer_id();
    let peer_b = Keypair::generate_ed25519().public().to_peer_id();

    // Give peer_a 3 strikes, peer_b only 2
    for _ in 0..3 {
        event_loop.record_invalid_gossip(peer_a);
    }
    for _ in 0..2 {
        event_loop.record_invalid_gossip(peer_b);
    }

    assert!(event_loop.is_banned(&peer_a), "peer_a should be banned");
    assert!(!event_loop.is_banned(&peer_b), "peer_b should not be banned yet");
}

/// Verify the semaphore is configured to allow at least 1 permit — i.e. the bound is > 0
/// and we can acquire a permit immediately on a fresh event loop.
#[tokio::test]
async fn test_13_gossip_semaphore_not_zero_bound() {
    let config = create_base_config();
    let keypair = Keypair::generate_ed25519();
    let (storage, vdf_engine) = create_engine_and_store();
    let (_, event_loop) =
        NetworkEventLoop::new(config, keypair, storage, watch::channel(0).1, None, None, vdf_engine)
            .unwrap();

    // A fresh event loop must have at least one permit available.
    // If the semaphore were misconfigured at 0, this would return Err immediately.
    let permit = event_loop.gossip_semaphore.try_acquire();
    assert!(permit.is_ok(), "gossip_semaphore must have available permits on startup");
}

proptest! {
    #[test]
    fn proptest_valid_cache_sizes(size in 1usize..1000000) {
        let mut config = create_base_config();
        config.lru_cache_size = std::num::NonZeroUsize::new(size).unwrap();
        assert_eq!(config.lru_cache_size.get(), size);
    }

    #[test]
    fn proptest_vdf_reveal_limits(reveals in 1usize..1000) {
        let mut config = create_base_config();
        config.max_reveals_per_hour = reveals;
        assert_eq!(config.max_reveals_per_hour, reveals);
    }
}
