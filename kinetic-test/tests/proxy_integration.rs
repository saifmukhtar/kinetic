use kinetic_network::{
    client::types::{ProxyRequest, ProxyResponse},
    NetworkClient, NetworkConfig, NetworkEventLoop,
};
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::{mpsc, watch};

async fn setup_node_with_proxy(
    port: u16,
    keypair: Keypair,
    bootstrap_nodes: Vec<String>,
    handle_proxy: bool,
) -> (NetworkClient, tokio::task::JoinHandle<()>) {
    let config = NetworkConfig {
        listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
        quic_listen_addr: None,
        external_address: None,
        max_reveals_per_hour: 100,
        lru_cache_size: std::num::NonZeroUsize::new(10_000).unwrap(),
        disable_pow: true,
        bootstrap_nodes: bootstrap_nodes
            .into_iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        initial_drand_pulse: 1000,
        mode: kinetic_network::NetworkMode::FullNode,
        enable_mdns: false,
        seed_domains: vec![],
    };
    let dir = tempdir().unwrap();
    let storage: Arc<dyn kinetic_core::traits::StorageEngine> =
        Arc::new(SledStorage::new(dir.path()).unwrap());
    let (_pulse_tx, pulse_rx) = watch::channel(1000);

    let (incoming_tx, incoming_rx) = if handle_proxy {
        let (tx, rx) = mpsc::channel(32);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
        Arc::new(kinetic_vdf::ChiaVdfEngine::new());

    let (client, event_loop) = NetworkEventLoop::new(
        config,
        keypair,
        storage,
        pulse_rx,
        incoming_tx,
        None,
        vdf_engine,
    )
    .unwrap();

    let client_clone = client.clone();
    if let Some(mut rx) = incoming_rx {
        tokio::spawn(async move {
            while let Some((_req, channel)) = rx.recv().await {
                // Return a mock response
                let resp = ProxyResponse {
                    status: 200,
                    headers: vec![],
                    body: b"Hello from Proxy Backend!".to_vec().into(),
                };
                let _ = client_clone.send_proxy_response(channel, resp).await;
            }
        });
    }

    let handle = tokio::spawn(async move {
        event_loop.run().await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    (client, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_proxy_integration_flow() {
    let key_a = Keypair::generate_ed25519();
    let peer_a = PeerId::from(key_a.public());
    let (_client_a, _handle_a) = setup_node_with_proxy(20050, key_a, vec![], true).await;

    let key_b = Keypair::generate_ed25519();
    let boot_addr = format!("/ip4/127.0.0.1/tcp/20050/p2p/{}", peer_a);
    let (client_b, _handle_b) = setup_node_with_proxy(20051, key_b, vec![boot_addr], false).await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    let req = ProxyRequest {
        method: "GET".to_string().into(),
        path: "/hello".to_string().into(),
        headers: vec![],
        body: bytes::Bytes::new(),
    };

    let mut response_opt = None;
    for _ in 0..3 {
        match client_b.send_proxy_request(peer_a, req.clone()).await {
            Ok(resp) => {
                response_opt = Some(resp);
                break;
            }
            Err(e) => {
                tracing::warn!("Proxy request failed: {:?}, retrying...", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    let response = response_opt.expect("Proxy request failed after retries");

    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "Hello from Proxy Backend!"
    );
}
