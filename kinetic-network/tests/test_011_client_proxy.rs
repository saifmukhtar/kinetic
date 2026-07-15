use kinetic_network::client::types::ProxyRequest;
use kinetic_network::client::{Command, NetworkClient};
use libp2p::PeerId;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_client_proxy_command() {
    let (tx, mut rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    let target_peer = PeerId::random();
    let proxy_req = ProxyRequest {
        method: "GET".into(),
        path: "/".into(),
        headers: Vec::new(),
        body: bytes::Bytes::from(vec![1, 2, 3]),
    };

    tokio::spawn(async move {
        let _ = client.send_proxy_request(target_peer, proxy_req).await;
    });

    if let Some(cmd) = rx.recv().await {
        match cmd {
            Command::SendProxyRequest { request, .. } => {
                assert_eq!(request.body, vec![1, 2, 3]);
                assert_eq!(request.method.as_ref(), "GET");
            }
            _ => panic!("Expected SendProxyRequest command"),
        }
    } else {
        panic!("Channel closed");
    }
}

#[tokio::test]
async fn test_client_resolve_name() {
    let (tx, mut rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    tokio::spawn(async move {
        let _ = client.resolve_redundant_payload("test.kid").await;
    });

    if let Some(cmd) = rx.recv().await {
        match cmd {
            Command::ResolveRedundant { name, .. } => {
                assert_eq!(&*name, "test.kid");
            }
            _ => panic!("Expected ResolveRedundant command"),
        }
    } else {
        panic!("Channel closed");
    }
}

#[tokio::test]
async fn test_client_publish_name() {
    let (tx, mut rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    tokio::spawn(async move {
        let _ = client
            .publish_redundant_payload("test.kid", vec![1, 2, 3])
            .await;
    });

    if let Some(cmd) = rx.recv().await {
        match cmd {
            Command::PublishRedundant { name, payload, .. } => {
                assert_eq!(&*name, "test.kid");
                assert_eq!(payload, vec![1, 2, 3]);
            }
            _ => panic!("Expected PublishRedundant command"),
        }
    } else {
        panic!("Channel closed");
    }
}

#[tokio::test]
async fn test_client_hot_swap() {
    let (tx, mut rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);
    let (tx2, _rx2) = mpsc::channel(32);

    // Test that the client hot swap mechanism sets the new channel
    client.update_backend(tx2, None);

    let target_peer = PeerId::random();
    let proxy_req = ProxyRequest {
        method: "GET".into(),
        path: "/".into(),
        headers: Vec::new(),
        body: bytes::Bytes::from(vec![1, 2, 3]),
    };

    let client_clone = client.clone();
    tokio::spawn(async move {
        let _ = client_clone
            .send_proxy_request(target_peer, proxy_req)
            .await;
    });

    let res = tokio::time::timeout(tokio::time::Duration::from_millis(50), rx.recv()).await;
    match res {
        Err(_) => {} // Timeout, meaning no message was received (expected if tx was not dropped)
        Ok(None) => {} // Channel closed (expected because tx was replaced and dropped)
        Ok(Some(_)) => panic!("Original rx should not receive messages after hot swap"),
    }
}
