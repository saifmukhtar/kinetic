use kinetic_core::error::PublishError;
use kinetic_network::client::command::Command;
use kinetic_network::client::core::NetworkClient;
use kinetic_network::client::types::{ProxyError, ProxyRequest};
use kinetic_network::NetworkEventLoop;
use libp2p::PeerId;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_client_payload_size_limits() {
    let (tx, _rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    let large_payload = vec![0u8; 8001]; // Exceeds 8000 bytes limit

    let result = client
        .publish_redundant_payload("large_test", large_payload)
        .await;
    assert!(result.is_err());

    if let Err(PublishError::Internal { message, .. }) = result {
        assert!(message.contains("8000-byte"));
    } else {
        panic!(
            "Expected PublishError::Internal with size limit message, got {:?}",
            result
        );
    }
}

#[tokio::test]
async fn test_client_empty_payload() {
    let (tx, mut rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    let empty_payload = vec![]; // 0 bytes (valid size)

    let client_clone = client.clone();
    tokio::spawn(async move {
        // Will fail eventually because `rx` doesn't send a response on `oneshot`
        // But we just want to ensure it passes the size check
        let _ = client_clone
            .publish_redundant_payload("empty_test", empty_payload)
            .await;
    });

    let cmd = rx.recv().await.unwrap();
    match cmd {
        Command::PublishRedundant { name, payload, .. } => {
            assert_eq!(name, "empty_test");
            assert_eq!(payload.len(), 0);
        }
        _ => panic!("Expected PublishRedundant command"),
    }
}

#[tokio::test]
async fn test_client_channel_closed_gracefully() {
    let (tx, rx) = mpsc::channel(32);
    let client = NetworkClient::new_mock(tx);

    // Drop the receiver to simulate the backend shutting down
    drop(rx);

    let request = ProxyRequest {
        method: "GET".to_string(),
        path: "/test".to_string(),
        headers: std::collections::HashMap::new(),
        body: vec![],
    };

    // The channel is closed, so sending the proxy request should fail
    // gracefully rather than panicking.
    let peer_id = PeerId::random();
    let result = client.send_proxy_request(peer_id, request).await;
    assert!(result.is_err());

    match result {
        Err(ProxyError::ChannelClosed) => {} // expected
        _ => panic!("Expected ProxyError::ChannelClosed"),
    }
}

#[tokio::test]
async fn test_xor_tie_breaker_empty_list() {
    // Edge case: tie breaker called on an empty payload list
    let winner = NetworkEventLoop::xor_tie_breaker("test_empty", vec![], 9999);

    assert!(winner.is_none());
}
