#[cfg(test)]
mod tests {
    use crate::api::{app, ApiState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use kinetic_core::traits::StorageEngine;
    use kinetic_network::client::{Command, NetworkClient};
    use kinetic_storage::SledStorage;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    fn get_test_token() -> String {
        std::fs::read_to_string(kinetic_core::config::get_api_token_path())
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|_| "test-token-123".to_string())
    }

    async fn setup_test_app() -> (axum::Router, mpsc::Receiver<Command>, Arc<SledStorage>) {
        let dir = tempdir().unwrap();
        let storage = Arc::new(SledStorage::new(dir.path()).unwrap());

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let network = NetworkClient::new_mock(cmd_tx);

        let state = ApiState {
            network,
            storage: storage.clone(),
            auth_token: "test-token-123".to_string(),
            vdf_tasks: Arc::new(Mutex::new(std::collections::HashMap::new())),
            vdf_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
        };

        let router = app(state);
        (router, cmd_rx, storage)
    }

    #[tokio::test]
    async fn test_auth_middleware_enforcement() {
        let (app, _, _) = setup_test_app().await;

        let request = Request::builder()
            .uri("/commit")
            .method("POST")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_commit_all_zero_hash_reject() {
        let (app, _, _) = setup_test_app().await;

        let req_body = serde_json::json!({
            "name": "saif.kin",
            "commitment": {
                "hash": vec![0; 32]
            }
        });

        let request = Request::builder()
            .uri("/commit")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Commitment hash must not be all-zeros"));
    }

    #[tokio::test]
    async fn test_commit_invalid_apex_domain() {
        let (app, _, _) = setup_test_app().await;

        let req_body = serde_json::json!({
            "name": "sub.saif.kin",
            "commitment": {
                "hash": vec![1; 32]
            }
        });

        let request = Request::builder()
            .uri("/commit")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Invalid domain name"));
    }

    #[tokio::test]
    async fn test_publish_invalid_apex_domain() {
        let (app, _, _) = setup_test_app().await;

        let req_body = serde_json::json!({
            "reveal": {
                "protocol_version": 2,
                "name": "sub.example.kin",
                "payload": [1, 2, 3],
                "salt": vec![0; 32],
                "drand_pulse": 100,
                "drand_randomness": "randomness",
                "iterations": 1000,
                "vdf_proof": {
                    "proof_bytes": vec![4, 5, 6]
                },
                "pubkey": vec![1; 32],
                "signature": vec![2; 64]
            }
        });

        let request = Request::builder()
            .uri("/publish")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Invalid domain name"));
    }

    #[tokio::test]
    async fn test_publish_structural_validation() {
        let (app, _, _) = setup_test_app().await;

        // Protocol version 1 (should be 2) to trigger structural validator error
        let req_body = serde_json::json!({
            "reveal": {
                "protocol_version": 1,
                "name": "validname.kin",
                "payload": [1, 2, 3],
                "salt": vec![0; 32],
                "drand_pulse": 100,
                "drand_randomness": "randomness",
                "iterations": 1000,
                "vdf_proof": {
                    "proof_bytes": vec![4, 5, 6]
                },
                "pubkey": vec![1; 32],
                "signature": vec![2; 64]
            }
        });

        let request = Request::builder()
            .uri("/publish")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Invalid Reveal"));
    }

    #[tokio::test]
    async fn test_publish_drand_staleness() {
        let (app, _, storage) = setup_test_app().await;

        // Mock current drand round to 1_000_000
        let mut mock_pulse = [0u8; 8];
        mock_pulse.copy_from_slice(&1_000_000u64.to_be_bytes());
        storage
            .put(b"kinetic_last_drand_round", &mock_pulse)
            .unwrap();

        let req_body = serde_json::json!({
            "reveal": {
                "protocol_version": 2,
                "name": "validname.kin",
                "payload": [1, 2, 3],
                "salt": vec![0; 32],
                "drand_pulse": 100, // Very old
                "drand_randomness": "randomness",
                "iterations": 1000,
                "vdf_proof": {
                    "proof_bytes": vec![4, 5, 6]
                },
                "pubkey": vec![1; 32],
                "signature": vec![2; 64]
            }
        });

        let request = Request::builder()
            .uri("/publish")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Reveal rejected: VDF pulse"));
    }

    #[tokio::test]
    async fn test_resolve_name_dht_fallback() {
        let (app, mut cmd_rx, storage) = setup_test_app().await;

        let mock_reveal = kinetic_core::types::Reveal {
            protocol_version: 2,
            name: "validname.kin".to_string(),
            payload: vec![1, 2, 3],
            salt: [0; 32],
            drand_pulse: 100,
            drand_randomness: "random".to_string(),
            iterations: 1000,
            vdf_proof: kinetic_core::types::VdfProof {
                proof_bytes: vec![],
            },
            pubkey: vec![1; 32],
            signature: vec![2; 64],
            previous_proof: None,
            miner_pubkey: None,
        };
        let reveal_key = "kinetic_reveal:validname.kin";
        storage
            .put(
                reveal_key.as_bytes(),
                &serde_json::to_vec(&mock_reveal).unwrap(),
            )
            .unwrap();

        tokio::spawn(async move {
            if let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    Command::ResolveRedundant { name, responder } => {
                        assert_eq!(&*name, "validname.kin");
                        let _ =
                            responder.send(Err(kinetic_core::error::ResolutionError::NotFound {
                                name: name.to_string(),
                                peers_queried: 3,
                            }));
                    }
                    _ => panic!("Unexpected command"),
                }
            }
        });

        let request = Request::builder()
            .uri("/resolve/validname.kin")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("validname.kin"));
    }

    #[tokio::test]
    async fn test_zone_publish_missing_registration() {
        let (app, _, _) = setup_test_app().await;

        let request = Request::builder()
            .uri("/zone/validname.kin/publish")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_concurrent_vdf_task_lock() {
        let (app, _, _) = setup_test_app().await;

        let req_body = serde_json::json!({
            "name": "testname.kin",
            "salt": vec![0; 32]
        });

        let req_body_str = req_body.to_string();

        let request1 = Request::builder()
            .uri("/vdf/register")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body_str.clone()))
            .unwrap();

        let request2 = Request::builder()
            .uri("/vdf/register")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body_str.clone()))
            .unwrap();

        let (resp1, resp2) = tokio::join!(app.clone().oneshot(request1), app.oneshot(request2));

        let s1 = resp1.unwrap().status();
        let s2 = resp2.unwrap().status();

        // One should succeed with OK, one should fail with CONFLICT
        assert!(
            (s1 == StatusCode::OK && s2 == StatusCode::CONFLICT)
                || (s1 == StatusCode::CONFLICT && s2 == StatusCode::OK)
        );
    }

    #[tokio::test]
    async fn test_publish_kid_signature_verification() {
        let (app, _, _) = setup_test_app().await;

        let req_body = serde_json::json!({
            "kid": "did:kin:12345",
            "key_type": "Ed25519",
            "public_key": "some_pubkey",
            "signature": "invalid_signature"
        });

        let request = Request::builder()
            .uri("/publish-kid")
            .method("POST")
            .header("Authorization", format!("Bearer {}", get_test_token()))
            .header("Content-Type", "application/json")
            .body(Body::from(req_body.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Since we provided totally invalid base58 encoded strings,
        // it will fail at the structure or verification level.
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
