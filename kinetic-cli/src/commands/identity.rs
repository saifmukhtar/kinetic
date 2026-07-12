use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;
use tracing::{info, warn};

#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Create a new Kinetic Identity Document (KID) keypair and JSON file
    Create {
        #[arg(short, long, default_value = "kid.json")]
        output: String,
    },
    /// Publish a KID and/or Capability Manifest JSON file to the network
    Publish {
        #[arg(long, default_value = "kid.json")]
        kid: String,
        #[arg(long, default_value = "manifest.json")]
        manifest: String,
        /// The domain name that owns this KID (e.g. saif.kin)
        #[arg(long)]
        name: String,
    },
    /// Resolve a did:kin from the network
    Resolve { did: String },
}

pub async fn handle_identity_command(
    cmd: IdentityCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    match cmd {
        IdentityCommands::Create { output } => {
            info!("Generating new Ed25519 keypair for Kinetic Identity...");
            use rand_core::OsRng;
            let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);

            use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
            let pub_key_b64 = b64_url.encode(keypair.verifying_key().to_bytes());

            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(keypair.verifying_key().to_bytes());
            let did_str = format!("did:kin:{}", hex::encode(hasher.finalize()));

            let kid_did = kinetic_kid::did::KineticDid::new(&did_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse DID: {:?}", e))?;
            let doc = kinetic_kid::document::KidDocument {
                doc_type: "kinetic.kid.v1".to_string(),
                kid: kid_did,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs(),
                controller_keys: vec![kinetic_kid::document::ControllerKey {
                    id: format!("{}#primary", did_str),
                    key_type: "Ed25519".to_string(),
                    public_key: pub_key_b64,
                }],
                manifest: None,
                revocation_keys: vec![],
                signature: None,
            };

            let signed_doc = doc.sign(&keypair).expect("Failed to sign KID");
            let json_data = serde_json::to_string_pretty(&signed_doc)?;

            std::fs::write(&output, json_data)?;
            info!("Successfully generated KID and wrote to {}", output);
        }
        IdentityCommands::Publish {
            kid,
            manifest,
            name,
        } => {
            // Load identity keypair to sign the AuthorizedKid
            let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
            let keypair = kinetic_core::types::load_keypair(&identity_path.to_string_lossy())?;
            use ed25519_dalek::Signer;

            if std::path::Path::new(&kid).exists() {
                let data = std::fs::read_to_string(&kid)?;
                let doc: kinetic_kid::document::KidDocument = serde_json::from_str(&data)?;

                let mut auth_kid = kinetic_core::types::AuthorizedKid {
                    name: name.clone(),
                    kid_doc: doc,
                    owner_signature: vec![],
                };
                let signable = auth_kid.signable_bytes();
                auth_kid.owner_signature = keypair.sign(&signable).to_bytes().to_vec();

                let daemon_url = format!("http://127.0.0.1:{}/publish-kid", config.daemon.api_port);
                info!(
                    "Publishing AuthorizedKID {} to local daemon...",
                    auth_kid.kid_doc.kid.as_str()
                );
                let response = client.post(daemon_url).json(&auth_kid).send().await;
                match response {
                    Ok(res) if res.status().is_success() => {
                        info!("Success! KID successfully routed to DHT.")
                    }
                    Ok(res) => warn!("Daemon rejected KID: {}", res.status()),
                    Err(e) => warn!("Failed to connect to daemon: {}", e),
                }
            } else {
                info!("KID file {} not found, skipping...", kid);
            }

            if std::path::Path::new(&manifest).exists() {
                let data = std::fs::read_to_string(&manifest)?;
                let doc: kinetic_kid::manifest::CapabilityManifest = serde_json::from_str(&data)?;

                let mut auth_manifest = kinetic_core::types::AuthorizedManifest {
                    name: name.clone(),
                    manifest: doc,
                    owner_signature: vec![],
                };
                let signable = auth_manifest.signable_bytes();
                auth_manifest.owner_signature = keypair.sign(&signable).to_bytes().to_vec();

                let daemon_url = format!(
                    "http://127.0.0.1:{}/publish-manifest",
                    config.daemon.api_port
                );
                info!(
                    "Publishing Authorized Capability Manifest for KID {}...",
                    auth_manifest.manifest.kid.as_str()
                );
                let response = client.post(daemon_url).json(&auth_manifest).send().await;
                match response {
                    Ok(res) if res.status().is_success() => {
                        info!("Success! Manifest routed to DHT.")
                    }
                    Ok(res) => warn!("Daemon rejected Manifest: {}", res.status()),
                    Err(e) => warn!("Failed to connect to daemon: {}", e),
                }
            } else {
                info!("Manifest file {} not found, skipping...", manifest);
            }
        }
        IdentityCommands::Resolve { did } => {
            let daemon_url = format!(
                "http://127.0.0.1:{}/resolve-kid/{}",
                config.daemon.api_port, did
            );
            info!("Resolving {} via local daemon...", did);
            let response = client.get(daemon_url).send().await;
            match response {
                Ok(res) if res.status().is_success() => {
                    let text = res.text().await?;
                    info!("Resolved KID:\n{}", text);
                }
                Ok(res) => warn!("Daemon returned error: {}", res.status()),
                Err(e) => warn!("Failed to connect to daemon: {}", e),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        routing::{get, post},
        Router,
    };
    use std::env;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_create_identity_command() {
        let output = env::temp_dir().join(format!(
            "kid_test_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let output_str = output.to_str().unwrap().to_string();

        let cmd = IdentityCommands::Create {
            output: output_str.clone(),
        };
        let config = KineticConfig::default();
        let client = Client::new();

        let res = handle_identity_command(cmd, &config, &client).await;
        assert!(res.is_ok());

        assert!(output.exists());
        let data = std::fs::read_to_string(&output).unwrap();
        let doc: kinetic_kid::document::KidDocument = serde_json::from_str(&data).unwrap();

        assert_eq!(doc.doc_type, "kinetic.kid.v1");
        assert!(doc.kid.as_str().starts_with("did:kin:"));
        assert!(!doc.controller_keys.is_empty());
        assert!(doc.signature.is_some());

        // Edge case: test writing to invalid path
        let invalid_cmd = IdentityCommands::Create {
            output: "/invalid_path/kid.json".to_string(),
        };
        let res2 = handle_identity_command(invalid_cmd, &config, &client).await;
        assert!(res2.is_err());

        std::fs::remove_file(output).unwrap();
    }

    #[tokio::test]
    async fn test_identity_publish_and_resolve() {
        let app = Router::new()
            .route(
                "/publish-kid",
                post(|| async {
                    axum::response::Response::builder()
                        .status(200)
                        .body(axum::body::Body::empty())
                        .unwrap()
                }),
            )
            .route(
                "/resolve-kid/{did}",
                get(
                    |axum::extract::Path(did): axum::extract::Path<String>| async move {
                        if did == "did:kin:valid" {
                            axum::response::Response::builder()
                                .status(200)
                                .body(axum::body::Body::from("valid data"))
                                .unwrap()
                        } else {
                            axum::response::Response::builder()
                                .status(404)
                                .body(axum::body::Body::from("not found"))
                                .unwrap()
                        }
                    },
                ),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut config = KineticConfig::default();
        config.daemon.api_port = port;

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::new();

        // 1. Resolve valid DID
        let cmd = IdentityCommands::Resolve {
            did: "did:kin:valid".to_string(),
        };
        let res = handle_identity_command(cmd, &config, &client).await;
        assert!(res.is_ok());

        // 2. Resolve invalid DID
        let cmd2 = IdentityCommands::Resolve {
            did: "did:kin:invalid".to_string(),
        };
        let res2 = handle_identity_command(cmd2, &config, &client).await;
        assert!(res2.is_ok()); // Logs error but does not fail the process

        // 3. Publish non-existent file
        let cmd3 = IdentityCommands::Publish {
            kid: "nonexistent.json".to_string(),
            manifest: "nonexistent.json".to_string(),
            name: "test.kin".to_string(),
        };
        let res3 = handle_identity_command(cmd3, &config, &client).await;
        assert!(res3.is_ok()); // Logs skipping
    }
}
