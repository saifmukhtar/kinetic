use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use kinetic_core::config::{get_zones_dir, KineticConfig};
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{load_or_create_keypair, Commitment, Reveal, VdfProof};
use reqwest::Client;
use serde_json::json;
use sha2::Digest;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "kinetic-cli")]
#[command(about = "CLI for the Kinetic Decentralized DNS Network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Claim and register a .kin name to secure ownership. This generates a blank local zone.json file.
    Register {
        /// The name to register (e.g. myname.kin)
        name: String,
        /// Number of VDF iterations (difficulty)
        #[arg(short, long, default_value_t = 4_194_304)]
        iterations: u64,
    },
    /// Push your local zone.json routing configuration to the decentralized network
    Publish {
        /// The name to publish routing for (e.g. myname.kin)
        name: String,
    },

    /// Pre-sign a chain of future heartbeats to delegate to a Watchtower daemon
    GenerateWatchtower {
        name: String,
        #[arg(short, long, default_value_t = 10_000)]
        rounds: u64,
        #[arg(short, long, default_value = "watchtower.json")]
        output: String,
    },
    /// Identity management for KIDs and Capability Manifests
    Identity {
        #[command(subcommand)]
        cmd: IdentityCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create a new Kinetic Identity Document (KID) keypair and JSON file
    Create {
        #[arg(short, long, default_value = "kid.json")]
        output: String,
    },
    /// Publish a KID JSON file to the network via the local daemon
    PublishKid {
        /// Path to the kid.json file
        file: String,
    },
    /// Publish a Capability Manifest JSON file to the network
    PublishManifest {
        /// Path to the manifest.json file
        file: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cli = Cli::parse();
    let config = KineticConfig::load();
    let client = build_client(30)?;

    match cli.command {
        Commands::Register { name, iterations } => {
            let fqdn = kinetic_core::types::normalize_name(&name);

            info!(
                "Starting registration process for '{}' ({} iterations)",
                fqdn, iterations
            );

            // 1. Fetch latest Drand beacon
            info!("Fetching latest Drand entropy beacon...");
            let drand_client = kinetic_core::drand::DrandClient::new(None);
            let drand_data = drand_client.fetch_latest().await?;
            info!(
                "Successfully fetched Drand round {}. Randomness: {}",
                drand_data.round, drand_data.randomness
            );

            // 2. Generate the VDF Proof
            info!("Initializing Chia VDF Engine. Generating cryptographic proof...");
            let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();

            // Generate a random salt to prevent pre-computation attacks
            let mut salt = [0u8; 32];
            getrandom::fill(&mut salt).expect("Failed to generate random salt");

            let challenge_bytes =
                hex::decode(&drand_data.randomness).unwrap_or_else(|_| vec![0u8; 32]);

            // Construct commitment: H(name || salt || drand_randomness || pubkey)
            let keypair = load_or_create_keypair()?;
            let pubkey = keypair.verifying_key().to_bytes();

            let mut hasher = sha2::Sha256::new();
            hasher.update(fqdn.as_bytes());
            hasher.update(salt);
            hasher.update(&challenge_bytes);
            hasher.update(pubkey);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());

            let challenge = Commitment { hash };

            // Phase 4.1: POST the commitment *before* generating the VDF proof
            info!("Broadcasting Commitment to DHT (Phase 1 of 2)...");
            let commit_req = kinetic_core::types::CommitRequest {
                name: fqdn.clone(),
                commitment: challenge.clone(),
            };
            let commit_res = client
                .post(format!(
                    "http://127.0.0.1:{}/commit",
                    config.daemon.api_port
                ))
                .json(&commit_req)
                .send()
                .await?;
            if !commit_res.status().is_success() {
                let status = commit_res.status();
                let err_text = commit_res.text().await.unwrap_or_default();
                let msg =
                    parse_and_format_api_error("Failed to broadcast commitment", status, &err_text);
                return Err(anyhow::anyhow!("{}", msg));
            }
            info!("Commitment accepted. Starting VDF computation (Phase 2 of 2)...");

            let required_iterations = kinetic_core::consensus_math::ConsensusParams::default()
                .required_iterations(&fqdn, drand_data.round, &pubkey);
            let actual_iterations = std::cmp::max(iterations, required_iterations);

            if actual_iterations >= 10_000_000 {
                warn!("================================================================");
                warn!(
                    "CRITICAL WARNING: You have requested {} VDF iterations.",
                    actual_iterations
                );
                warn!("This computation may take several HOURS or DAYS to complete.");
                warn!("If you close this terminal, interrupt the process (Ctrl+C), or if your computer sleeps/restarts, ALL PROGRESS WILL BE LOST because checkpointing is not supported.");
                warn!("Please ensure your computer is plugged in and sleep mode is disabled.");
                warn!("================================================================");
                info!("Starting in 10 seconds. Press Ctrl+C NOW to cancel...");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }

            let refresh_challenge = challenge.clone();
            let refresh_fqdn = fqdn.clone();
            let refresh_port = config.daemon.api_port;
            let refresh_client = client.clone();

            // Phase 4.1.5: Spawn a background task to refresh the commitment periodically
            let refresh_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
                loop {
                    interval.tick().await; // The first tick completes immediately
                    let commit_req = kinetic_core::types::CommitRequest {
                        name: refresh_fqdn.clone(),
                        commitment: refresh_challenge.clone(),
                    };
                    let _ = refresh_client
                        .post(format!("http://127.0.0.1:{}/commit", refresh_port))
                        .json(&commit_req)
                        .send()
                        .await;
                }
            });

            // Run VDF evaluation in a blocking thread so we don't starve the async runtime
            let challenge_clone = challenge.clone();
            let actual_iterations_clone = actual_iterations;
            let proof = tokio::task::spawn_blocking(move || {
                vdf_engine.evaluate(&challenge_clone, actual_iterations_clone)
            })
            .await
            .unwrap()?;

            refresh_handle.abort();
            info!("VDF Proof successfully generated!");
            info!("Proof: {}", hex::encode(&proof.proof_bytes));

            // 3. Construct the DnsZone and auto-generate/inherit KID
            let mut records = std::collections::HashMap::new();
            
            // Check if this is a subdomain
            let parts: Vec<&str> = fqdn.split('.').collect();
            let base_name = if parts.len() >= 3 && fqdn.ends_with(".kin") {
                format!("{}.kin", parts[parts.len() - 2])
            } else {
                fqdn.clone()
            };

            let kid_dir = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("kinetic")
                .join("kids");
            std::fs::create_dir_all(&kid_dir).unwrap_or_default();

            let base_kid_path = kid_dir.join(format!("{}.json", base_name));
            let kid_str = if base_kid_path.exists() {
                // Subdomain inheriting base KID, or renewing base name
                if let Ok(content) = std::fs::read_to_string(&base_kid_path) {
                    if let Ok(doc) = serde_json::from_str::<kinetic_kid::document::KidDocument>(&content) {
                        doc.kid.as_str().to_string()
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };

            let final_kid_str = if kid_str.is_empty() {
                // Generate a new KID for this new base name
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
                let kid_keypair = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
                let pk_bytes = kid_keypair.verifying_key().to_bytes();
                let pk_b64 = b64_url.encode(pk_bytes);
                
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(&pk_bytes);
                let hash = hasher.finalize();
                let mut hex_hash = String::new();
                for byte in hash {
                    use std::fmt::Write;
                    let _ = write!(&mut hex_hash, "{:02x}", byte);
                }
                
                let did_string = format!("did:kin:{}", hex_hash);
                let did = kinetic_kid::did::KineticDid::new(&did_string).unwrap();
                let controller_key = kinetic_kid::document::ControllerKey {
                    id: format!("{}#key-1", did.as_str()),
                    key_type: "Ed25519".to_string(),
                    public_key: pk_b64,
                };
                
                let mut doc = kinetic_kid::document::KidDocument {
                    doc_type: "kinetic.kid.v1".to_string(),
                    kid: did.clone(),
                    created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                    pow_nonce: 0,
                    controller_keys: vec![controller_key],
                    manifest: None,
                    revocation_keys: vec![],
                    signature: None,
                };
                
                doc.mine_pow();
                let signed_doc = doc.sign(&kid_keypair).unwrap();
                
                // Save to file
                let doc_json = serde_json::to_string_pretty(&signed_doc).unwrap();
                std::fs::write(&base_kid_path, doc_json).unwrap();
                
                // Also save the private key for the user
                let key_path = kid_dir.join(format!("{}.key.bin", base_name));
                std::fs::write(&key_path, kid_keypair.to_bytes()).unwrap();

                info!("Automatically generated new KID for {}: {}", base_name, did.as_str());
                did.as_str().to_string()
            } else {
                info!("Inheriting existing KID for {}: {}", fqdn, kid_str);
                kid_str
            };

            // Map the apex of the zone to this KID
            if !final_kid_str.is_empty() {
                records.insert("@".to_string(), vec![kinetic_core::types::DnsRecord::KID(final_kid_str)]);
            }

            let zone = kinetic_core::types::DnsZone { records };
            let payload = serde_json::to_vec(&zone).expect("Failed to serialize DnsZone");

            let mut reveal = Reveal {
                protocol_version: 2,
                name: fqdn.clone(),
                payload,
                salt,
                drand_pulse: drand_data.round,
                drand_randomness: drand_data.randomness.clone(),
                iterations: actual_iterations,
                vdf_proof: VdfProof {
                    proof_bytes: proof.proof_bytes,
                },
                pubkey: pubkey.to_vec(),
                signature: vec![],
            };

            let signable = reveal.signable_bytes();
            reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

            // 4. Submit to local Daemon via REST API
            info!("Submitting fully signed Reveal tuple to local Kinetic Daemon...");
            let daemon_url = format!("http://127.0.0.1:{}/publish", config.daemon.api_port);

            let req_body = json!({
                "reveal": reveal,
            });

            let response = client.post(daemon_url).json(&req_body).send().await;

            match response {
                Ok(res) if res.status().is_success() => {
                    info!(
                        "Success! {} has been published to the Kinetic DHT network.",
                        fqdn
                    );
                    let _ = save_zone_file(&fqdn, &zone);
                    let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
                    let reveal_str =
                        serde_json::to_string_pretty(&reveal).expect("Failed to serialize Reveal");
                    let _ = std::fs::write(&reveal_path, reveal_str);
                    info!(
                        "Your zone configuration was saved to {}/{}.json",
                        get_zones_dir().display(),
                        fqdn
                    );
                    info!("Your reveal proof was saved to {}", reveal_path.display());
                }
                Ok(res) => {
                    warn!("Daemon returned an error: {}", res.status());
                    let status = res.status();
                    let text = res.text().await.unwrap_or_default();
                    warn!(
                        "{}",
                        parse_and_format_api_error("Publish error", status, &text)
                    );
                }
                Err(e) => {
                    warn!("Failed to connect to local daemon: {}", e);
                    warn!("Are you sure `kinetic-daemon` is running?");
                }
            }
        }
        Commands::Publish { name } => {
            let fqdn = kinetic_core::types::normalize_name(&name);
            let mut zone_file = get_zones_dir();
            zone_file.push(format!("{}.json", fqdn));

            if !zone_file.exists() {
                return Err(anyhow::anyhow!(
                    "No zone file found at {}. Please create it or run 'register' first.",
                    zone_file.display()
                ));
            }

            let file_contents = std::fs::read_to_string(&zone_file)?;
            let zone: kinetic_core::types::DnsZone =
                serde_json::from_str(&file_contents).map_err(|e| {
                    anyhow::anyhow!("Invalid DnsZone JSON in {}: {}", zone_file.display(), e)
                })?;

            update_zone_logic(fqdn, zone, &config, "ZonePublish".to_string()).await?;
        }

        Commands::GenerateWatchtower {
            name,
            rounds,
            output,
        } => {
            let fqdn = kinetic_core::types::normalize_name(&name);
            info!(
                "Generating Watchtower Delegation for {}: Pre-signing {} future rounds.",
                fqdn, rounds
            );

            let drand_client = kinetic_core::drand::DrandClient::new(None);
            let drand_data = drand_client.fetch_latest().await?;

            let keypair = load_or_create_keypair()?;

            let mut tokens = Vec::new();
            for i in 1..=rounds {
                let target_round = drand_data.round + i;
                let mut hb = kinetic_core::types::Heartbeat {
                    name: fqdn.clone(),
                    latest_drand_pulse: target_round,
                    signature: vec![],
                };
                hb.signature = keypair.sign(&hb.signable_bytes()).to_bytes().to_vec();
                tokens.push(hb);
            }

            let json_data = serde_json::to_string_pretty(&tokens)?;
            std::fs::write(&output, json_data)?;
            info!(
                "Successfully wrote {} watchtower tokens to {}.",
                rounds, output
            );
            info!("A Watchtower daemon can now load this file to maintain your name.");
        }
        Commands::Identity { cmd } => {
            match cmd {
                IdentityCommands::Create { output } => {
                    info!("Generating new Ed25519 keypair for Kinetic Identity...");
                    // Note: This relies on rand_core which might require adding rand_core to kinetic-cli deps
                    // We can use rand instead since kinetic-cli already has it.
                    use rand_core::OsRng;
                    let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);

                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
                    let pub_key_b64 = b64_url.encode(keypair.verifying_key().to_bytes());

                    let mut hasher = sha2::Sha256::new();
                    hasher.update(keypair.verifying_key().to_bytes());
                    let did_str = format!("did:kin:{}", hex::encode(hasher.finalize()));

                    let kid_did = kinetic_kid::KineticDid::new(&did_str)
                        .map_err(|e| anyhow::anyhow!("Failed to parse DID: {:?}", e))?;
                    let doc = kinetic_kid::KidDocument {
                        doc_type: "kinetic.kid.v1".to_string(),
                        kid: kid_did,
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs(),
                        controller_keys: vec![kinetic_kid::ControllerKey {
                            id: format!("{}#primary", did_str),
                            key_type: "Ed25519".to_string(),
                            public_key: pub_key_b64,
                        }],
                        manifest: None,
                        revocation_keys: vec![],
                        signature: None,
                        pow_nonce: 0,
                    };

                    let signed_doc = doc.sign(&keypair).expect("Failed to sign KID");
                    let json_data = serde_json::to_string_pretty(&signed_doc)?;

                    std::fs::write(&output, json_data)?;
                    info!("Successfully generated KID and wrote to {}", output);
                }
                IdentityCommands::PublishKid { file } => {
                    let data = std::fs::read_to_string(&file)?;
                    let doc: kinetic_kid::KidDocument = serde_json::from_str(&data)?;

                    let client = build_client(30)?;
                    let daemon_url =
                        format!("http://127.0.0.1:{}/publish-kid", config.daemon.api_port);

                    info!("Publishing KID {} to local daemon...", doc.kid.as_str());
                    let response = client.post(daemon_url).json(&doc).send().await;

                    match response {
                        Ok(res) if res.status().is_success() => {
                            info!("Success! KID successfully routed to DHT.")
                        }
                        Ok(res) => {
                            let status = res.status();
                            let text = res.text().await.unwrap_or_default();
                            warn!(
                                "Daemon rejected KID: {}",
                                parse_and_format_api_error("Publish KID error", status, &text)
                            );
                        }
                        Err(e) => warn!("Failed to connect to daemon: {}", e),
                    }
                }
                IdentityCommands::PublishManifest { file } => {
                    let data = std::fs::read_to_string(&file)?;
                    let manifest: kinetic_kid::CapabilityManifest = serde_json::from_str(&data)?;

                    let client = build_client(30)?;
                    let daemon_url = format!(
                        "http://127.0.0.1:{}/publish-manifest",
                        config.daemon.api_port
                    );

                    info!(
                        "Publishing Capability Manifest for KID {}...",
                        manifest.kid.as_str()
                    );
                    let response = client.post(daemon_url).json(&manifest).send().await;

                    match response {
                        Ok(res) if res.status().is_success() => {
                            info!("Success! Manifest routed to DHT.")
                        }
                        Ok(res) => {
                            let status = res.status();
                            let text = res.text().await.unwrap_or_default();
                            warn!(
                                "Daemon rejected Manifest: {}",
                                parse_and_format_api_error("Publish Manifest error", status, &text)
                            );
                        }
                        Err(e) => warn!("Failed to connect to daemon: {}", e),
                    }
                }
            }
        }
    }

    Ok(())
}

async fn update_zone_logic(
    fqdn: String,
    zone: kinetic_core::types::DnsZone,
    config: &KineticConfig,
    _display_val: String,
) -> anyhow::Result<()> {
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        tracing::error!(
            "Invalid domain name: '{}'. You must update an apex domain.",
            fqdn
        );
        return Ok(());
    }
    let keypair = load_or_create_keypair()?;
    let client = build_client(30)?;

    // Check for local reveal file first for massive UX improvement
    let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
    let mut existing_reveal: Reveal = if reveal_path.exists() {
        let content = std::fs::read_to_string(&reveal_path)?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Local reveal file corrupted: {}", e))?
    } else {
        let resolve_url = format!(
            "http://127.0.0.1:{}/resolve/{}",
            config.daemon.api_port, fqdn
        );
        let resolve_res = client.get(&resolve_url).send().await?;
        if !resolve_res.status().is_success() {
            let status = resolve_res.status();
            let text = resolve_res.text().await.unwrap_or_default();
            let msg = parse_and_format_api_error(
                "Failed to resolve existing name from DHT",
                status,
                &text,
            );
            return Err(anyhow::anyhow!("No local reveal file found, and {}", msg));
        }
        resolve_res.json().await?
    };

    let challenge_bytes =
        hex::decode(&existing_reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
    let mut hasher = sha2::Sha256::new();
    hasher.update(existing_reveal.name.as_bytes());
    hasher.update(existing_reveal.salt);
    hasher.update(&challenge_bytes);
    hasher.update(&existing_reveal.pubkey);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    let commit_res = client
        .post(format!(
            "http://127.0.0.1:{}/commit",
            config.daemon.api_port
        ))
        .json(&kinetic_core::types::CommitRequest {
            name: fqdn.clone(),
            commitment: Commitment { hash },
        })
        .send()
        .await?;
    if !commit_res.status().is_success() {
        let status = commit_res.status();
        let text = commit_res.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "{}",
            parse_and_format_api_error("Commit failed", status, &text)
        ));
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    existing_reveal.payload = serde_json::to_vec(&zone).expect("Failed to serialize DnsZone");
    let signable = existing_reveal.signable_bytes();
    existing_reveal.signature = keypair.sign(&signable).to_bytes().to_vec();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/publish",
            config.daemon.api_port
        ))
        .json(&json!({"reveal": existing_reveal}))
        .send()
        .await?;
    if response.status().is_success() {
        info!("Success! {} updated.", fqdn);
        let _ = save_zone_file(&fqdn, &zone);
        let reveal_str = serde_json::to_string_pretty(&existing_reveal)?;
        let _ = std::fs::write(&reveal_path, reveal_str);
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        warn!(
            "Daemon returned an error updating zone: {}",
            parse_and_format_api_error("Publish zone error", status, &text)
        );
    }
    Ok(())
}

fn parse_and_format_api_error(context: &str, status: reqwest::StatusCode, body: &str) -> String {
    if let Ok(api_err) = serde_json::from_str::<kinetic_core::ApiError>(body) {
        format!("[{}] {}: {}", api_err.code, context, api_err.detail)
    } else {
        format!("{}: HTTP {} - {}", context, status, body)
    }
}

fn save_zone_file(fqdn: &str, zone: &kinetic_core::types::DnsZone) -> Result<(), std::io::Error> {
    let zones_dir = get_zones_dir();
    std::fs::create_dir_all(&zones_dir)?;
    let path = zones_dir.join(format!("{}.json", fqdn));
    let json_str = serde_json::to_string_pretty(zone)?;
    std::fs::write(path, json_str)
}

fn get_api_token() -> anyhow::Result<String> {
    let path = kinetic_core::config::get_api_token_path();
    std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read API token from {}: {}. Is kinetic-daemon running?",
            path.display(),
            e
        )
    })
}

fn build_client(timeout_secs: u64) -> anyhow::Result<Client> {
    let token = get_api_token()?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?,
    );

    Ok(Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .default_headers(headers)
        .build()?)
}
