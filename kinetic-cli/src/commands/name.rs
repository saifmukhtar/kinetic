use crate::utils::{parse_and_format_api_error, save_zone_file};
use clap::Subcommand;
use ed25519_dalek::Signer;
use kinetic_core::config::{get_zones_dir, KineticConfig};
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{load_keypair, Commitment, Reveal};
use reqwest::Client;
use serde_json::json;
use sha2::Digest;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Subcommand)]
pub enum NameCommands {
    /// Claim and register a .kin name to secure ownership
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
    /// Renew an existing registration with a fresh VDF proof
    Renew {
        /// The name to renew (e.g. myname.kin)
        name: String,
        /// Number of VDF iterations (difficulty)
        #[arg(short, long, default_value_t = 4_194_304)]
        iterations: u64,
    },
    /// Pre-sign a chain of future heartbeats to delegate to a Watchtower daemon
    Guard {
        name: String,
        #[arg(short, long, default_value_t = 10_000)]
        rounds: u64,
        #[arg(short, long, default_value = "watchtower.json")]
        output: String,
    },
    /// List all .kin names you own
    List,
    /// Get status and info for a specific .kin name
    Info { name: String },
    /// Resolve a .kin name from the network
    Resolve { name: String },
}

pub async fn update_zone_logic(
    fqdn: String,
    zone: kinetic_core::types::DnsZone,
    config: &KineticConfig,
    client: &Client,
    _display_val: String,
) -> anyhow::Result<()> {
    if !kinetic_core::types::is_valid_apex_name(&fqdn) {
        tracing::error!(
            "Invalid domain name: '{}'. You must update an apex domain.",
            fqdn
        );
        return Ok(());
    }
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = load_keypair(&identity_path.to_string_lossy())?;

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

pub async fn handle_name_command(
    cmd: NameCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    match cmd {
        NameCommands::Register { name, iterations } => {
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
            let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
            let keypair = load_keypair(&identity_path.to_string_lossy())?;
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
                .required_iterations(&fqdn, drand_data.round);
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
            let base_name = if parts.len() >= 3 && fqdn.ends_with(kinetic_core::types::DOT_TLD) {
                format!("{}{}", parts[parts.len() - 2], kinetic_core::types::DOT_TLD)
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
                    if let Ok(doc) =
                        serde_json::from_str::<kinetic_kid::document::KidDocument>(&content)
                    {
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
                hasher.update(pk_bytes);
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

                let doc = kinetic_kid::document::KidDocument {
                    doc_type: "kinetic.kid.v1".to_string(),
                    kid: did.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    controller_keys: vec![controller_key],
                    manifest: None,
                    revocation_keys: vec![],
                    signature: None,
                };

                let signed_doc = doc.sign(&kid_keypair).unwrap();

                // Save to file
                let doc_json = serde_json::to_string_pretty(&signed_doc).unwrap();
                std::fs::write(&base_kid_path, doc_json).unwrap();

                // Also save the private key for the user
                let key_path = kid_dir.join(format!("{}.key.kin", base_name));
                std::fs::write(&key_path, kid_keypair.to_bytes()).unwrap();

                info!(
                    "Automatically generated new KID for {}: {}",
                    base_name,
                    did.as_str()
                );
                did.as_str().to_string()
            } else {
                info!("Inheriting existing KID for {}: {}", fqdn, kid_str);
                kid_str
            };

            // Map the apex of the zone to this KID
            if !final_kid_str.is_empty() {
                records.insert(
                    "@".to_string(),
                    vec![kinetic_core::types::DnsRecord::KID(final_kid_str)],
                );
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
                vdf_proof: kinetic_core::types::VdfProof {
                    proof_bytes: proof.proof_bytes,
                },
                pubkey: pubkey.to_vec(),
                signature: vec![],
                previous_proof: None,
                miner_pubkey: None,
                points_spent: None,
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
        NameCommands::Publish { name } => {
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

            update_zone_logic(fqdn, zone, config, client, "ZonePublish".to_string()).await?;
        }
        NameCommands::Renew { name, iterations } => {
            let fqdn = kinetic_core::types::normalize_name(&name);
            info!("Starting renewal for '{}'", fqdn);

            let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
            let old_reveal: kinetic_core::types::Reveal = if reveal_path.exists() {
                let content = std::fs::read_to_string(&reveal_path)?;
                serde_json::from_str(&content)?
            } else {
                return Err(anyhow::anyhow!(
                    "No local reveal found for '{}'. Cannot renew.",
                    fqdn
                ));
            };

            let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
            let keypair = load_keypair(&identity_path.to_string_lossy())?;
            let pubkey = keypair.verifying_key().to_bytes();

            if old_reveal.pubkey != pubkey {
                return Err(anyhow::anyhow!(
                    "Local keypair does not match the public key in the old reveal."
                ));
            }

            info!("Fetching latest Drand entropy beacon...");
            let drand_client = kinetic_core::drand::DrandClient::new(None);
            let drand_data = drand_client.fetch_latest().await?;
            info!("Successfully fetched Drand round {}.", drand_data.round);

            let mut salt = [0u8; 32];
            getrandom::fill(&mut salt).expect("Failed to generate random salt");

            let challenge_bytes =
                hex::decode(&drand_data.randomness).unwrap_or_else(|_| vec![0u8; 32]);

            let mut hasher = sha2::Sha256::new();
            hasher.update(fqdn.as_bytes());
            hasher.update(salt);
            hasher.update(&challenge_bytes);
            hasher.update(pubkey);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            let challenge = Commitment { hash };

            info!("Broadcasting Commitment to DHT...");
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
            info!("Commitment accepted. Starting discounted VDF computation...");

            let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
            let base_iterations =
                consensus_math.required_iterations(&fqdn, drand_data.round);

            // 80% discount
            let discounted_iterations = std::cmp::max(1, base_iterations / 5);
            let actual_iterations = std::cmp::max(iterations, discounted_iterations);
            info!(
                "Using discounted iteration count: {} (base was {})",
                actual_iterations, base_iterations
            );

            let refresh_challenge = challenge.clone();
            let refresh_fqdn = fqdn.clone();
            let refresh_port = config.daemon.api_port;
            let refresh_client = client.clone();
            let refresh_handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
                loop {
                    interval.tick().await;
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

            let vdf_engine = kinetic_vdf::ChiaVdfEngine::new();
            let vdf_proof = tokio::task::spawn_blocking(move || {
                vdf_engine.evaluate(&challenge, actual_iterations)
            })
            .await??;

            refresh_handle.abort();

            let previous_proof = kinetic_core::types::PreviousProof {
                salt: old_reveal.salt,
                drand_pulse: old_reveal.drand_pulse,
                drand_randomness: old_reveal.drand_randomness.clone(),
                iterations: old_reveal.iterations,
                vdf_proof: old_reveal.vdf_proof.clone(),
                signature: old_reveal.signature.clone(),
            };

            let mut new_reveal = kinetic_core::types::Reveal {
                protocol_version: 2,
                name: fqdn.clone(),
                payload: old_reveal.payload.clone(),
                salt,
                drand_pulse: drand_data.round,
                drand_randomness: drand_data.randomness.clone(),
                iterations: actual_iterations,
                vdf_proof,
                pubkey: pubkey.to_vec(),
                signature: vec![],
                previous_proof: Some(previous_proof),
                miner_pubkey: None,
                points_spent: None,
            };

            new_reveal.signature = keypair
                .sign(&new_reveal.signable_bytes())
                .to_bytes()
                .to_vec();

            let req_body = serde_json::json!({
                "reveal": new_reveal,
            });
            let res = client
                .post(format!(
                    "http://127.0.0.1:{}/publish",
                    config.daemon.api_port
                ))
                .json(&req_body)
                .send()
                .await?;

            if res.status().is_success() {
                info!("Successfully renewed '{}'!", fqdn);
                std::fs::write(&reveal_path, serde_json::to_string_pretty(&new_reveal)?)?;
            } else {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                let msg =
                    parse_and_format_api_error("Failed to publish renewal", status, &err_text);
                return Err(anyhow::anyhow!("{}", msg));
            }
        }
        NameCommands::Guard {
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

            let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
            let keypair = load_keypair(&identity_path.to_string_lossy())?;

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
        NameCommands::List => {
            let daemon_url = format!("http://127.0.0.1:{}/owned-names", config.daemon.api_port);
            let response = client.get(&daemon_url).send().await;
            match response {
                Ok(res) if res.status().is_success() => {
                    let names: Vec<String> = res.json().await.unwrap_or_default();
                    info!("Names managed by local daemon:");
                    for name in names {
                        info!("- {}", name);
                    }
                }
                _ => {
                    warn!("Daemon unreachable or returned error. Falling back to local storage...");
                    let zones_dir = get_zones_dir();
                    if let Ok(entries) = std::fs::read_dir(&zones_dir) {
                        info!("Local names found in {}:", zones_dir.display());
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                if name.ends_with(".json") && !name.ends_with(".reveal.json") {
                                    info!("- {}", name.trim_end_matches(".json"));
                                }
                            }
                        }
                    } else {
                        info!("No local names found.");
                    }
                }
            }
        }
        NameCommands::Info { name } => {
            let fqdn = kinetic_core::types::normalize_name(&name);

            let daemon_url = format!(
                "http://127.0.0.1:{}/resolve/{}",
                config.daemon.api_port, fqdn
            );
            let resolve_res = client.get(&daemon_url).send().await;

            let mut resolved_from_network = false;
            match resolve_res {
                Ok(res) if res.status().is_success() => {
                    info!("Info for {} (Resolved from network):", fqdn);
                    let text = res.text().await.unwrap_or_default();
                    info!("{}", text);
                    resolved_from_network = true;
                }
                _ => {
                    warn!("Daemon unreachable or name not found on DHT. Falling back to local storage...");
                }
            }

            if !resolved_from_network {
                let reveal_path = get_zones_dir().join(format!("{}.reveal.json", fqdn));
                if reveal_path.exists() {
                    let content = std::fs::read_to_string(&reveal_path)?;
                    let reveal: Reveal = serde_json::from_str(&content)?;
                    info!("Info for {} (Local):", fqdn);
                    info!("  Created at Drand pulse: {}", reveal.drand_pulse);
                    info!("  VDF Iterations: {}", reveal.iterations);
                    info!("  Status: Local reveal file exists, but network resolution failed.");
                } else {
                    info!("No local info found for {}.", fqdn);
                }
            }
        }
        NameCommands::Resolve { name } => {
            let fqdn = kinetic_core::types::normalize_name(&name);
            info!("Resolving {} via local daemon...", fqdn);
            let daemon_url = format!(
                "http://127.0.0.1:{}/resolve/{}",
                config.daemon.api_port, fqdn
            );
            let resolve_res = client.get(&daemon_url).send().await;
            match resolve_res {
                Ok(res) if res.status().is_success() => {
                    let text = res.text().await?;
                    info!("Resolved data:\n{}", text);
                }
                Ok(res) => {
                    warn!("Failed to resolve: {}", res.status());
                }
                Err(e) => {
                    warn!("Daemon unreachable: {}", e);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_name_resolve_mock_api() {
        // Removed unused channel

        let app = Router::new().route(
            "/resolve/{name}",
            get(
                |axum::extract::Path(name): axum::extract::Path<String>| async move {
                    if name == "test.kin" {
                        axum::response::Response::builder()
                            .status(200)
                            .body(axum::body::Body::from("mocked data"))
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

        // Resolve successfully
        let cmd = NameCommands::Resolve {
            name: "test.kin".to_string(),
        };
        let res = handle_name_command(cmd, &config, &client).await;
        assert!(res.is_ok());

        // Resolve not found
        let cmd2 = NameCommands::Resolve {
            name: "invalid.kin".to_string(),
        };
        let res2 = handle_name_command(cmd2, &config, &client).await;
        assert!(res2.is_ok()); // Logs error but doesn't fail process
    }

    #[tokio::test]
    async fn test_name_publish_no_zone() {
        let config = KineticConfig::default();
        let client = Client::new();
        // Trying to publish a name that we haven't registered
        let cmd = NameCommands::Publish {
            name: "nonexistent.kin".to_string(),
        };
        let res = handle_name_command(cmd, &config, &client).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("No zone file found"));
    }

    #[tokio::test]
    async fn test_name_guard_generation() {
        let output = std::env::temp_dir().join(format!(
            "guard_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cmd = NameCommands::Guard {
            name: "testguard.kin".to_string(),
            rounds: 5,
            output: output.to_str().unwrap().to_string(),
        };
        let config = KineticConfig::default();
        let client = Client::new();

        let res = handle_name_command(cmd, &config, &client).await;
        assert!(res.is_ok());

        assert!(output.exists());
        let content = std::fs::read_to_string(&output).unwrap();
        let tokens: Vec<kinetic_core::types::Heartbeat> = serde_json::from_str(&content).unwrap();
        assert_eq!(tokens.len(), 5);

        std::fs::remove_file(output).unwrap();
    }
}
