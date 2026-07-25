//! CLI commands for submitting, signing, and managing post-quantum Kinetic network governance proposals.

use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use kinetic_core::governance::{GovernanceAction, SignedGovernanceMessage};
use reqwest::Client;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum GovernanceCommands {
    /// Appoint a new member to the Governance Council (Requires Quorum)
    AppointMember {
        /// Hex-encoded ML-DSA-65 public key
        key: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Propose a network-wide binary update (Requires Quorum)
    UpdateBinary {
        #[arg(long, default_value = "release.json")]
        file: PathBuf,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Lock the council to prevent further membership changes (Requires Supermajority)
    LockCouncil {
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Veto an active proposal (Requires 1 Council Member)
    VetoUpdate {
        /// Hex-encoded hash of the proposal to veto
        target_hash: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Rotate the overarching Root Key (Requires Guard Signature)
    RotateRootKey {
        /// Hex-encoded ML-DSA-65 public key
        new_key: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Rotate the Guard Key (Requires Root Signature)
    RotateGuardKey {
        /// Hex-encoded ML-DSA-65 public key
        new_key: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Self-Appoint to the Council (Requires genesis bootstrap privileges)
    SelfAppointCouncilMember {
        /// Hex-encoded ML-DSA-65 public key
        candidate_key: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Remove a member from the Governance Council (Requires Quorum)
    RemoveCouncilMember {
        /// Hex-encoded ML-DSA-65 public key
        target_key: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Execute a timelocked proposal whose wait period has expired
    ExecuteTimelock {
        /// Hex-encoded hash of the timelocked proposal
        target_hash: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Grant premium namespace rights to a specific key
    GrantPremiumName {
        /// The apex name to grant
        name: String,
        /// Hex-encoded ML-DSA-65 public key
        target_pubkey: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
    /// Revoke premium namespace rights
    RevokePremiumName {
        /// The apex name to revoke
        name: String,
        #[arg(long, default_value = "~/.local/share/kinetic/identity.key")]
        signer_key: PathBuf,
    },
}

/// Processes a governance CLI command, signs the action, and publishes it to the network.
///
/// # Errors
/// Returns an `anyhow::Error` if:
/// - Target keys cannot be parsed or decoded from hex.
/// - Pre-flight validation against mirror manifest files fails.
/// - The local governance identity keypair cannot be loaded.
/// - The daemon API cannot be reached or returns an error.
/// - The governance message signature fails to generate.
pub async fn handle_governance_command(
    cmd: GovernanceCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    // Determine the signer key path and action from the command
    let (signer_key_path, action) = match cmd {
        GovernanceCommands::AppointMember { key, signer_key } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(key, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::AppointMember {
                    key: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::UpdateBinary { file, signer_key } => {
            let json_str = std::fs::read_to_string(&file).map_err(|e| {
                anyhow::anyhow!("Failed to read release JSON file {}: {}", file.display(), e)
            })?;

            #[derive(serde::Deserialize)]
            struct ReleaseJson {
                version: u64,
                manifest_hash: String,
                github_username: String,
                git_commit: String,
                git_branch: String,
                mirrors: Vec<String>,
            }

            let release: ReleaseJson = serde_json::from_str(&json_str).map_err(|e| {
                anyhow::anyhow!("Failed to parse JSON in {}: {}", file.display(), e)
            })?;

            let mut hash_bytes = [0u8; 32];
            hex::decode_to_slice(&release.manifest_hash, &mut hash_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid hex in manifest_hash: {}", e))?;

            // Pre-flight validation: check that the manifest on the mirror matches our version
            if let Some(mirror) = release.mirrors.first() {
                let manifest_url = format!("{}/manifest.json", mirror.trim_end_matches('/'));
                let response = client.get(&manifest_url).send().await.map_err(|e| {
                    anyhow::anyhow!(
                        "Pre-flight validation failed: could not fetch manifest from {}: {}",
                        manifest_url,
                        e
                    )
                })?;
                if !response.status().is_success() {
                    return Err(anyhow::anyhow!(
                        "Pre-flight validation failed: HTTP {} from {}",
                        response.status(),
                        manifest_url
                    ));
                }

                #[derive(serde::Deserialize)]
                struct ManifestJson {
                    version: u64,
                }
                let manifest: ManifestJson = response.json().await.map_err(|e| {
                    anyhow::anyhow!(
                        "Pre-flight validation failed: could not parse manifest JSON: {}",
                        e
                    )
                })?;

                if manifest.version != release.version {
                    return Err(anyhow::anyhow!("Pre-flight validation failed: release.json specifies version {}, but mirror manifest.json specifies version {}. Aborting proposal.", release.version, manifest.version));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Pre-flight validation failed: no mirrors specified in release.json"
                ));
            }

            (
                signer_key,
                GovernanceAction::UpdateBinary {
                    manifest_hash: hash_bytes,
                    version_nonce: release.version,
                    github_username: release.github_username,
                    git_commit: release.git_commit,
                    git_branch: release.git_branch,
                    mirrors: release.mirrors,
                },
            )
        }
        GovernanceCommands::LockCouncil { signer_key } => {
            (signer_key, GovernanceAction::LockCouncil)
        }
        GovernanceCommands::VetoUpdate {
            target_hash,
            signer_key,
        } => {
            let mut hash_bytes = [0u8; 32];
            hex::decode_to_slice(target_hash, &mut hash_bytes)?;
            (
                signer_key,
                GovernanceAction::VetoUpdate {
                    target_hash: hash_bytes,
                },
            )
        }
        GovernanceCommands::RotateRootKey {
            new_key,
            signer_key,
        } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(new_key, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::RotateRootKey {
                    new_key: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::RotateGuardKey {
            new_key,
            signer_key,
        } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(new_key, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::RotateGuardKey {
                    new_key: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::SelfAppointCouncilMember {
            candidate_key,
            signer_key,
        } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(candidate_key, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::SelfAppointCouncilMember {
                    candidate_key: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::RemoveCouncilMember {
            target_key,
            signer_key,
        } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(target_key, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::RemoveCouncilMember {
                    target_key: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::ExecuteTimelock {
            target_hash,
            signer_key,
        } => {
            let mut hash_bytes = [0u8; 32];
            hex::decode_to_slice(target_hash, &mut hash_bytes)?;
            (
                signer_key,
                GovernanceAction::ExecuteTimelock {
                    target_hash: hash_bytes,
                },
            )
        }
        GovernanceCommands::GrantPremiumName {
            name,
            target_pubkey,
            signer_key,
        } => {
            let mut key_bytes = [0u8; 1952];
            hex::decode_to_slice(target_pubkey, &mut key_bytes)?;
            (
                signer_key,
                GovernanceAction::GrantPremiumName {
                    name,
                    target_pubkey: key_bytes.into(),
                },
            )
        }
        GovernanceCommands::RevokePremiumName { name, signer_key } => {
            (signer_key, GovernanceAction::RevokePremiumName { name })
        }
    };

    // Replace ~ with home dir
    let expanded_path = if signer_key_path.to_string_lossy().starts_with('~') {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
        home.join(signer_key_path.to_string_lossy().trim_start_matches("~/"))
    } else {
        signer_key_path
    };

    let keypair = if expanded_path.extension().and_then(|e| e.to_str()) == Some("aes") {
        let password = rpassword::prompt_password(format!(
            "Enter AES decryption password for {}: ",
            expanded_path.display()
        ))
        .map_err(|e| anyhow::anyhow!("Failed to read password: {}", e))?;
        kinetic_core::types::load_encrypted_keypair(&expanded_path, &password)?
    } else {
        kinetic_core::types::load_keypair(expanded_path.to_str().unwrap())?
    };

    // Fetch the current governance state from Daemon API to get council size
    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/governance", config.daemon.bind_ip, port);
    let token =
        std::fs::read_to_string(kinetic_core::config::get_api_tokens_dir().join("admin.token"))?;

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token.trim()))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch governance state: HTTP {}",
            response.status()
        ));
    }

    let state_bytes = response.bytes().await?;
    let state: kinetic_core::governance::GovernanceState =
        bincode::deserialize(&state_bytes).map_err(|e| anyhow::anyhow!("Bincode error: {}", e))?;

    let timestamp_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let mut msg = SignedGovernanceMessage {
        action,
        timestamp_sec,
        council_size_at_proposal: state.active_council.len() as u32,
        signatures: Vec::new(),
    };

    let canonical = msg.to_canonical_bytes();
    use ml_dsa::signature::Signer;
    use ml_dsa::SignatureEncoding;
    let sig: ml_dsa::Signature<ml_dsa::MlDsa65> = keypair.try_sign(&canonical)?;
    msg.signatures.push(sig.to_bytes().to_vec());

    // Publish to the daemon
    let publish_url = format!(
        "http://{}:{}/publish-governance",
        config.daemon.bind_ip, port
    );
    let publish_resp = client
        .post(&publish_url)
        .header("Authorization", format!("Bearer {}", token.trim()))
        .json(&msg)
        .send()
        .await?;

    if publish_resp.status().is_success() {
        println!("Successfully published governance action to the Kinetic Network!");
    } else {
        let err_text = publish_resp.text().await?;
        println!("Failed to publish governance action: {}", err_text);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_preflight_validation_success() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version": 2}"#)
            .create_async()
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let release_path = temp_dir.path().join("release.json");
        let release_json = format!(
            r#"{{
            "version": 2,
            "manifest_hash": "671ecf284c7ade56078f3e9d187bfa579d98bf0dd2ea2f923bb10aa8abe1375b",
            "github_username": "saifmukhtar",
            "git_commit": "e4a5b6c7d8e9f0e1d2c3b4a5f6e7d8c9b0a1f2e3",
            "git_branch": "main",
            "mirrors": ["{}"]
        }}"#,
            server.url()
        );

        let mut file = File::create(&release_path).await.unwrap();
        file.write_all(release_json.as_bytes()).await.unwrap();

        let cmd = GovernanceCommands::UpdateBinary {
            file: release_path,
            signer_key: PathBuf::from("dummy_key.json"),
        };

        let client = reqwest::Client::new();
        let config = kinetic_core::config::KineticConfig::default();
        let res = handle_governance_command(cmd, &config, &client).await;

        let err_str = res.unwrap_err().to_string();
        assert!(
            !err_str.contains("Pre-flight validation failed"),
            "Pre-flight validation should have passed, but got error: {}",
            err_str
        );
    }

    #[tokio::test]
    async fn test_preflight_validation_mismatch() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version": 1}"#)
            .create_async()
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let release_path = temp_dir.path().join("release.json");
        let release_json = format!(
            r#"{{
            "version": 2,
            "manifest_hash": "671ecf284c7ade56078f3e9d187bfa579d98bf0dd2ea2f923bb10aa8abe1375b",
            "github_username": "saifmukhtar",
            "git_commit": "e4a5b6c7d8e9f0e1d2c3b4a5f6e7d8c9b0a1f2e3",
            "git_branch": "main",
            "mirrors": ["{}"]
        }}"#,
            server.url()
        );

        let mut file = File::create(&release_path).await.unwrap();
        file.write_all(release_json.as_bytes()).await.unwrap();

        let cmd = GovernanceCommands::UpdateBinary {
            file: release_path,
            signer_key: PathBuf::from("dummy_key.json"),
        };

        let client = reqwest::Client::new();
        let config = kinetic_core::config::KineticConfig::default();
        let res = handle_governance_command(cmd, &config, &client).await;

        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("Pre-flight validation failed"));
        assert!(
            err_str.contains("specifies version 2, but mirror manifest.json specifies version 1")
        );
    }
}
