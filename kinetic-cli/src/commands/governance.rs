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

    /// Lock the council to prevent further membership changes (Requires Supermajority)
    LockCouncil {
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

    /// Rotate a Council Member's Key (Requires Quorum)
    RotateCouncilMemberKey {
        /// Hex-encoded ML-DSA-65 public key of the existing member
        target_key: String,
        /// Hex-encoded ML-DSA-65 public key of the new member
        new_key: String,
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

    /// Grant premium namespace rights to a specific key
    GrantPremiumName {
        /// The apex name to grant
        name: String,
        /// Hex-encoded ML-DSA-65 public key
        target_pubkey: String,
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

        GovernanceCommands::LockCouncil { signer_key } => {
            (signer_key, GovernanceAction::LockCouncil)
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

        GovernanceCommands::RotateCouncilMemberKey {
            target_key,
            new_key,
            signer_key,
        } => {
            let mut target_key_bytes = [0u8; 1952];
            hex::decode_to_slice(target_key, &mut target_key_bytes)?;
            let mut new_key_bytes = [0u8; 1952];
            hex::decode_to_slice(new_key, &mut new_key_bytes)?;
            (
                signer_key,
                GovernanceAction::RotateCouncilMemberKey {
                    target_key: target_key_bytes.into(),
                    new_key: new_key_bytes.into(),
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

