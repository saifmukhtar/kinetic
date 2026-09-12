//! CLI commands for Kinetic Identity Document (KID) creation, post-quantum key rotation, revocation, and DHT publishing.
//! Now utilizes the secure Kinetic Daemon API for wallet management.

use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;
use serde_json::json;
use tracing::{info, warn};

/// Available subcommands for identity operations.
#[derive(Subcommand)]
pub enum IdentityCommands {
    /// Generate a new Kinetic Identity Document (KID) securely within the daemon
    Generate {
        #[arg(long)]
        base_name: String,
        #[arg(long)]
        sub_name: Option<String>,
        #[arg(long, default_value_t = true)]
        inherit_subname: bool,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// List all identities managed by the local daemon
    List,
    /// Fetch details of a specific identity from the daemon
    Info { name: String },
    /// Rotate the controller key for an identity securely within the daemon
    RotateKey { name: String },
    /// Revoke a Kinetic Identity securely within the daemon
    Revoke { name: String },
    /// Fetch the local capability manifest for an identity
    Manifest { name: String },
    /// Update the local capability manifest for an identity
    UpdateManifest {
        name: String,
        #[arg(short, long)]
        file: String,
    },
    /// Publish a KID and/or Capability Manifest JSON file to the network
    Publish {
        #[arg(long, default_value = "kid.json")]
        kid: String,
        #[arg(long, default_value = "manifest.json")]
        manifest: String,
        /// The name that owns this KID (e.g. saif.kin)
        #[arg(long)]
        name: String,
    },
    /// Resolve a did:kin from the network
    Resolve { did: String },
}

/// Dispatches identity-related CLI subcommands.
pub async fn handle_identity_command(
    cmd: IdentityCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let base_url = format!("http://{}:{}", config.daemon.bind_ip, port);

    match cmd {
        IdentityCommands::Generate {
            base_name,
            sub_name,
            inherit_subname,
            force,
        } => {
            let url = format!("{}/api/v1/micro/kid/generate", base_url);
            let payload = json!({
                "base_name": base_name,
                "sub_name": sub_name,
                "inherit_subname": inherit_subname,
                "force": force
            });
            let resp = client.post(&url).json(&payload).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!(
                    "Successfully generated identity:\n{}",
                    serde_json::to_string_pretty(&json)?
                );
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::List => {
            let url = format!("{}/api/v1/micro/kid/list", base_url);
            let resp = client.get(&url).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::Info { name } => {
            let url = format!("{}/api/v1/micro/kid/{}", base_url, name);
            let resp = client.get(&url).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::RotateKey { name } => {
            let url = format!("{}/api/v1/micro/kid/{}/rotate", base_url, name);
            let resp = client.post(&url).send().await?;
            if resp.status().is_success() {
                println!("Successfully rotated identity keys for {}.", name);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::Revoke { name } => {
            let url = format!("{}/api/v1/micro/kid/{}/revoke", base_url, name);
            let resp = client.post(&url).send().await?;
            if resp.status().is_success() {
                println!("Successfully revoked identity for {}.", name);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::Manifest { name } => {
            let url = format!("{}/api/v1/micro/kid/{}/manifest", base_url, name);
            let resp = client.get(&url).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::UpdateManifest { name, file } => {
            let data = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("Failed to read manifest file: {}", e))?;

            let payload: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Failed to parse JSON payload: {}", e))?;

            let url = format!("{}/api/v1/micro/kid/{}/manifest", base_url, name);
            let resp = client.post(&url).json(&payload).send().await?;
            if resp.status().is_success() {
                println!("Successfully updated local manifest for {}.", name);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
        IdentityCommands::Publish {
            kid,
            manifest,
            name,
        } => {
            // Retain the existing local signing behavior for Publish until the Daemon
            // exposes a direct `POST /v1/micro/kid/{name}/publish` API.
            let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
            let keypair = kinetic_local::identity::load_keypair(&identity_path)?;

            if std::path::Path::new(&kid).exists() {
                let data = std::fs::read_to_string(&kid)?;
                let doc: kinetic_kid::document::Document = serde_json::from_str(&data)?;

                let mut auth_kid = kinetic_core::types::AuthorizedKid {
                    name: name.clone(),
                    kid_doc: doc,
                    owner_signature: vec![],
                };
                let signable = auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT);
                auth_kid.owner_signature = keypair.sign(&signable);

                let daemon_url = format!("{}/api/v1/micro/kid/publish", base_url);
                info!(
                    "Publishing AuthorizedKID {} to local daemon...",
                    auth_kid.kid_doc.kid.as_str()
                );

                let response = client.post(daemon_url).json(&auth_kid).send().await?;
                if response.status().is_success() {
                    info!("Success! KID successfully routed to DHT.");
                } else {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    warn!("{}", crate::utils::parse_and_format_api_error("Daemon rejected KID", status, &text));
                }
            } else {
                warn!("KID file '{}' not found. Skipping KID publish.", kid);
            }

            if std::path::Path::new(&manifest).exists() {
                let data = std::fs::read_to_string(&manifest)?;
                let doc: kinetic_kid::manifest::Manifest = serde_json::from_str(&data)?;

                let mut auth_manifest = kinetic_core::types::AuthorizedManifest {
                    name: name.clone(),
                    manifest: doc,
                    kid_doc: None,
                    owner_signature: vec![],
                };
                let signable = auth_manifest.signable_bytes(kinetic_core::constants::NETWORK_SALT);
                auth_manifest.owner_signature = keypair.sign(&signable);

                let daemon_url = format!("{}/api/v1/micro/kid/manifest/publish", base_url);
                info!("Publishing AuthorizedManifest to local daemon...");
                let response = client.post(daemon_url).json(&auth_manifest).send().await?;
                if response.status().is_success() {
                    info!("Success! Manifest successfully routed to DHT.");
                } else {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    warn!("{}", crate::utils::parse_and_format_api_error("Daemon rejected Manifest", status, &text));
                }
            } else {
                warn!(
                    "Manifest file '{}' not found. Skipping manifest publish.",
                    manifest
                );
            }
        }
        IdentityCommands::Resolve { did } => {
            let url = format!("{}/api/v1/micro/kid/resolve/{}", base_url, did);
            let resp = client.get(&url).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests are temporarily disabled as they relied on local filesystem generation.
    // Future PR: Add HTTP mocking to test the API requests.
}
