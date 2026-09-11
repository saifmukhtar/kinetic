//! Name zone routing updates and commit-reveal network publishing logic.

use kinetic_core::config::KineticConfig;
use reqwest::Client;
use tracing::info;

/// Handles publishing local zone configuration to the network.
///
/// Instructs the Kinetic Daemon to securely read the local zone file,
/// apply the cryptographic signature using its wallet, and publish the
/// updated NameRecord to the DHT.
///
/// # Errors
/// Returns an `anyhow::Error` if the daemon rejects the publish request.
pub async fn handle_name_publish(
    name: String,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/nrs/zone/{}/publish",
        config.daemon.bind_ip, port, fqdn
    );

    // Grab admin token for secure daemon access
    let token_path = kinetic_local::config::get_api_tokens_dir().join("admin.token");
    let token = std::fs::read_to_string(&token_path).unwrap_or_default();
    let auth_header = format!("Bearer {}", token.trim());

    info!("Instructing daemon to sign and publish zone for {}...", fqdn);
    
    let response = client
        .post(&url)
        .header("Authorization", &auth_header)
        .send()
        .await?;

    if response.status().is_success() {
        info!("Success! Zone for {} successfully published to the network.", fqdn);
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        anyhow::bail!("Daemon rejected zone publish ({}): {}", status, text);
    }

    Ok(())
}
