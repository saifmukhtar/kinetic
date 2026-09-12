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

    info!(
        "Instructing daemon to sign and publish zone for {}...",
        fqdn
    );

    let response = client.post(&url).send().await?;

    if response.status().is_success() {
        info!(
            "Success! Zone for {} successfully published to the network.",
            fqdn
        );
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    Ok(())
}
