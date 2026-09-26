//! Name zone routing updates and commit-reveal network publishing logic.

use kinetic_core::config::KineticConfig;
use reqwest::Client;
use tracing::info;

/// Dispatches a request to the Daemon to broadcast a routing manifest to the network.
///
/// > [!NOTE]
/// > Because the CLI itself is completely stateless and has no cryptographic identity,
/// > it cannot directly sign the routing update. It delegates this task to the Daemon,
/// > which has access to the `kinetic-local` Secure Enclave keystore.
///
/// ### Execution Flow
/// 1. **Normalization**: Ensures the target domain is properly formatted (e.g., lowercase `.kin`).
/// 2. **Delegation**: Sends an authenticated HTTP POST to `/api/v1/micro/nrs/zone/{fqdn}/publish`.
/// 3. **Daemon Processing**: The daemon reads the local zone configuration, cryptographically signs
///    it using the domain owner's private key, and injects the `Reveal` packet into the Libp2p Swarm.
/// 4. **Terminal Feedback**: The CLI waits for the HTTP 200 OK from the daemon and prints success to stdout.
///
/// # Errors
/// Returns an `anyhow::Error` if the daemon rejects the publish request (e.g., due to invalid signatures or network offline).
pub async fn handle_name_publish(
    name: String,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/nrs/zone/{}/publish",
        config.peer.bind_ip, port, fqdn
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
        anyhow::bail!(
            "{}",
            crate::utils::parse_and_format_api_error("Daemon error", status, &text)
        );
    }

    Ok(())
}
