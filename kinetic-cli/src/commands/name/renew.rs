//! Name renewal engine with cryptographic proof chaining and owner VDF difficulty discounts.

use crate::utils::parse_and_format_api_error;
use kinetic_core::config::KineticConfig;

use reqwest::Client;

use std::time::Duration;
use tracing::info;

/// Handles name renewal.
///
/// Renews an existing `.kin` name by fetching the latest Drand beacon,
/// computing a discounted VDF proof based on the previous proof, and publishing
/// the new `Reveal` to the DHT. This extends the lifespan of the registration.
///
/// # Errors
/// Returns an `anyhow::Error` if the previous reveal is not found locally,
/// keypairs don't match, or network/VDF generation steps fail.
pub async fn handle_name_renew(
    name: String,
    iterations: u64,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    info!("Starting renewal for '{}'", fqdn);

    let required_iters = kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
    let actual_iterations = std::cmp::max(iterations, required_iters);

    info!("Submitting renewal request to local Kinetic Daemon...");
    let daemon_url = format!(
        "http://{}:{}/macro/renew",
        config.daemon.bind_ip, config.daemon.api_port
    );

    let req_body = serde_json::json!({
        "name": fqdn,
        "iterations": actual_iterations,
    });

    let response = client.post(&daemon_url).json(&req_body).send().await;

    let task_id = match response {
        Ok(res) if res.status().is_success() => {
            let body: serde_json::Value = res.json().await?;
            body["task_id"].as_str().unwrap_or_default().to_string()
        }
        Ok(res) => {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            tracing::warn!(
                "{}",
                parse_and_format_api_error("Daemon error", status, &text)
            );
            return Err(anyhow::anyhow!("Daemon returned an error"));
        }
        Err(e) => {
            tracing::warn!("Failed to connect to local daemon: {}", e);
            tracing::warn!("Are you sure `kinetic-daemon` is running?");
            return Err(e.into());
        }
    };

    if task_id.is_empty() {
        return Err(anyhow::anyhow!("Daemon did not return a valid task ID"));
    }

    info!(
        "Daemon accepted the request. Tracking macro task: {}",
        task_id
    );

    let status_url = format!(
        "http://{}:{}/macro/status/{}",
        config.daemon.bind_ip, config.daemon.api_port, task_id
    );

    let mut last_progress = 0;
    let mut last_status = String::new();

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let res = match client.get(&status_url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to poll daemon status: {}", e);
                continue;
            }
        };

        if !res.status().is_success() {
            continue;
        }

        let body: serde_json::Value = res.json().await.unwrap_or_default();
        if let Some(err) = body.get("error") {
            if err.is_string() {
                tracing::warn!("Task failed: {}", err.as_str().unwrap());
                return Err(anyhow::anyhow!("Task failed: {}", err.as_str().unwrap()));
            }
        }

        let status = body["status"].as_str().unwrap_or("Unknown").to_string();
        let progress = body["progress"].as_u64().unwrap_or(0);

        if status != last_status || progress != last_progress {
            info!("[{}] Progress: {}% - {}", task_id, progress, status);
            last_status = status.clone();
            last_progress = progress;
        }

        if status == "Complete" {
            info!(
                "Success! {} has been completely renewed by the Daemon.",
                fqdn
            );
            break;
        } else if status == "Failed" {
            let err_msg = body["error"].as_str().unwrap_or("Unknown error");
            tracing::warn!("Daemon failed to renew {}: {}", fqdn, err_msg);
            return Err(anyhow::anyhow!("Renewal failed"));
        }
    }

    Ok(())
}
