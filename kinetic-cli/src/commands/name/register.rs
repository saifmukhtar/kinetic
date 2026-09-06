//! New .kin name registration engine featuring Drand entropy, two-phase commitment, and VDF proof generation.

use crate::utils::parse_and_format_api_error;
use kinetic_core::config::KineticConfig;

use reqwest::Client;
use serde_json::json;

use std::time::Duration;
use tracing::{info, warn};

/// Handles the registration of a new `.kin` name.
///
/// This involves fetching the latest Drand beacon for entropy, generating a VDF
/// proof (which can be computationally intensive), creating/inheriting a Kinetic
/// Identity Document (KID) for the name, and submitting the resulting proof
/// and zone configuration to the local daemon for DHT propagation.
///
/// # Errors
/// Returns an `anyhow::Error` if Drand fetching, proof generation, identity loading,
/// or network broadcast fails.
pub async fn handle_name_register(
    name: String,
    iterations: u64,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    info!(
        "Starting registration process for '{}' ({} iterations)",
        fqdn, iterations
    );

    let required_iters = kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
    let actual_iterations = std::cmp::max(iterations, required_iters);

    let label = kinetic_core::types::names::extract_apex_name(&fqdn);
    let label = label
        .strip_suffix(kinetic_core::constants::NSP_SUFFIX)
        .unwrap_or(&label);

    let expected_minutes = (actual_iterations as f64
        / kinetic_core::constants::BASE_ITERATIONS as f64)
        * kinetic_core::constants::TARGET_MINUTES;
    let time_str = if expected_minutes >= 1440.0 {
        format!("{:.1} days", expected_minutes / 1440.0)
    } else if expected_minutes >= 60.0 {
        format!("{:.1} hours", expected_minutes / 60.0)
    } else {
        format!("{:.0} minutes", expected_minutes)
    };

    if !label.is_empty() && label.len() <= 6 {
        warn!("================================================================");
        warn!(
            "CRITICAL WARNING: You are attempting to register a {}-letter name.",
            label.len()
        );
        warn!("Short names require massive VDF computations to prevent squatting.");
        warn!(
            "This requires {} iterations and will take approximately {} of continuous CPU time.",
            actual_iterations, time_str
        );
        warn!(
            "(Note: This expected time assumes an Intel Core i5-11400H equivalent CPU or better)."
        );
        warn!(
            "If your computer sleeps, restarts, or loses power during this process, ALL PROGRESS WILL BE LOST."
        );
        warn!("================================================================");
        info!("Starting in 15 seconds. Press Ctrl+C NOW to cancel...");
        tokio::time::sleep(Duration::from_secs(15)).await;
    } else {
        info!(
            "This name requires {} iterations and will take approximately {}.",
            actual_iterations, time_str
        );
    }

    info!("Submitting registration request to local Kinetic Daemon...");
    let daemon_url = format!(
        "http://{}:{}/macro/register",
        config.daemon.bind_ip, config.daemon.api_port
    );

    let req_body = json!({
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
            warn!(
                "{}",
                parse_and_format_api_error("Daemon error", status, &text)
            );
            return Err(anyhow::anyhow!("Daemon returned an error"));
        }
        Err(e) => {
            warn!("Failed to connect to local daemon: {}", e);
            warn!("Are you sure `kinetic-daemon` is running?");
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
                warn!("Failed to poll daemon status: {}", e);
                continue;
            }
        };

        if !res.status().is_success() {
            continue;
        }

        let body: serde_json::Value = res.json().await.unwrap_or_default();
        if let Some(err) = body.get("error") {
            if err.is_string() {
                warn!("Task failed: {}", err.as_str().unwrap());
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
                "Success! {} has been completely registered and published by the Daemon.",
                fqdn
            );
            info!("Your zone and reveal files have been saved to your local database.");
            break;
        } else if status == "Failed" {
            let err_msg = body["error"].as_str().unwrap_or("Unknown error");
            warn!("Daemon failed to register {}: {}", fqdn, err_msg);
            return Err(anyhow::anyhow!("Registration failed"));
        }
    }

    Ok(())
}
