use crate::utils::parse_and_format_api_error;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub async fn handle_name_register(
    name: String,
    iterations: u64,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    let required_iters = kinetic_core::consensus_math::ConsensusParams::default().iterations(&fqdn);
    let actual_iterations = std::cmp::max(iterations, required_iters);

    let label = kinetic_core::types::names::extract_apex_name(&fqdn);
    let label = label
        .strip_suffix(kinetic_core::constants::NSP_SUFFIX)
        .unwrap_or(&label);

    let diff_url = format!(
        "http://{}:{}/api/v1/micro/consensus/difficulty/{}",
        config.daemon.bind_ip, config.daemon.api_port, fqdn
    );
    let mut time_str = "an unknown amount of time".to_string();
    let mut rating_str = "".to_string();

    if let Ok(res) = client.get(&diff_url).send().await
        && let Ok(json) = res.json::<serde_json::Value>().await
        && let Some(pred) = json.get("local_prediction")
    {
        if let Some(fmt) = pred.get("estimated_formatted").and_then(|v| v.as_str()) {
            time_str = fmt.to_string();
        }
        if let Some(rating) = pred.get("hardware_rating").and_then(|v| v.as_str()) {
            rating_str = format!(" (Hardware Rating: {})", rating);
        }
    }

    if !label.is_empty() && label.len() <= 6 {
        println!(
            "{}",
            "================================================================".yellow()
        );
        println!(
            "{}",
            format!(
                "CRITICAL WARNING: You are attempting to register a {}-letter name.",
                label.len()
            )
            .yellow()
            .bold()
        );
        println!(
            "{}",
            "Short names require massive VDF computations to prevent namespace hoarding.".yellow()
        );
        println!(
            "{}",
            format!(
                "This requires {} iterations and will take approximately {}{}.",
                actual_iterations, time_str, rating_str
            )
            .yellow()
        );
        println!("{}", "If your computer sleeps, restarts, or loses power during this process, ALL PROGRESS WILL BE LOST.".red().bold());
        println!(
            "{}",
            "================================================================".yellow()
        );
        println!("Starting in 15 seconds. Press Ctrl+C NOW to cancel...");
        tokio::time::sleep(Duration::from_secs(15)).await;
    } else {
        println!(
            "This name requires {} iterations and will take approximately {}{}.",
            actual_iterations, time_str, rating_str
        );
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.blue} {msg}")?);
    pb.set_message("Submitting registration request to local Kinetic Daemon...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let daemon_url = format!(
        "http://{}:{}/api/v1/macro/register",
        config.daemon.bind_ip, config.daemon.api_port
    );
    let req_body = json!({ "name": fqdn, "iterations": actual_iterations });
    let response = client.post(&daemon_url).json(&req_body).send().await;

    let task_id = match response {
        Ok(res) if res.status().is_success() => {
            let body: serde_json::Value = res.json().await?;
            body["task_id"].as_str().unwrap_or_default().to_string()
        }
        Ok(res) => {
            pb.finish_and_clear();
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            let err = parse_and_format_api_error("Daemon error", status, &text);
            anyhow::bail!("{}", err);
        }
        Err(e) => {
            pb.finish_and_clear();
            anyhow::bail!(
                "Failed to connect to local daemon: {}\nAre you sure `kinetic-daemon` is running?",
                e
            );
        }
    };

    if task_id.is_empty() {
        pb.finish_and_clear();
        anyhow::bail!("Daemon did not return a valid task ID");
    }

    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% - {msg}")?
            .progress_chars("#>-"),
    );
    pb.set_length(100);
    pb.set_message("Waiting in queue...");

    let status_url = format!(
        "http://{}:{}/api/v1/macro/status/{}",
        config.daemon.bind_ip, config.daemon.api_port, task_id
    );

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = match client.get(&status_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if !res.status().is_success() {
            continue;
        }

        let body: serde_json::Value = res.json().await.unwrap_or_default();
        if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
            pb.finish_and_clear();
            anyhow::bail!("Task failed: {}", err);
        }

        let status = body["status"].as_str().unwrap_or("Unknown").to_string();
        let progress = body["progress"].as_u64().unwrap_or(0);

        pb.set_position(progress);
        pb.set_message(status.clone());

        if status == "Complete" {
            pb.finish_with_message("Registration Complete!");
            println!(
                "✅ Success! {} has been completely registered and published.",
                fqdn
            );
            println!("Your zone and record files have been saved to your local database.");
            break;
        } else if status == "Failed" {
            pb.finish_and_clear();
            let err_msg = body["error"].as_str().unwrap_or("Unknown error");
            anyhow::bail!("Daemon failed to register {}: {}", fqdn, err_msg);
        }
    }

    Ok(())
}
