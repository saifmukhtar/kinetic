use kinetic_core::config::{get_zones_dir, KineticConfig};
use reqwest::Client;
use tracing::{info, warn};
use kinetic_core::types::Reveal;

pub async fn handle_list(config: &KineticConfig, client: &Client) -> anyhow::Result<()> {
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
    Ok(())
}

pub async fn handle_info(name: String, config: &KineticConfig, client: &Client) -> anyhow::Result<()> {
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
    Ok(())
}
pub async fn handle_resolve(name: String, config: &KineticConfig, client: &Client) -> anyhow::Result<()> {
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
    Ok(())
}
