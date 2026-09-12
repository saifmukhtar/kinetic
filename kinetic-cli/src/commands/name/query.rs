use comfy_table::{Cell, Color, Table};
use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;
use kinetic_local::config::get_zones_dir;

pub async fn handle_name_list(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.blue} {msg}")?);
    pb.set_message("Fetching owned names from daemon...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let daemon_url = format!(
        "http://{}:{}/api/v1/micro/nrs/owned",
        config.daemon.bind_ip, config.daemon.api_port
    );
    let response = client.get(&daemon_url).send().await;
    pb.finish_and_clear();

    let mut names = Vec::new();
    let mut source = "Daemon API";

    match response {
        Ok(res) if res.status().is_success() => {
            names = res.json().await.unwrap_or_default();
        }
        _ => {
            source = "Local Disk (Daemon Offline)";
            let config_dir = get_zones_dir().join("config");
            if let Ok(entries) = std::fs::read_dir(&config_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str()
                        && name.ends_with(".json")
                    {
                        names.push(name.trim_end_matches(".json").to_string());
                    }
                }
            }
        }
    }

    if names.is_empty() {
        println!("No owned names found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Name").fg(Color::Cyan),
        Cell::new("Data Source").fg(Color::DarkGrey),
    ]);

    for name in names {
        table.add_row(vec![name.to_string(), source.to_string()]);
    }

    println!("\n{table}");
    Ok(())
}

pub async fn handle_name_info(
    name: String,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.blue} {msg}")?);
    pb.set_message(format!("Fetching info for {}...", fqdn));
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let daemon_url = format!(
        "http://{}:{}/api/v1/micro/nrs/resolve/{}",
        config.daemon.bind_ip, config.daemon.api_port, fqdn
    );
    let resolve_res = client.get(&daemon_url).send().await;
    pb.finish_and_clear();

    if let Ok(res) = resolve_res
        && res.status().is_success()
    {
        let json: serde_json::Value = res.json().await?;
        println!("Info for {} (Resolved from network):", fqdn);
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("Daemon unreachable or name not found on DHT. Checking local cache...");
    let record_path = get_zones_dir()
        .join("cache")
        .join(format!("{}.record.json", fqdn));
    if record_path.exists() {
        let content = std::fs::read_to_string(&record_path)?;
        let record: kinetic_core::types::NameRecord = serde_json::from_str(&content)?;

        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("Metric").fg(Color::Cyan),
            Cell::new("Value").fg(Color::White),
        ]);

        match record {
            kinetic_core::types::NameRecord::Standard(r) => {
                table.add_row(vec!["Type", "Standard"]);
                table.add_row(vec!["Created at Drand KYN", &r.kyn.to_string()]);
                table.add_row(vec!["VDF Iterations", &r.iterations.to_string()]);
            }
            kinetic_core::types::NameRecord::Prime { kyn, .. } => {
                table.add_row(vec!["Type", "Prime"]);
                table.add_row(vec!["Granted at Kyn", &kyn.to_string()]);
            }
            kinetic_core::types::NameRecord::Infra { kyn, .. } => {
                table.add_row(vec!["Type", "Infra"]);
                table.add_row(vec!["Granted at Kyn", &kyn.to_string()]);
            }
        }
        println!("\nInfo for {} (Local Cache):", fqdn);
        println!("{table}");
    } else {
        println!("No local info found for {}.", fqdn);
    }

    Ok(())
}

pub async fn handle_name_resolve(
    name: String,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.magenta} {msg}")?);
    pb.set_message(format!("Resolving {} via network...", fqdn));
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let daemon_url = format!(
        "http://{}:{}/api/v1/micro/nrs/resolve/{}",
        config.daemon.bind_ip, config.daemon.api_port, fqdn
    );
    let resolve_res = client.get(&daemon_url).send().await;
    pb.finish_and_clear();

    match resolve_res {
        Ok(res) if res.status().is_success() => {
            let json: serde_json::Value = res.json().await?;
            println!(
                "✅ Resolved data for {}:\n{}",
                fqdn,
                serde_json::to_string_pretty(&json)?
            );
        }
        Ok(res) => {
            println!("❌ Failed to resolve: {}", res.status());
        }
        Err(e) => {
            println!("❌ Daemon unreachable: {}", e);
        }
    }
    Ok(())
}

pub async fn handle_name_difficulty(
    name: String,
    kyns_idle: Option<u64>,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let port = config.daemon.api_port;

    let base_url = format!(
        "http://{}:{}/api/v1/micro/consensus/difficulty/{}",
        config.daemon.bind_ip, port, fqdn
    );
    let resp = client.get(&base_url).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let base_json: serde_json::Value = resp.json().await?;
    println!("Base Difficulty (Mining):");
    println!("{}", serde_json::to_string_pretty(&base_json)?);

    if let Some(idle) = kyns_idle {
        let takeover_url = format!(
            "http://{}:{}/api/v1/micro/consensus/takeover-difficulty/{}?kyns_idle={}",
            config.daemon.bind_ip, port, fqdn, idle
        );
        let t_resp = client.get(&takeover_url).send().await?;
        if t_resp.status().is_success() {
            let t_json: serde_json::Value = t_resp.json().await?;
            println!("\nTakeover Difficulty ({} Kyns idle):", idle);
            println!("{}", serde_json::to_string_pretty(&t_json)?);
        }
    }

    Ok(())
}

pub async fn handle_name_validate(
    name: String,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/consensus/validate",
        config.daemon.bind_ip, port
    );

    let payload = serde_json::json!({ "name": name });
    let resp = client.post(&url).json(&payload).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
