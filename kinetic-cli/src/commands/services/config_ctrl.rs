use kinetic_core::config::KineticConfig;
use indicatif::{ProgressBar, ProgressStyle};

pub async fn handle_config(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    pb.set_message("Fetching live configuration...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/config", config.daemon.bind_ip, port);
    let resp = client.get(&url).send().await?;
    
    pb.finish_and_clear();

    if !resp.status().is_success() {
        anyhow::bail!("Failed to fetch config: {}", resp.text().await?);
    }
    
    // We print config as pretty JSON because it's too nested for a flat table
    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

pub async fn handle_dns_flush(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    pb.set_message("Flushing DNS cache...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/config/dns/flush", config.daemon.bind_ip, port);
    let resp = client.post(&url).send().await?;
    
    pb.finish_and_clear();

    if !resp.status().is_success() {
        anyhow::bail!("Failed to flush DNS: {}", resp.text().await?);
    }
    println!("✅ DNS cache flushed successfully.");
    Ok(())
}
