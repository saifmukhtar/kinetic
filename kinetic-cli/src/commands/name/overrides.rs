use kinetic_core::config::KineticConfig;
use std::path::PathBuf;

pub async fn handle_fat_zone(
    name: String,
    file: PathBuf,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let payload = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("Failed to read fat zone file {:?}: {}", file, e))?;
    let json_body: serde_json::Value = serde_json::from_str(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to parse fat zone JSON: {}", e))?;

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/nrs/fat-zone/{}", config.daemon.bind_ip, port, name);
    
    let resp = client.post(&url).json(&json_body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to publish fat zone: {}", resp.text().await?);
    }
    
    println!("Successfully published Fat Zone for {}", name);
    Ok(())
}

pub async fn handle_local_zone(
    name: String,
    file: PathBuf,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let payload = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("Failed to read local zone file {:?}: {}", file, e))?;
    let json_body: serde_json::Value = serde_json::from_str(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to parse local zone JSON: {}", e))?;

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/nrs/zone/local/{}", config.daemon.bind_ip, port, name);
    
    let resp = client.post(&url).json(&json_body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to save local zone override: {}", resp.text().await?);
    }
    
    println!("Successfully saved local DNS override for {}", name);
    Ok(())
}

pub async fn handle_local_zone_delete(
    name: String,
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/nrs/zone/local/{}", config.daemon.bind_ip, port, name);
    
    let resp = client.delete(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to delete local zone override: {}", resp.text().await?);
    }
    
    println!("Successfully deleted local DNS override for {}", name);
    Ok(())
}
