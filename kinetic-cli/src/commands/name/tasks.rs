use kinetic_core::config::KineticConfig;

pub async fn handle_tasks(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/macro/tasks",
        config.daemon.bind_ip, port
    );
    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("Failed to fetch macro tasks: {}", resp.text().await?);
    }

    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}
