use kinetic_core::config::KineticConfig;

pub async fn handle_peer_id(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/network/peer-id",
        config.daemon.bind_ip, port
    );

    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        let err = resp.text().await?;
        anyhow::bail!("Failed to get peer ID: {}", err);
    }

    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
