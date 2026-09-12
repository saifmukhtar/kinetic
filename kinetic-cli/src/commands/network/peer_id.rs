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
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let json: serde_json::Value = resp.json().await?;
    if let Some(peer_id) = json.get("peer_id").and_then(|v| v.as_str()) {
        use colored::Colorize;
        println!("🆔 Local Node Peer ID:");
        println!("   {}", peer_id.cyan().bold());
    } else {
        println!("{}", serde_json::to_string_pretty(&json)?);
    }

    Ok(())
}
