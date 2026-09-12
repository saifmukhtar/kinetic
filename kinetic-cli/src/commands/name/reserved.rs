use kinetic_core::config::KineticConfig;

pub async fn handle_reserved(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/nrs/reserved",
        config.daemon.bind_ip, port
    );

    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let json: serde_json::Value = resp.json().await?;
    if let Some(arr) = json.as_array() {
        use colored::Colorize;
        println!("{} Reserved Names:", "🔒".bold());
        for name in arr.iter().filter_map(|v| v.as_str()) {
            println!("  - {}", name.yellow());
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&json)?);
    }

    Ok(())
}
