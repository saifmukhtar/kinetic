use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;

pub async fn handle_config(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    pb.set_message("Fetching live configuration...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/config",
        config.daemon.bind_ip, port
    );
    let resp = client.get(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    // We print config as pretty JSON because it's too nested for a flat table
    let json: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}
