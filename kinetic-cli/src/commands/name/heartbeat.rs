use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;

#[derive(Subcommand)]
pub enum HeartbeatCommands {
    /// List all active background heartbeats managed by the daemon
    List,
    /// Manually force a heartbeat refresh for a specific name
    Trigger {
        /// The name to heartbeat
        name: String,
        /// Trigger a Fat Zone payload sync instead of a standard zone sync
        #[arg(long, default_value_t = false)]
        fat: bool,
    },
}

pub async fn handle_heartbeat(
    cmd: HeartbeatCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let base_url = format!("http://{}:{}", config.daemon.bind_ip, port);

    match cmd {
        HeartbeatCommands::List => {
            let url = format!("{}/api/v1/micro/heartbeat", base_url);
            let resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
            let json: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        HeartbeatCommands::Trigger { name, fat } => {
            let url = if fat {
                format!("{}/api/v1/micro/heartbeat/{}/fat", base_url, name)
            } else {
                format!("{}/api/v1/micro/heartbeat/{}", base_url, name)
            };

            let resp = client.post(&url).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
            }
            println!(
                "Successfully triggered {}heartbeat for '{}'.",
                if fat { "Fat Zone " } else { "" },
                name
            );
        }
    }

    Ok(())
}
