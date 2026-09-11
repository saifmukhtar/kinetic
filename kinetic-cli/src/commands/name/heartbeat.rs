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
    
    // Grab admin token
    let token_path = kinetic_local::config::get_api_tokens_dir().join("admin.token");
    let token = std::fs::read_to_string(&token_path).unwrap_or_default();
    let auth_header = format!("Bearer {}", token.trim());

    match cmd {
        HeartbeatCommands::List => {
            let url = format!("{}/api/v1/micro/heartbeat", base_url);
            let resp = client.get(&url).header("Authorization", &auth_header).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to list heartbeats: {}", resp.text().await?);
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
            
            let resp = client.post(&url).header("Authorization", &auth_header).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to trigger heartbeat for '{}': {}", name, resp.text().await?);
            }
            println!("Successfully triggered {}heartbeat for '{}'.", if fat { "Fat Zone " } else { "" }, name);
        }
    }
    
    Ok(())
}
