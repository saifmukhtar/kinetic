use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;
use serde_json::json;
use tracing::info;

#[derive(Subcommand)]
pub enum GossipCommands {
    /// List all active gossipsub topics the local daemon is participating in
    Topics,
    /// Publish a message to a specific gossipsub topic
    Publish {
        topic: String,
        /// The JSON payload or text to publish
        message: String,
    },
    /// Subscribe to a gossipsub topic and stream live messages to the terminal
    Subscribe { topic: String },
}

pub async fn handle_gossip_command(
    cmd: GossipCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let base_url = format!("http://{}:{}", config.daemon.bind_ip, port);

    match cmd {
        GossipCommands::Topics => {
            let url = format!("{}/api/v1/micro/gossip/topics", base_url);
            let resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to list gossip topics: {}", resp.text().await?);
            }
            let json: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        GossipCommands::Publish { topic, message } => {
            // Attempt to parse message as JSON to send as properly formatted payload,
            // fallback to raw string if it's not JSON
            let payload: serde_json::Value =
                serde_json::from_str(&message).unwrap_or_else(|_| json!(message));
            let url = format!("{}/api/v1/micro/gossip/publish/{}", base_url, topic);

            let resp = client.post(&url).json(&payload).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to publish to topic: {}", resp.text().await?);
            }
            println!("Successfully published message to topic '{}'.", topic);
        }
        GossipCommands::Subscribe { topic } => {
            let url = format!("{}/api/v1/micro/gossip/subscribe/{}", base_url, topic);
            info!(
                "Subscribing to topic: {}. Waiting for live events... (Ctrl+C to stop)",
                topic
            );

            let mut resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to subscribe to topic: {}", resp.text().await?);
            }

            while let Some(chunk) = resp.chunk().await? {
                let text = String::from_utf8_lossy(&chunk);
                for line in text.lines() {
                    // SSE format sends `data: <content>`
                    if let Some(data) = line.strip_prefix("data: ") {
                        // Try to pretty-print if it's JSON
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                            println!("{}", serde_json::to_string_pretty(&parsed)?);
                        } else {
                            println!("{}", data);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
