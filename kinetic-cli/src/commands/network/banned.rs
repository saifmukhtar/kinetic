use kinetic_core::config::KineticConfig;
use comfy_table::{Table, Cell, Color};
use indicatif::{ProgressBar, ProgressStyle};

pub async fn handle_banned(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.red} {msg}")?);
    pb.set_message("Fetching banned peers...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/network/peers/banned", config.daemon.bind_ip, port);
    
    let resp = client.get(&url).send().await?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let err = resp.text().await?;
        anyhow::bail!("Failed to list banned peers: {}", err);
    }
    
    let json: serde_json::Value = resp.json().await?;
    let banned = json.as_object().cloned().unwrap_or_default();

    if banned.is_empty() {
        println!("No banned peers found. Network is healthy.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Banned Peer ID").fg(Color::Red),
        Cell::new("Strike Count").fg(Color::Yellow),
    ]);

    for (peer_id, strikes) in banned {
        let strike_count = strikes.as_u64().unwrap_or(0);
        table.add_row(vec![
            peer_id,
            strike_count.to_string(),
        ]);
    }

    println!("\n{table}");
    Ok(())
}
