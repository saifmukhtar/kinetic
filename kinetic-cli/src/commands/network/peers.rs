use comfy_table::{Cell, Color, Table};
use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;

pub async fn handle_peers(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    pb.set_message("Fetching connected peers...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/network/peers",
        config.daemon.bind_ip, port
    );

    let resp = client.get(&url).send().await?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let json: serde_json::Value = resp.json().await?;
    let peers = json
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if peers.is_empty() {
        println!("No connected peers found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Peer ID").fg(Color::Cyan),
        Cell::new("IP Address").fg(Color::Green),
        Cell::new("Latency").fg(Color::Yellow),
    ]);

    for p in peers {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let ip = p.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
        let latency = p
            .get("latency")
            .and_then(|v| v.as_u64())
            .map(|l| format!("{}ms", l))
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![id.to_string(), ip.to_string(), latency]);
    }

    println!("\n{table}");
    Ok(())
}
