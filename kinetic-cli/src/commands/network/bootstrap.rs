use comfy_table::{Cell, Color, Table};
use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;

pub async fn handle_bootstrap(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.magenta} {msg}")?);
    pb.set_message("Bootstrapping DHT and searching for peers...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/network/bootstrap",
        config.daemon.bind_ip, port
    );

    let resp = client.post(&url).send().await?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    let json: serde_json::Value = resp.json().await?;
    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Bootstrap Event").fg(Color::Magenta),
        Cell::new("Status").fg(Color::White),
    ]);

    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            let val_str = if v.is_string() {
                v.as_str().unwrap().to_string()
            } else {
                v.to_string()
            };
            table.add_row(vec![k.to_string(), val_str]);
        }
    }

    println!("✅ Kademlia DHT Bootstrap completed!\n");
    println!("{table}");
    Ok(())
}
