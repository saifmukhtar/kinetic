use kinetic_core::config::KineticConfig;
use comfy_table::{Table, Cell, Color};
use indicatif::{ProgressBar, ProgressStyle};

pub async fn handle_status(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    pb.set_message("Fetching network status...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/network/status", config.daemon.bind_ip, port);
    
    let resp = client.get(&url).send().await?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let err = resp.text().await?;
        anyhow::bail!("Failed to get network status: {}", err);
    }
    
    let json: serde_json::Value = resp.json().await?;
    
    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Metric").fg(Color::Cyan),
        Cell::new("Value").fg(Color::White),
    ]);

    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            let val_str = if v.is_string() {
                v.as_str().unwrap().to_string()
            } else if v.is_array() {
                v.as_array().unwrap().iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
            } else {
                v.to_string()
            };
            table.add_row(vec![k.to_string(), val_str]);
        }
    }

    println!("\n{table}");
    Ok(())
}
