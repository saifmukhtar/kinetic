use kinetic_core::config::KineticConfig;

pub async fn handle_atlas_sync(config: &KineticConfig, client: &reqwest::Client) -> anyhow::Result<()> {
    let token_path = kinetic_local::config::get_api_tokens_dir().join("admin.token");
    let token = std::fs::read_to_string(&token_path).unwrap_or_default();
    let auth_header = format!("Bearer {}", token.trim());

    let port = config.daemon.api_port;
    let url = format!("http://{}:{}/api/v1/micro/atlas/sync", config.daemon.bind_ip, port);
    
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(indicatif::ProgressStyle::default_spinner().template("{spinner:.blue} {msg}")?);
    pb.set_message("Triggering global Atlas index sync...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let resp = client.post(&url).header("Authorization", &auth_header).send().await?;
    
    pb.finish_and_clear();

    if !resp.status().is_success() {
        anyhow::bail!("Failed to trigger Atlas sync: {}", resp.text().await?);
    }
    
    println!("✅ Atlas global index sync triggered successfully.");
    Ok(())
}
