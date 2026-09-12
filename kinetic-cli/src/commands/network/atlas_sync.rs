use kinetic_core::config::KineticConfig;

pub async fn handle_atlas_sync(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/atlas/sync",
        config.daemon.bind_ip, port
    );

    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(indicatif::ProgressStyle::default_spinner().template("{spinner:.blue} {msg}")?);
    pb.set_message("Triggering global Atlas index sync...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let resp = client.post(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }

    println!("✅ Atlas global index sync triggered successfully.");
    Ok(())
}
