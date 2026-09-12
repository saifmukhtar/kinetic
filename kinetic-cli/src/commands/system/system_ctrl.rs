use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;

pub async fn handle_restart(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.yellow} {msg}")?);
    pb.set_message("Sending restart signal to daemon...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/system/restart",
        config.daemon.bind_ip, port
    );
    let resp = client.post(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }
    println!("✅ Daemon restart initiated gracefully.");
    Ok(())
}

pub async fn handle_shutdown(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.red} {msg}")?);
    pb.set_message("Sending shutdown signal to daemon...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/system/shutdown",
        config.daemon.bind_ip, port
    );
    let resp = client.post(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }
    println!("🛑 Daemon shutdown initiated gracefully.");
    Ok(())
}

pub async fn handle_ca_cert(
    config: &KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let port = config.daemon.api_port;
    let url = format!(
        "http://{}:{}/api/v1/micro/system/ca-cert",
        config.daemon.bind_ip, port
    );
    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{}", crate::utils::parse_and_format_api_error("Daemon error", status, &text));
    }
    let cert = resp.text().await?;
    println!("{}", cert);
    Ok(())
}
