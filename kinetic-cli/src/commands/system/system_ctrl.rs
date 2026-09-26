use indicatif::{ProgressBar, ProgressStyle};
use kinetic_core::config::KineticConfig;

/// Instructs the Kinetic Daemon to execute a graceful restart cycle.
///
/// > [!WARNING]
/// > Because the daemon orchestrates critical network infrastructure, ripping the process
/// > from memory (e.g., `kill -9`) can corrupt the redb storage and abruptly drop proxy connections.
///
/// This CLI command delegates the restart logic to the Daemon via the `/api/v1/micro/system/restart`
/// endpoint, ensuring the Daemon gracefully flushes its local Kademlia DHT state to disk and cleanly
/// terminates OS-level proxy loops before spinning back up.
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
        config.peer.bind_ip, port
    );
    let resp = client.post(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "{}",
            crate::utils::parse_and_format_api_error("Daemon error", status, &text)
        );
    }
    println!("✅ Daemon restart initiated gracefully.");
    Ok(())
}

/// Instructs the Kinetic Daemon to securely and permanently halt its execution.
///
/// ### Execution Flow
/// 1. Instantiates an HTTP client with the `X-Kinetic-Token` authorization header.
/// 2. Sends an authenticated POST to `/api/v1/micro/system/shutdown`.
/// 3. The daemon acknowledges the request (HTTP 200) before initiating its internal OS teardown logic.
/// 4. The CLI reports success to the user terminal.
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
        config.peer.bind_ip, port
    );
    let resp = client.post(&url).send().await?;

    pb.finish_and_clear();

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "{}",
            crate::utils::parse_and_format_api_error("Daemon error", status, &text)
        );
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
        config.peer.bind_ip, port
    );
    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "{}",
            crate::utils::parse_and_format_api_error("Daemon error", status, &text)
        );
    }
    let cert = resp.text().await?;
    println!("{}", cert);
    Ok(())
}
