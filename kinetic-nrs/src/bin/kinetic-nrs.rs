//! Command-line service and daemon for the Kinetic DNS server.
//!
//! Intercepts `.kin` queries and resolves them via the local Kinetic daemon HTTP API,
//! while proxying all standard internet queries to upstream resolvers. Includes service management
//! (`install`, `uninstall`, `start`, `stop`) and automatic POSIX privilege dropping (`privdrop`).

use anyhow::Result;
use clap::{Parser, Subcommand};
use hickory_server::ServerFuture;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;
use tokio::net::UdpSocket;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

use kinetic_nrs::KineticDnsHandler;

#[derive(Parser)]
#[command(
    name = "kinetic-dns-server",
    version = "0.1.0",
    author = "Kinetic Protocol"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, default_value = "http://127.0.0.1:16000")]
    api_url: String,

    #[arg(long, default_value_t = 53)]
    dns_port: u16,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the DNS server as a system service
    Install,
    /// Uninstall the DNS server system service
    Uninstall,
    /// Start the DNS server (foreground)
    Run,
    /// Start the DNS server service (background)
    Start,
    /// Stop the DNS server service (background)
    Stop,
}

#[cfg(target_os = "macos")]
fn setup_macos_alias(ip: &str) {
    let status = std::process::Command::new("ifconfig")
        .args(["lo0", "alias", ip, "255.255.255.255", "up"])
        .status();

    if let Ok(s) = status {
        if !s.success() {
            tracing::warn!("Failed to create macOS loopback alias for {}", ip);
        }
    } else {
        tracing::warn!("Failed to execute ifconfig for macOS alias setup");
    }
}

#[cfg(target_os = "macos")]
fn teardown_macos_alias(ip: &str) {
    let _ = std::process::Command::new("ifconfig")
        .args(["lo0", "-alias", ip])
        .status();
}

fn configure_os_dns(dns_port: u16) -> Result<()> {
    let os = std::env::consts::OS;
    let nsp = kinetic_core::constants::NSP;
    let network_id = kinetic_core::constants::NETWORK_ID;
    let bind_ip = kinetic_core::constants::LOCAL_BIND_IP;

    if os == "linux" {
        let conf_dir = std::path::Path::new("/etc/systemd/resolved.conf.d");
        if conf_dir.exists() {
            let conf_path = conf_dir.join(format!("{}.conf", network_id));
            let content = format!(
                "[Resolve]\nDNS={}:{}\nDomains=~{}\n",
                bind_ip, dns_port, nsp
            );
            std::fs::write(&conf_path, content)?;
            println!("Wrote systemd-resolved config to {:?}", conf_path);
            let _ = std::process::Command::new("systemctl")
                .args(["restart", "systemd-resolved"])
                .status();
        }
    } else if os == "macos" {
        #[cfg(target_os = "macos")]
        setup_macos_alias(bind_ip);

        let conf_dir = std::path::Path::new("/etc/resolver");
        std::fs::create_dir_all(conf_dir).ok();
        let conf_path = conf_dir.join(nsp);
        let content = format!("nameserver {}\nport {}\n", bind_ip, dns_port);
        std::fs::write(&conf_path, content)?;
        println!("Wrote macOS resolver config to {:?}", conf_path);
    } else if os == "windows" {
        let _ = std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Add-DnsClientNrptRule -Namespace '.{}' -NameServers '{}'",
                    nsp, bind_ip
                ),
            ])
            .status();
        println!("Added Windows NRPT rule for .{}", nsp);
    }
    Ok(())
}

fn remove_os_dns() {
    let os = std::env::consts::OS;
    let nsp = kinetic_core::constants::NSP;
    let network_id = kinetic_core::constants::NETWORK_ID;

    if os == "linux" {
        let conf_path = format!("/etc/systemd/resolved.conf.d/{}.conf", network_id);
        std::fs::remove_file(&conf_path).ok();
        let _ = std::process::Command::new("systemctl")
            .args(["restart", "systemd-resolved"])
            .status();
    } else if os == "macos" {
        let conf_path = format!("/etc/resolver/{}", nsp);
        std::fs::remove_file(&conf_path).ok();
        let _bind_ip = kinetic_core::constants::LOCAL_BIND_IP;
        #[cfg(target_os = "macos")]
        teardown_macos_alias(_bind_ip);
    } else if os == "windows" {
        let _ = std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!("Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '.{}' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue", nsp)
            ])
            .status();
    }
}

fn install_service() -> Result<()> {
    println!("Installing Kinetic DNS Server service...");
    let label: ServiceLabel = format!("{}-dns", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec![
            "run".into(),
            "--dns-port".into(),
            kinetic_core::config::KineticConfig::load()
                .daemon
                .nrs_port
                .to_string()
                .into(),
        ],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    if let Err(e) = configure_os_dns(kinetic_core::config::KineticConfig::load().daemon.nrs_port) {
        println!("Warning: Failed to configure OS DNS: {}", e);
    }

    println!("Service installed successfully. Run 'kinetic-dns-server start' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-dns", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.uninstall(ServiceUninstallCtx { label })?;

    remove_os_dns();

    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-dns", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-dns", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

async fn run_server(api_url: String, nrs_port: u16) -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    info!("Starting Kinetic DNS Server");
    info!("Upstream Daemon API URL: {}", api_url);

    let dns_handler = KineticDnsHandler::new(
        api_url,
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        5354,
    );
    let mut server = ServerFuture::new(dns_handler);

    let bind_ip = kinetic_core::constants::LOCAL_BIND_IP;

    #[cfg(target_os = "macos")]
    setup_macos_alias(bind_ip);

    match UdpSocket::bind(format!("{}:{}", bind_ip, nrs_port)).await {
        Ok(socket) => {
            server.register_socket(socket);

            if let Ok(ipv6_socket) = UdpSocket::bind(format!("[::1]:{}", nrs_port)).await {
                server.register_socket(ipv6_socket);
            }

            info!("DNS proxy ready on {}:{} (and [::1])", bind_ip, nrs_port);

            #[cfg(unix)]
            {
                if let Err(e) = privdrop::PrivDrop::default()
                    .user("nobody")
                    .group("nogroup")
                    .apply()
                {
                    tracing::error!("Failed to drop privileges: {}", e);
                    std::process::exit(1);
                } else {
                    tracing::info!(
                        "Successfully dropped privileges after binding privileged port."
                    );
                }
            }

            tokio::select! {
                res = server.block_until_done() => {
                    if let Err(e) = res {
                        tracing::error!("DNS Server error: {:?}", e);
                    }
                }
                _ = kinetic_core::shutdown::shutdown_signal() => {
                    info!("Shutdown signal received. Commencing graceful shutdown...");
                }
            }

            #[cfg(target_os = "macos")]
            teardown_macos_alias(bind_ip);
        }
        Err(e) => {
            warn!(
                "Failed to bind DNS proxy to {}:{}: {}",
                bind_ip, nrs_port, e
            );
            warn!("Falling back to non-privileged port. Use sudo for native DNS interception.");
            let fallback_port = if nrs_port == 53 {
                5353
            } else {
                nrs_port + 1000
            };

            match UdpSocket::bind(format!("{}:{}", bind_ip, fallback_port)).await {
                Ok(socket) => {
                    server.register_socket(socket);

                    if let Ok(ipv6_socket) =
                        UdpSocket::bind(format!("[::1]:{}", fallback_port)).await
                    {
                        server.register_socket(ipv6_socket);
                    }

                    info!(
                        "DNS proxy ready (fallback) on {}:{}",
                        bind_ip, fallback_port
                    );

                    #[cfg(unix)]
                    {
                        if let Err(e) = privdrop::PrivDrop::default()
                            .user("nobody")
                            .group("nogroup")
                            .apply()
                        {
                            tracing::error!("Failed to drop privileges: {}", e);
                            std::process::exit(1);
                        } else {
                            tracing::info!(
                                "Successfully dropped privileges after binding fallback port."
                            );
                        }
                    }

                    tokio::select! {
                        res = server.block_until_done() => {
                            if let Err(e) = res {
                                tracing::error!("DNS Server fallback error: {:?}", e);
                            }
                        }
                        _ = kinetic_core::shutdown::shutdown_signal() => {
                            info!("Shutdown signal received. Commencing graceful shutdown...");
                        }
                    }

                    #[cfg(target_os = "macos")]
                    teardown_macos_alias(bind_ip);
                }
                Err(e2) => {
                    warn!(
                        "Failed to bind DNS proxy to fallback port {}: {}",
                        fallback_port, e2
                    );
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install) => {
            install_service()?;
        }
        Some(Commands::Uninstall) => {
            uninstall_service()?;
        }
        Some(Commands::Start) => {
            start_background_service()?;
        }
        Some(Commands::Stop) => {
            stop_background_service()?;
        }
        Some(Commands::Run) | None => {
            run_server(cli.api_url, cli.dns_port).await?;
        }
    }

    Ok(())
}
