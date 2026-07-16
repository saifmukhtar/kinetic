use anyhow::Result;
use clap::{Parser, Subcommand};
use hickory_server::ServerFuture;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;
use tokio::net::UdpSocket;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use kinetic_dns::KineticDnsHandler;

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

fn install_service() -> Result<()> {
    println!("Installing Kinetic DNS Server service...");
    let label: ServiceLabel = format!(
        "{}.{}.dns",
        kinetic_core::constants::TLD,
        kinetic_core::constants::NETWORK_ID
    )
    .parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["run".into()],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-dns-server start' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = format!(
        "{}.{}.dns",
        kinetic_core::constants::TLD,
        kinetic_core::constants::NETWORK_ID
    )
    .parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!(
        "{}.{}.dns",
        kinetic_core::constants::TLD,
        kinetic_core::constants::NETWORK_ID
    )
    .parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!(
        "{}.{}.dns",
        kinetic_core::constants::TLD,
        kinetic_core::constants::NETWORK_ID
    )
    .parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

async fn run_server(api_url: String, dns_port: u16) -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    info!("Starting Kinetic DNS Server");
    info!("Upstream Daemon API URL: {}", api_url);

    let dns_handler = KineticDnsHandler::new(api_url);
    let mut server = ServerFuture::new(dns_handler);

    let bind_ip = if cfg!(target_os = "linux") {
        "127.0.0.2"
    } else {
        "127.0.0.1"
    };

    match UdpSocket::bind(format!("{}:{}", bind_ip, dns_port)).await {
        Ok(socket) => {
            server.register_socket(socket);

            if let Ok(ipv6_socket) = UdpSocket::bind(format!("[::1]:{}", dns_port)).await {
                server.register_socket(ipv6_socket);
            }

            info!("DNS proxy ready on {}:{} (and [::1])", bind_ip, dns_port);

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
        }
        Err(e) => {
            warn!(
                "Failed to bind DNS proxy to {}:{}: {}",
                bind_ip, dns_port, e
            );
            warn!("Falling back to non-privileged port. Use sudo for native DNS interception.");
            let fallback_port = if dns_port == 53 {
                5353
            } else {
                dns_port + 1000
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
