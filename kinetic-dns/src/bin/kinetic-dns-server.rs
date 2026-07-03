use anyhow::Result;
use clap::{Parser, Subcommand};
use hickory_server::ServerFuture;
use tokio::net::UdpSocket;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use std::env;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use kinetic_dns::KineticDnsHandler;

#[derive(Parser)]
#[command(name = "kinetic-dns-server", version = "0.1.0", author = "Kinetic Protocol")]
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
    Start,
    /// Start the DNS server service (background)
    StartService,
    /// Stop the DNS server service (background)
    StopService,
}

fn install_service() -> Result<()> {
    println!("Installing Kinetic DNS Server service...");
    let label: ServiceLabel = "com.kinetic.dnsserver".parse()?;
    let manager = <dyn ServiceManager>::native().expect("Failed to detect native service manager");
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["start".parse().unwrap()],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-dns-server start-service' to begin.");
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.dnsserver".parse()?;
    let manager = <dyn ServiceManager>::native().expect("Failed to detect native service manager");
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

fn start_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.dnsserver".parse()?;
    let manager = <dyn ServiceManager>::native().expect("Failed to detect native service manager");
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.dnsserver".parse()?;
    let manager = <dyn ServiceManager>::native().expect("Failed to detect native service manager");
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

            info!(
                "DNS proxy ready on {}:{} (and [::1])",
                bind_ip, dns_port
            );

            if let Err(e) = server.block_until_done().await {
                tracing::error!("DNS Server error: {:?}", e);
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

                    if let Ok(ipv6_socket) = UdpSocket::bind(format!("[::1]:{}", fallback_port)).await {
                        server.register_socket(ipv6_socket);
                    }

                    info!(
                        "DNS proxy ready (fallback) on {}:{}",
                        bind_ip, fallback_port
                    );

                    if let Err(e) = server.block_until_done().await {
                        tracing::error!("DNS Server fallback error: {:?}", e);
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
        Some(Commands::StartService) => {
            start_background_service()?;
        }
        Some(Commands::StopService) => {
            stop_background_service()?;
        }
        Some(Commands::Start) | None => {
            run_server(cli.api_url, cli.dns_port).await?;
        }
    }

    Ok(())
}
