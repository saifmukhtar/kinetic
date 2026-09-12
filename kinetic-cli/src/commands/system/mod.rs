use clap::Subcommand;

pub mod config_ctrl;
pub mod executor;
pub mod health;
pub mod system_ctrl;

/// Available subcommands for managing Kinetic background services and system state.
#[derive(Subcommand)]
pub enum ServicesCommand {
    /// Manage the Kinetic Daemon (P2P node + local proxy for name owners)
    Daemon {
        #[command(subcommand)]
        cmd: executor::ServiceCommands,
    },
    /// Manage the Kinetic Host (website / content hosting, for VPS and homelabs)
    Host {
        #[command(subcommand)]
        cmd: executor::ServiceCommands,
    },
    /// Manage the Kinetic Node (full DHT node for network contributors)
    Node {
        #[command(subcommand)]
        cmd: executor::ServiceCommands,
    },
    /// Manage the Kinetic DNS Server (system-wide .kin resolution — requires root/sudo)
    Dns {
        #[command(subcommand)]
        cmd: executor::ServiceCommands,
    },
    /// Manage the Kinetic PAC Server (system-wide proxy auto-configuration)
    Pac {
        #[command(subcommand)]
        cmd: executor::ServiceCommands,
    },
    /// Check the health of the local daemon
    Health,
    /// Restart the local daemon via API
    Restart,
    /// Shutdown the local daemon via API
    Shutdown,
    /// Fetch the live configuration of the daemon
    Config,
    /// Download the local proxy's TLS Root certificate
    CaCert,
}

/// Dispatches the service lifecycle command to the appropriate binary or API.
pub async fn handle_services_command(
    cmd: ServicesCommand,
    config: &kinetic_core::config::KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    match cmd {
        ServicesCommand::Daemon { cmd } => {
            let bin = format!("{}-daemon", kinetic_core::constants::NSP);
            executor::handle_service_command(&bin, cmd, false).await
        }
        ServicesCommand::Host { cmd } => {
            let bin = format!("{}-host", kinetic_core::constants::NSP);
            executor::handle_service_command(&bin, cmd, false).await
        }
        ServicesCommand::Node { cmd } => {
            let bin = format!("{}-node", kinetic_core::constants::NSP);
            executor::handle_service_command(&bin, cmd, false).await
        }
        ServicesCommand::Dns { cmd } => {
            let bin = format!("{}-dns", kinetic_core::constants::NSP);
            executor::handle_service_command(&bin, cmd, true).await
        }
        ServicesCommand::Pac { cmd } => {
            let bin = format!("{}-pac", kinetic_core::constants::NSP);
            executor::handle_service_command(&bin, cmd, false).await
        }
        ServicesCommand::Health => health::handle_health(config, client).await,
        ServicesCommand::Restart => system_ctrl::handle_restart(config, client).await,
        ServicesCommand::Shutdown => system_ctrl::handle_shutdown(config, client).await,
        ServicesCommand::Config => config_ctrl::handle_config(config, client).await,
        ServicesCommand::CaCert => system_ctrl::handle_ca_cert(config, client).await,
    }
}
