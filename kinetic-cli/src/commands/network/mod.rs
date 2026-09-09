use clap::Subcommand;

pub mod action;
pub mod status;
pub mod peers;
pub mod banned;
pub mod bootstrap;

#[derive(Subcommand)]
pub enum NetworkCommands {
    /// Submit proposals and manage Kinetic Network governance
    Governance {
        #[command(subcommand)]
        cmd: action::ActionCommands,
    },
    /// Get Swarm/DHT networking status
    Status,
    /// List connected peers
    Peers,
    /// List banned peers and strike counts
    Banned,
    /// Force a Kademlia DHT bootstrap
    Bootstrap,
}

pub async fn handle_network_command(
    cmd: NetworkCommands,
    config: &kinetic_core::config::KineticConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    match cmd {
        NetworkCommands::Governance { cmd } => {
            action::handle_governance_command(cmd, config, client).await
        }
        NetworkCommands::Status => status::handle_status(config, client).await,
        NetworkCommands::Peers => peers::handle_peers(config, client).await,
        NetworkCommands::Banned => banned::handle_banned(config, client).await,
        NetworkCommands::Bootstrap => bootstrap::handle_bootstrap(config, client).await,
    }
}
