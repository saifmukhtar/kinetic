//! # kinetic
//!
//! The command-line interface for the Kinetic daemon (`kinetic`).
//!
//! This binary provides an ergonomic terminal interface for interacting with a
//! locally running `kinetic-daemon`. It authenticates all requests using the
//! token stored in `~/.local/share/kinetic/api.token`.
//!
//! ## Command groups
//!
//! - **`identity`** — Display the local node's Peer ID and network identity.
//! - **`name`** — Register, renew, update, and transfer `.kin` names.
//! - **`service`** — Install, uninstall, start, and stop the daemon as a system service.
//! - **`setup`** — Interactive setup wizard for initial node configuration.
//! - **`seed`** — Generate or restore the node's seed phrase identity.
//! - **`governance`** — Submit and manage post-quantum governance proposals.
//! - **`dns-tree`** — Generate Merkle DNS tree zone files for P2P bootstrapping.
//! - **`clock`** — Display the Kinetic Network Time and sync status.
//! - **`daemon` / `host` / `node` / `dns`** — Process management commands for individual Kinetic subsystems.

mod commands;
mod utils;

use clap::Parser;
use commands::{Commands, handle_service_command};
use kinetic_core::config::KineticConfig;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "kinetic")]
#[command(about = "CLI for the Kinetic Decentralized DNS Network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap_or(());

    let cli = Cli::parse();
    let config = KineticConfig::load();

    match cli.command {
        Commands::Setup(cmd) => {
            commands::setup::handle_setup_command(cmd).await?;
        }
        Commands::Name { cmd } => {
            let client = utils::build_client(30)?;
            commands::name::handle_name_command(cmd, &config, &client).await?;
        }
        Commands::Identity { cmd } => {
            let client = utils::build_client(30)?;
            commands::identity::handle_identity_command(cmd, &config, &client).await?;
        }
        Commands::Seed { cmd } => {
            commands::seed::handle_seed_command(cmd).await?;
        }
        Commands::Governance { cmd } => {
            let client = utils::build_client(30)?;
            commands::governance::handle_governance_command(cmd, &config, &client).await?;
        }
        Commands::DnsTree { cmd } => {
            commands::dns_tree::handle_dns_tree_command(cmd).await?;
        }
        Commands::Daemon { cmd } => {
            let bin = format!("{}-daemon", kinetic_core::constants::NETWORK_ID);
            handle_service_command(&bin, cmd, false).await?;
        }
        Commands::Host { cmd } => {
            let bin = format!("{}-host", kinetic_core::constants::NETWORK_ID);
            handle_service_command(&bin, cmd, false).await?;
        }
        Commands::Node { cmd } => {
            let bin = format!("{}-node", kinetic_core::constants::NETWORK_ID);
            handle_service_command(&bin, cmd, false).await?;
        }
        Commands::Dns { cmd } => {
            let bin = format!("{}-dns", kinetic_core::constants::NETWORK_ID);
            handle_service_command(&bin, cmd, true).await?;
        }
        Commands::Pac { cmd } => {
            let bin = format!("{}-pac", kinetic_core::constants::NETWORK_ID);
            handle_service_command(&bin, cmd, false).await?;
        }
        Commands::Clock(args) => {
            let client = utils::build_client(30)?;
            commands::clock::handle_clock_command(args, &config, &client).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        // clap's built-in debug_assert checks for conflicting arguments,
        // missing required args in definition, and structural bugs.
        Cli::command().debug_assert();
    }
}
