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
//! - **`setup`** — Interactive configuration utility for initial node setup.
//! - **`seed`** — Generate or restore the node's seed phrase identity.
//! - **`action`** — Submit and manage post-quantum action proposals.
//! - **`dns-tree`** — Generate Merkle DNS tree zone files for P2P bootstrapping.
//! - **`clock`** — Display the Kinetic Network Time and sync status.
//! - **`daemon` / `host` / `node` / `dns`** — Process management commands for individual Kinetic subsystems.

mod commands;
mod utils;

use clap::Parser;
use commands::Commands;
use tracing_subscriber::FmtSubscriber;

use clap::builder::styling::{AnsiColor, Effects};
use clap::builder::Styles;

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Cyan.on_default() | Effects::BOLD | Effects::UNDERLINE)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Yellow.on_default())
}

#[derive(Parser)]
#[command(name = "kinetic")]
#[command(about = "CLI for the Kinetic Decentralized DNS Network", long_about = None)]
#[command(styles = cli_styles())]
#[command(override_usage = "kinetic <COMMAND> <SUBCOMMAND>")]
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
    let config = kinetic_local::config::load_config();

    match cli.command {
        Commands::Setup(cmd) => {
            commands::setup::handle_setup_command(cmd).await?;
        }
        Commands::Action { cmd } => {
            let client = utils::build_client(30)?;
            commands::action::handle_action_command(cmd, &config, &client).await?;
        }
        Commands::Name { cmd } => {
            let client = utils::build_client(30)?;
            commands::name::handle_name_command(cmd, &config, &client).await?;
        }
        Commands::Zone { cmd } => {
            let client = utils::build_client(30)?;
            commands::zone::handle_zone_command(cmd, &config, &client).await?;
        }
        Commands::Identity { cmd } => {
            let client = utils::build_client(30)?;
            commands::identity::handle_identity_command(cmd, &config, &client).await?;
        }
        Commands::Network { cmd } => {
            let client = utils::build_client(30)?;
            commands::network::handle_network_command(cmd, &config, &client).await?;
        }
        Commands::Seed { cmd } => {
            commands::seed::handle_seed_command(cmd).await?;
        }
        Commands::DnsTree { cmd } => {
            commands::dns_tree::handle_dns_tree_command(cmd).await?;
        }
        Commands::Clock(cmd) => {
            let client = utils::build_client(30)?;
            commands::clock::handle_clock_command(cmd, &config, &client).await?;
        }
        Commands::Auth { cmd } => {
            let client = utils::build_client(30)?;
            commands::auth::handle_auth_command(cmd, &config, &client).await?;
        }
        Commands::System { cmd } => {
            let client = utils::build_client(30)?;
            commands::system::handle_services_command(cmd, &config, &client).await?;
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
