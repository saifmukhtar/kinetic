//! # kinetic-cli
//!
//! The command-line interface for the Kinetic daemon (`kinetic-cli`).
//!
//! This binary provides an ergonomic terminal interface for interacting with a
//! locally running `kinetic-daemon`. It authenticates all requests using the
//! token stored in `~/.config/kinetic/api.token`.
//!
//! ## Command groups
//!
//! - **`identity`** — Display the local node's Peer ID and network identity.
//! - **`name`** — Register, renew, update, and transfer `.kin` domain names.
//! - **`service`** — Install, uninstall, start, and stop the daemon as a
//!   system service.

mod commands;
mod utils;

use clap::Parser;
use commands::{handle_service_command, Commands};
use kinetic_core::config::KineticConfig;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "kinetic-cli")]
#[command(about = "CLI for the Kinetic Decentralized DNS Network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let cli = Cli::parse();
    let config = KineticConfig::load();
    let client = utils::build_client(30)?;

    match cli.command {
        Commands::Name { cmd } => {
            commands::name::handle_name_command(cmd, &config, &client).await?;
        }
        Commands::Identity { cmd } => {
            commands::identity::handle_identity_command(cmd, &config, &client).await?;
        }
        Commands::Seed { cmd } => {
            commands::seed::handle_seed_command(cmd).await?;
        }
        Commands::Daemon { cmd } => {
            handle_service_command("kinetic-daemon", cmd, false).await?;
        }
        Commands::Host { cmd } => {
            handle_service_command("kinetic-host", cmd, false).await?;
        }
        Commands::Node { cmd } => {
            handle_service_command("kinetic-node", cmd, false).await?;
        }
        Commands::Dns { cmd } => {
            handle_service_command("kinetic-dns-server", cmd, true).await?;
        }
    }

    Ok(())
}
