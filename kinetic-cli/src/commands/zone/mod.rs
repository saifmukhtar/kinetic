use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;

pub mod actions;

#[derive(Subcommand)]
pub enum ZoneCommands {
    /// Publish a Fat Zone using a delegated hot key payload
    Fat {
        /// The name to publish routing for
        name: String,
        /// Path to the Fat Zone JSON file
        #[arg(short, long)]
        file: std::path::PathBuf,
    },
    /// Save a local DNS override for a domain (bypasses DHT)
    Local {
        /// The name to override locally
        name: String,
        /// Path to the JSON zone file
        #[arg(short, long)]
        file: std::path::PathBuf,
    },
    /// Delete a local DNS override
    DeleteLocal {
        /// The name to stop overriding locally
        name: String,
    },
    /// Broadcast a manual DHT heartbeat for a Fat Zone payload
    FatHeartbeat {
        /// The name of the Fat Zone
        name: String,
        /// Path to the Fat Zone Heartbeat JSON file (containing hot_key_hex and manifest)
        #[arg(short, long)]
        file: std::path::PathBuf,
    },
}

pub async fn handle_zone_command(
    cmd: ZoneCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    match cmd {
        ZoneCommands::Fat { name, file } => {
            actions::handle_fat_zone(name, file, config, client).await
        }
        ZoneCommands::FatHeartbeat { name, file } => {
            actions::handle_fat_heartbeat(name, file, config, client).await
        }
        ZoneCommands::Local { name, file } => {
            actions::handle_local_zone(name, file, config, client).await
        }
        ZoneCommands::DeleteLocal { name } => {
            actions::handle_local_zone_delete(name, config, client).await
        }
    }
}
