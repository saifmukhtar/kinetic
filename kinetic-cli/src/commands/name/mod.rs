//! Name management subcommands for registering, publishing, renewing, and querying .kin names.

use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;

pub mod publish;
pub mod query;
pub mod register;
pub mod renew;
pub mod overrides;
#[cfg(test)]
mod tests;

/// Available subcommands for managing `.kin` names.
#[derive(Subcommand)]
pub enum NameCommands {
    /// Claim and register a .kin name to secure ownership
    Register {
        /// The name to register (e.g. myname.kin)
        name: String,
        /// Number of VDF iterations (difficulty)
        #[arg(short, long, default_value_t = 4_194_304)]
        iterations: u64,
    },
    /// Push your local zone.json routing configuration to the decentralized network
    Publish {
        /// The name to publish routing for (e.g. myname.kin)
        name: String,
    },
    /// Renew an existing registration with a fresh VDF proof
    Renew {
        /// The name to renew (e.g. myname.kin)
        name: String,
        /// Number of VDF iterations (difficulty)
        #[arg(short, long, default_value_t = 4_194_304)]
        iterations: u64,
    },

    /// List all .kin names you own
    List,
    /// Get status and info for a specific .kin name
    Info { name: String },
    /// Resolve a .kin name from the network
    Resolve { name: String },

    /// Publish a Fat Zone using a delegated hot key payload
    FatZone {
        /// The name to publish routing for
        name: String,
        /// Path to the Fat Zone JSON file
        #[arg(short, long)]
        file: std::path::PathBuf,
    },
    /// Save a local DNS override for a domain (bypasses DHT)
    LocalZone {
        /// The name to override locally
        name: String,
        /// Path to the JSON zone file
        #[arg(short, long)]
        file: std::path::PathBuf,
    },
    /// Delete a local DNS override
    LocalZoneDelete {
        /// The name to stop overriding locally
        name: String,
    },

    #[cfg(test)]
    Guard {
        name: String,
        rounds: usize,
        output: String,
    },
}

/// Dispatches name-related CLI subcommands.
pub async fn handle_name_command(
    cmd: NameCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    match cmd {
        NameCommands::Register { name, iterations } => {
            register::handle_name_register(name, iterations, config, client).await
        }
        NameCommands::Publish { name } => publish::handle_name_publish(name, config, client).await,
        NameCommands::Renew { name, iterations } => {
            renew::handle_name_renew(name, iterations, config, client).await
        }
        NameCommands::List => query::handle_name_list(config, client).await,
        NameCommands::Info { name } => query::handle_name_info(name, config, client).await,
        NameCommands::Resolve { name } => query::handle_name_resolve(name, config, client).await,
        NameCommands::FatZone { name, file } => {
            overrides::handle_fat_zone(name, file, config, client).await
        }
        NameCommands::LocalZone { name, file } => {
            overrides::handle_local_zone(name, file, config, client).await
        }
        NameCommands::LocalZoneDelete { name } => {
            overrides::handle_local_zone_delete(name, config, client).await
        }
        #[cfg(test)]
        NameCommands::Guard { .. } => Ok(()), // Just for tests
    }
}
