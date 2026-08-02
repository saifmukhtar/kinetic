//! Name management subcommands for registering, publishing, renewing, and querying .kin names.

use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;

pub mod publish;
pub mod query;
pub mod register;
pub mod renew;
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

    #[cfg(test)]
    Guard {
        name: String,
        rounds: usize,
        output: String,
    },
}

/// Dispatches name-related CLI subcommands.
///
/// Handles name operations such as registration, publishing, renewal, and queries
/// by forwarding them to the corresponding handlers.
///
/// # Errors
/// Returns an `anyhow::Error` if the underlying API requests to the daemon fail,
/// or if invalid inputs are provided.
pub async fn handle_name_command(
    cmd: NameCommands,
    config: &KineticConfig,
    client: &Client,
) -> anyhow::Result<()> {
    match cmd {
        NameCommands::Register { name, iterations } => {
            register::handle(name, iterations, config, client).await
        }
        NameCommands::Publish { name } => publish::handle(name, config, client).await,
        NameCommands::Renew { name, iterations } => {
            renew::handle(name, iterations, config, client).await
        }
        NameCommands::List => query::handle_list(config, client).await,
        NameCommands::Info { name } => query::handle_info(name, config, client).await,
        NameCommands::Resolve { name } => query::handle_resolve(name, config, client).await,
        #[cfg(test)]
        NameCommands::Guard { .. } => Ok(()), // Just for tests
    }
}
