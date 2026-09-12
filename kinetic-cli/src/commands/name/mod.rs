//! Name management subcommands for registering, publishing, renewing, and querying .kin names.

use clap::Subcommand;
use kinetic_core::config::KineticConfig;
use reqwest::Client;

pub mod heartbeat;
pub mod publish;
pub mod query;
pub mod register;
pub mod renew;
pub mod reserved;
pub mod tasks;
#[cfg(test)]
mod tests;
pub mod verify;

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

    /// List network-reserved names that cannot be registered
    Reserved,
    /// Verify the quorum replication status of a name on the network
    Verify { name: String },
    /// Manage and inspect background DHT heartbeats
    Heartbeat {
        #[command(subcommand)]
        cmd: heartbeat::HeartbeatCommands,
    },
    /// View background VDF proofs and macro jobs
    Tasks,
    /// Query the VDF mining difficulty and network takeover difficulty for a name
    Difficulty {
        /// The name to check difficulty for
        name: String,
        /// How many Kyns the name has been idle (for takeover difficulty)
        #[arg(short, long)]
        kyns_idle: Option<u64>,
    },
    /// Validate a potential name string according to Kinetic's naming rules
    Validate {
        /// The raw string name to validate
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
        NameCommands::Reserved => reserved::handle_reserved(config, client).await,
        NameCommands::Verify { name } => verify::handle_verify(name, config, client).await,
        NameCommands::Heartbeat { cmd } => heartbeat::handle_heartbeat(cmd, config, client).await,
        NameCommands::Tasks => tasks::handle_tasks(config, client).await,
        NameCommands::Difficulty { name, kyns_idle } => {
            query::handle_name_difficulty(name, kyns_idle, config, client).await
        }
        NameCommands::Validate { name } => query::handle_name_validate(name, config, client).await,
        #[cfg(test)]
        NameCommands::Guard { .. } => Ok(()), // Just for tests
    }
}
