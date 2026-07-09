pub mod identity;
pub mod name;
pub mod seed;
pub mod service;

use clap::Subcommand;
pub use service::handle_service_command;

#[derive(Subcommand)]
pub enum Commands {
    /// Domain name operations (register, publish, guard, etc.)
    Name {
        #[command(subcommand)]
        cmd: name::NameCommands,
    },
    /// Identity management for KIDs and Capability Manifests
    Identity {
        #[command(subcommand)]
        cmd: identity::IdentityCommands,
    },
    /// Generate and backup the master node seed phrase
    Seed {
        #[command(subcommand)]
        cmd: seed::SeedCommands,
    },
    /// Manage the Kinetic Daemon (P2P node + local proxy for name owners)
    Daemon {
        #[command(subcommand)]
        cmd: service::ServiceCommands,
    },
    /// Manage the Kinetic Host (website / content hosting, for VPS and homelabs)
    Host {
        #[command(subcommand)]
        cmd: service::ServiceCommands,
    },
    /// Manage the Kinetic Node (full DHT node for network contributors)
    Node {
        #[command(subcommand)]
        cmd: service::ServiceCommands,
    },
    /// Manage the Kinetic DNS Server (system-wide .kin resolution — requires root/sudo)
    Dns {
        #[command(subcommand)]
        cmd: service::ServiceCommands,
    },
}
