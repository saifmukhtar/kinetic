//! Command modules and CLI subcommand structure definitions.

pub mod clock;
pub mod dns_tree;
pub mod governance;
pub mod identity;
pub mod name;
pub mod seed;
pub mod service;
pub mod setup;

use clap::Subcommand;
pub use service::handle_service_command;

/// Available subcommands for the Kinetic CLI.
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
    /// Interactive wizard to initialize your Kinetic node
    Setup(setup::SetupCommand),
    /// Submit proposals and manage Kinetic Network governance
    Governance {
        #[command(subcommand)]
        cmd: governance::GovernanceCommands,
    },
    /// Starts a localized bootstrap seed node.
    Seed {
        #[command(subcommand)]
        cmd: seed::SeedCommands,
    },
    /// Generates Cloudflare DNS Tree records from a list of IPs.
    DnsTree {
        #[command(subcommand)]
        cmd: dns_tree::DnsTreeCommands,
    },
    /// Displays a real-time digital clock of the Kinetic Network Time.
    Clock(clock::ClockArgs),
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
