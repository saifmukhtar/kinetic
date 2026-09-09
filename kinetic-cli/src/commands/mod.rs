//! Command modules and CLI subcommand structure definitions.

pub mod auth;
pub mod crypto;
pub mod name;
pub mod network;
pub mod services;
pub mod utilities;

use clap::Subcommand;


/// Available subcommands for the Kinetic CLI.
#[derive(Subcommand)]
pub enum Commands {
    /// Name operations (register, publish, guard, etc.)
    Name {
        #[command(subcommand)]
        cmd: name::NameCommands,
    },
    /// Identity management for KIDs and Capability Manifests
    Identity {
        #[command(subcommand)]
        cmd: crypto::identity::IdentityCommands,
    },
    /// Interactive wizard to initialize your Kinetic node
    Setup(utilities::setup::SetupCommand),
    /// Network operations (peers, status, bootstrap, governance)
    Network {
        #[command(subcommand)]
        cmd: network::NetworkCommands,
    },
    /// Starts a localized bootstrap seed node.
    Seed {
        #[command(subcommand)]
        cmd: crypto::seed::SeedCommands,
    },
    /// Generates Cloudflare DNS Tree records from a list of IPs.
    DnsTree {
        #[command(subcommand)]
        cmd: utilities::dns_tree::DnsTreeCommands,
    },
    /// Displays a real-time digital clock of the Kinetic Network Time.
    Clock(utilities::clock::ClockArgs),
    /// Manage third-party application authentication sessions
    Auth {
        #[command(subcommand)]
        cmd: auth::AuthCommands,
    },
    /// Manage background system services (daemon, host, node, etc.)
    System {
        #[command(subcommand)]
        cmd: services::ServicesCommand,
    },
}
