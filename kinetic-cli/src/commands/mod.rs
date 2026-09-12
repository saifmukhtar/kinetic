//! Command modules and CLI subcommand structure definitions.

pub mod action;
pub mod auth;
pub mod clock;
pub mod dns_tree;
pub mod identity;
pub mod name;
pub mod network;
pub mod seed;
pub mod setup;
pub mod system;
pub mod zone;

use clap::Subcommand;

/// Available subcommands for the Kinetic CLI.
#[derive(Subcommand)]
pub enum Commands {
    /// Submit proposals and manage Kinetic Network action
    Action {
        #[command(subcommand)]
        cmd: action::ActionCommands,
    },
    /// Name operations (register, publish, guard, etc.)
    Name {
        #[command(subcommand)]
        cmd: name::NameCommands,
    },
    /// Advanced Zone manipulation (fat payloads, local overrides)
    Zone {
        #[command(subcommand)]
        cmd: zone::ZoneCommands,
    },
    /// Identity management for KIDs and Capability Manifests
    Identity {
        #[command(subcommand)]
        cmd: identity::IdentityCommands,
    },
    /// Interactive configuration utility to initialize your Kinetic node
    Setup(setup::SetupCommand),
    /// Network operations (peers, status, bootstrap, action)
    Network {
        #[command(subcommand)]
        cmd: network::NetworkCommands,
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
    /// Manage third-party application authentication sessions
    Auth {
        #[command(subcommand)]
        cmd: auth::AuthCommands,
    },
    /// Manage background system services (daemon, host, node, etc.)
    System {
        #[command(subcommand)]
        cmd: system::ServicesCommand,
    },
}
