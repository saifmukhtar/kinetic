//! Event loop driving the libp2p swarm, handling network commands, and processing inbound events.

/// Outbound command handlers.
pub mod command_handler;
/// The core event loop definition.
pub(crate) mod fullnode;
pub(crate) mod lightnode;
pub mod core;
/// Swarm initialization logic.
pub mod swarm_builder;
/// Inbound swarm handlers.
pub mod swarm_handler;
/// Specialized handlers.
pub mod handlers;
/// Event loop utilities.
pub mod utils;

pub use self::core::NetworkEventLoop;
