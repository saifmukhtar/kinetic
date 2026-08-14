//! Event loop driving the libp2p swarm, handling network commands, and processing inbound events.

/// Outbound command handlers.
pub mod command_handler;
pub mod core;
/// The core event loop definition.
pub(crate) mod fullnode;
/// Specialized handlers.
pub mod handlers;
pub(crate) mod lightnode;
/// Swarm initialization logic.
pub mod swarm_builder;
/// Inbound swarm handlers.
pub mod swarm_handler;
/// Event loop utilities.
pub mod utils;

pub use self::core::NetworkEventLoop;
