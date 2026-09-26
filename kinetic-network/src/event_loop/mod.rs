//! Event loop driving the libp2p swarm, handling network commands, and processing inbound events.

/// Outbound command handlers.
pub mod command_handler;
pub mod core;
pub(crate) mod edge;
/// Specialized handlers.
pub mod handlers;
/// The core event loop definition.
pub(crate) mod router;
/// Swarm initialization logic.
pub mod swarm_builder;
/// Inbound swarm handlers.
pub mod swarm_handler;
/// Event loop utilities.
pub mod utils;

pub use self::core::NetworkEventLoop;
