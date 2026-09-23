//! Thread-safe network client handle, command channel definitions, and configuration types.
//!
//! ## Layer 7 Architecture: The Thread-Safe Boundary
//! Because the `kinetic-network` Event Loop is locked to a single thread (`tokio::select!`),
//! the rest of the application (e.g. `kinetic-daemon` API handlers or background synchronizers)
//! cannot directly interact with the `libp2p::Swarm`.
//!
//! This module provides the `NetworkClient`, a completely thread-safe handle that operates
//! via bounded `tokio::sync::mpsc` channels. When an external module wants to perform a network
//! action (like broadcasting a block or fetching a DHT record), it builds a `Command` message
//! and transmits it to the isolated Event Loop.
//!
//! ## The Command Orchestrator
//! By forcing all interactions through this `Command` enum, `kinetic-network` guarantees that
//! the Libp2p Swarm never experiences deadlocks or concurrent state mutation panics.

/// Commands for the network event loop.
pub mod command;
/// Core client implementation.
pub mod core;
/// Anonymous network telemetry service.
pub mod telemetry;
/// Types used by the network client.
pub mod types;

pub use self::command::*;
pub use self::core::*;
pub use self::types::*;
/// KYN Provider entropy beacon client.
pub mod time_oracle;
