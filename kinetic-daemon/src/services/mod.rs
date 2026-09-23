//! Daemon background services for Gossipsub processing, name heartbeats, and network loops.
//!
//! ## Layer 8 Architecture: Asynchronous Workers
//! The `kinetic-daemon` is fundamentally divided into two halves: the synchronous HTTP REST API
//! (which handles explicit user commands) and these Asynchronous Workers (which maintain network
//! liveness in the background).
//!
//! Because the underlying `NetworkClient` channel is fully thread-safe, these workers are spawned
//! independently via `tokio::spawn` during daemon boot. They operate silently in the background
//! to refresh PoW identities (`network`), broadcast liveness (`heartbeat`), and react to emergency
//! network halts (`gossip`).

/// Gossip protocol processor service.
pub mod gossip;
/// Heartbeat broadcast and verification service.
pub mod heartbeat;
/// Network loops including PoW mining and republishing.
pub mod network;
