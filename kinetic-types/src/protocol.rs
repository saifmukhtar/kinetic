//! Reserved protocol names.
//!
//! Defines the static list of reserved `.kin` names used for official network 
//! infrastructure, routing, and foundational services.

/// Reserved network names for official Kinetic protocol services.
///
/// These names (e.g., `seed`, `node`, `rpc`) are strictly reserved and cannot 
/// be registered by standard users via Proof of Patience. They are allocated 
/// to ensure critical network infrastructure remains globally resolvable.
pub const PROTOCOL_NAMES: &[&str] = &[
    "seed",
    "node",
    "docs",
    "status",
    "api",
    "blog",
    "rpc",
    "foundation",
    "metrics",
];
