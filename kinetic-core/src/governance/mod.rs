//! Network governance state transitions and engine drivers.
//!
//! Controls Sovereign-phase rules, name mappings, and emergency halts.
//!
//! ## Engine Variants
//!
//! The active engine is selected at compile time via `GOVERNANCE_MODEL` from `network.json`:
//!
//! | Engine | Signing Rule |
//! |---|---|
//! | `sovereign` | Root key signs alone |
//! | `permissionless` | Network operates in read-only mode (all governance rejected) |
//!
//! See `kinetic-core/src/governance/engine/` for concrete implementations.

pub mod engine;
pub mod logic;
pub mod persistence;
pub mod types;

#[cfg(test)]
mod tests;

pub use logic::*;
pub use persistence::*;
pub use types::*;
