//! Network governance state transitions, threshold voting logic, and engine drivers.
//!
//! Controls Founder-phase bootstrap rules, Council multi-signature voting,
//! emergency vetos via the Guard key, and Over-The-Air (OTA) software update timelocks.
//!
//! ## Engine Variants
//!
//! The active engine is selected at compile time via `GOVERNANCE_MODEL` from `network.json`:
//!
//! | Engine | Signing Rule |
//! |---|---|
//! | `sovereign` | Root key signs alone |
//! | `council` | ≥50% of council |
//! | `permissionless` | No signing required (development only) |
//!
//! See `kinetic-core/src/governance/engine/` for concrete implementations.

pub mod engine;
pub mod logic;
pub mod state_io;
pub mod types;

#[cfg(test)]
mod tests;

pub use logic::*;
pub use state_io::*;
pub use types::*;
