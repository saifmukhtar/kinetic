//! Network governance state transitions, threshold voting logic, and engine drivers.
//!
//! Controls Founder-phase bootstrap rules, Council multi-signature voting,
//! emergency vetos via the Guard key, and Over-The-Air (OTA) software update timelocks.

pub mod engine;
pub mod logic;
pub mod state_io;
pub mod types;

#[cfg(test)]
mod tests;

pub use logic::*;
pub use state_io::*;
pub use types::*;
