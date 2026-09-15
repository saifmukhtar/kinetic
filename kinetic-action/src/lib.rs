//! # kinetic-action
//!
//! **Layer 4: Verification & Domain Rules**
//!
//! This crate implements the `ActionState` which defines how the network's global 
//! configurations (like prime names, infrastructure names, and Sovereign keys) are securely 
//! updated over time. It is strictly a Layer 4 crate and has no knowledge of P2P 
//! networking or higher-level asynchronous runtimes.
//!
//! ## Core Components
//!
//! - [`engine`]: Evaluates action validity based on the active network model (e.g., Sovereign or Permissionless).
//! - [`error`]: Semantic failure boundaries for action verification.
//! - [`logic`]: Core state transition functions and signature aggregation.
//! - [`traits`]: Trait definitions for action engine implementations.
//! - [`types`]: Data structures for action proposals, effects, and state tracking.

pub mod engine;
pub mod error;
pub mod logic;
pub mod traits;
pub mod types;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_additions;
