//! Core wire-format domain models and protocol primitives.
//!
//! This module exports all shared data structures for DNS records, cryptographic identity,
//! time-stamping, infrastructure reservation, and VDF proofs.

pub mod clock;
pub mod dns;
pub mod domain;
pub mod identity;
pub mod infrastructure;
pub mod names;
pub mod vdf;

pub use clock::*;
pub use dns::*;
pub use domain::*;
pub use identity::*;
pub use infrastructure::*;
pub use names::*;
pub use vdf::*;
