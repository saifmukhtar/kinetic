//! # kinetic-verify
//!
//! **Layer 3: Core Architecture (Validation & Rules Engine)**
//!
//! This crate provides the pure, `no_std`-compatible cryptographic verification logic 
//! for Kinetic network payloads. It strictly isolates the mathematical validation of 
//! Sovereign signatures and Proof of Patience (VDF) claims from the asynchronous 
//! P2P networking stack.
//!
//! ## Core Components
//!
//! - [`signatures`]: Implements the [`VerifySignature`](crate::signatures::VerifySignature) extension trait for strict payload and identity validation.
//! - [`error`]: Semantic boundary for translating cryptographic failures into protocol-level errors.

pub mod error;
pub mod signatures;

/// Resquaring epoch interval in KineticTime kyns (~6 months / 182.5 days at 3 seconds per kyn).
pub const RESQUARING_EPOCH_KYNS: u64 = 5_256_000;

/// Maximum allowed byte size for a name reveal payload (64 KB).
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

pub use error::SignatureVerifyError;
pub use kinetic_types::vdf::{CommitRequest, Commitment, PreviousProof, Reveal, VdfProof};
