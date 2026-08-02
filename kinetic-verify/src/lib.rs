//! Lightweight, no_std compatible cryptographic verification library for the Kinetic Network.
//! This crate contains the core verification logic, signatures, and data structures for Kinetic's VDF names, decoupled from the P2P networking stack.

pub mod error;


/// Resquaring epoch interval in drand rounds (~6 months / 182.5 days at 3 seconds per round).
pub const RESQUARING_EPOCH_ROUNDS: u64 = 5_256_000;
/// Maximum allowed byte size for a domain reveal payload (64 KB).
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

pub use kinetic_types::vdf::{
    CommitRequest, Commitment, PreviousProof, Reveal, VdfJobRequest, VdfProof, VdfVerifyError,
};
