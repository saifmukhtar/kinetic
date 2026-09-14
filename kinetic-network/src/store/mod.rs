//! # Kinetic Kademlia Record Store
//!
//! Custom Kademlia record store for Kinetic apex state, reveals, commitments, and verification rules.
//!
//! ## Layer 4 Architecture: The Cryptographic Gatekeeper
//! This module acts as the strict boundary between the untrusted P2P swarm (Layer 4 Trunk) 
//! and the trusted local disk (`kinetic-storage`). Standard libp2p Kademlia implementations 
//! blindly write incoming network records to memory. The `KineticRecordStore` aggressively 
//! intercepts the `libp2p::kad::store::RecordStore` trait methods to run incoming payloads 
//! through our pure cryptographic rules (`verification.rs`) before persisting them.
//!
//! ## Architecture Context
//! ```text
//! [libp2p::Swarm (Gossip/Kademlia)]
//!            | (Receives untrusted DHT put_record)
//!            v
//! [kinetic-network::store::core] (Intercepts request)
//!            | 
//!            v
//! [kinetic-network::store::verification] (Validates VDFs, Signatures, Timestamps)
//!            | (If valid)
//!            v
//! [kinetic-storage::KineticStorage] (Persists to Redb/OPFS)
//! ```

/// Store constants.
pub(crate) mod constants;
/// The core store implementation.
pub mod core;
pub(crate) mod handlers;
/// Store validation logic.
pub(crate) mod verification;

#[cfg(test)]
mod handlers_tests;

#[cfg(test)]
mod verification_tests;

pub use self::core::KineticRecordStore;
