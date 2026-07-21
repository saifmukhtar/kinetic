//! Core trait abstractions and dependency inversion interfaces.
//!
//! Defines the abstract contracts for Kinetic's primary operational backends:
//! - [`VdfEngine`]: Proof evaluation and verification.
//! - [`StorageEngine`]: Key-value persistence and prefix scanning.
//! - [`GovernanceEngine`]: Protocol proposal verification and state transitions.

use crate::error::{GovernanceError, StorageError, VdfError};
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::types::{Commitment, VdfProof};

/// Abstract interface for Verifiable Delay Function (VDF) computation engines.
pub trait VdfEngine: Send + Sync {
    /// Evaluates the VDF sequentially for a given number of iterations.
    ///
    /// # Computational Note
    ///
    /// This is a CPU-intensive, sequential operation that blocks the executing thread.
    ///
    /// # Errors
    ///
    /// Returns [`VdfError`](crate::error::VdfError) if evaluation fails or is interrupted.
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError>;

    /// Instantly verifies a provided VDF proof against a challenge hash and target iteration count.
    ///
    /// # Errors
    ///
    /// Returns [`VdfError`](crate::error::VdfError) if the proof is malformed or invalid.
    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError>;
}

/// Abstract interface for local embedded database storage engines.
pub trait StorageEngine: Send + Sync {
    /// Stores a key-value byte pair, overwriting any existing entry.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`](crate::error::StorageError) if the write operation fails.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Retrieves the stored value byte vector for a given key.
    ///
    /// # Returns
    ///
    /// `Ok(Some(Bytes))` if found, `Ok(None)` if missing.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`](crate::error::StorageError) if the database query fails.
    fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError>;

    /// Removes an entry by key. A no-op if the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`](crate::error::StorageError) if the deletion fails.
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;

    /// Iterates over all key-value pairs matching a prefix byte slice up to an optional limit.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`](crate::error::StorageError) if prefix iteration encounters an error.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(
        &self,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

/// Abstract interface for protocol governance state verification and action execution.
pub trait GovernanceEngine: Send + Sync {
    /// Verifies whether a signed governance message meets threshold and timelock requirements.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError`](crate::error::GovernanceError) if signatures are invalid or proposal constraints fail.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError>;

    /// Executes a verified governance action, applying state changes and returning effects.
    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        wait_time: Option<u64>,
    ) -> Option<GovernanceEffect>;
}
