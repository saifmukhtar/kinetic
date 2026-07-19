use crate::error::{GovernanceError, StorageError, VdfError};
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::types::{Commitment, VdfProof};

/// Abstract trait defining the contract for any underlying VDF implementation.
pub trait VdfEngine: Send + Sync {
    /// Evaluates the VDF sequentially for a given number of iterations.
    /// This is computationally heavy and blocks the thread.
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError>;

    /// Instantly verifies a provided VDF proof against the challenge.
    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError>;
}

/// Abstract trait defining the contract for the local embedded database.
pub trait StorageEngine: Send + Sync {
    /// Stores a `value` under the given `key`, overwriting any existing entry.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    /// Retrieves the value stored under `key`, or `None` if the key does not exist.
    fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError>;
    /// Removes the entry for `key`. A no-op if the key does not exist.
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;

    /// Iterate over all key-value pairs whose key starts with `prefix`. If `limit` is Some(n), returns at most n results.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(
        &self,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

/// Abstract trait defining the rules and consensus parameters for network governance.
pub trait GovernanceEngine: Send + Sync {
    /// Verifies whether a signed governance message meets the rules to be executed.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError>;

    /// Executes a verified governance action, applying its state changes and returning any resulting effects.
    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        wait_time: Option<u64>,
    ) -> Option<GovernanceEffect>;
}
