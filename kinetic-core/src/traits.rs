use crate::error::{StorageError, VdfError};
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

    /// Iterate over all key-value pairs whose key starts with `prefix`.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}
