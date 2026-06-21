use crate::error::KineticError;
use crate::types::{Commitment, VdfProof};

/// Abstract trait defining the contract for any underlying VDF implementation.
pub trait VdfEngine: Send + Sync {
    /// Evaluates the VDF sequentially for a given number of iterations.
    /// This is computationally heavy and blocks the thread.
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, KineticError>;

    /// Instantly verifies a provided VDF proof against the challenge.
    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, KineticError>;
}

/// Abstract trait defining the contract for the local embedded database.
pub trait StorageEngine: Send + Sync {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KineticError>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KineticError>;
    fn delete(&self, key: &[u8]) -> Result<(), KineticError>;
}
