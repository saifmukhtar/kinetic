use thiserror::Error;

#[derive(Error, Debug)]
pub enum KineticError {
    #[error("VDF proof verification failed")]
    InvalidVdfProof,
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Hash commitment mismatch: revealed data does not match commitment")]
    CommitmentMismatch,
    #[error("Invalid Drand pulse: {0}")]
    InvalidDrandPulse(String),
    #[error("Storage layer error: {0}")]
    StorageError(String),
    #[error("Internal engine error: {0}")]
    Internal(String),
}
