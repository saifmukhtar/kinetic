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

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization/Deserialization error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Network interaction failed: {0}")]
    NetworkError(String),
}
