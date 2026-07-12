use thiserror::Error;

/// DHT record rejection and resolution/publish/registration error types.
pub mod dht;
/// Council governance and parameter-update error types.
pub mod governance;
/// libp2p network client error types.
pub mod network;
/// Sled storage engine error types.
pub mod storage;
/// OTA self-updater error types.
pub mod updater;
/// chiavdf Verifiable Delay Function error types.
pub mod vdf;
/// Drand Quicknet pulse acquisition and verification error types.
pub mod drand;
/// DNS Zone parsing and validation error types.
pub mod dns;
/// Node identity and seed phrase error types.
pub mod identity;

pub use dht::{PublishError, RecordRejectReason, RegistrationError, ResolutionError};
pub use governance::GovernanceError;
pub use network::NetworkClientError;
pub use storage::StorageError;
pub use updater::UpdaterError;
pub use vdf::{VdfError, VdfRejectReason};
pub use drand::DrandError;
pub use dns::DnsError;
pub use identity::IdentityError;

/// The top-level error type for core Kinetic protocol operations.
#[derive(Error, Debug)]
pub enum KineticError {
    /// A VDF proof did not meet the required difficulty target.
    #[error("VDF proof verification failed")]
    InvalidVdfProof,

    /// An Ed25519 or similar signature failed to verify.
    #[error("Signature verification failed")]
    InvalidSignature,

    /// The revealed data's hash does not match the previously published commitment.
    #[error("Hash commitment mismatch: revealed data does not match commitment")]
    CommitmentMismatch,

    /// A drand pulse was rejected as invalid (e.g. bad hex, wrong round).
    #[error("Invalid Drand pulse: {0}")]
    InvalidDrandPulse(String),

    /// A Sled or other storage operation failed.
    #[error("Storage layer error: {0}")]
    StorageError(String),

    /// An unexpected internal engine error.
    #[error("Internal engine error: {0}")]
    Internal(String),

    /// An OS I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A configuration value was missing or invalid.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// A cryptographic operation (hashing, signing, key derivation) failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// A P2P network interaction failed.
    #[error("Network interaction failed: {0}")]
    NetworkError(String),
}

// ─── Severity ─────────────────────────────────────────────────────────────────

/// How serious an error is — drives logging level, monitoring alerts, and UI treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected outcome, not a system problem (e.g. name not found).
    Info,
    /// Transient condition expected to self-recover (e.g. offline, timeout).
    Warning,
    /// Unexpected failure requiring attention (e.g. VDF tampering).
    Error,
    /// Security-critical failure — system should halt (e.g. getrandom failed).
    Critical,
}
