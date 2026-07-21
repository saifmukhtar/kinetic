//! Unified error taxonomy and logbook registry for Kinetic.
//!
//! All errors in Kinetic follow a domain-specific hierarchy designed to prevent
//! raw OS error leakage, enforce RFC 7807 problem details URIs, and supply clean
//! user-facing messages.
//!
//! ## Kinetic Error Taxonomy Architecture
//!
//! Every specialized domain error (e.g. [`ResolutionError`], [`PublishError`], [`RegistrationError`])
//! provides a rich metadata interface:
//!
//! 1. **Stable Protocol Code**: Unique string code (e.g. `KIN-RES-001`, `KIN-PUB-003`, `KIN-REG-005`).
//! 2. **RFC 7807 Type URI**: Web specification URI for standard error documentation.
//! 3. **Retryability Flag** ([`is_retryable`](ResolutionError::is_retryable)): Indicates if clients should retry.
//! 4. **Severity Classifier** ([`Severity`]): Directs logging and alert levels (`Info`, `Warning`, `Error`, `Critical`).
//! 5. **User Message** ([`user_message`](ResolutionError::user_message)): Clean, non-technical explanation for UIs.
//! 6. **Developer Details** ([`details`](ResolutionError::details)): Structured JSON payload for API extractors.

use thiserror::Error;

/// DHT record rejection and resolution/publish/registration error types.
pub mod dht;
/// DNS Zone parsing and validation error types.
pub mod dns;
/// Drand Quicknet pulse acquisition and verification error types.
pub mod drand;
/// Council governance and parameter-update error types.
pub mod governance;
/// Node identity and seed phrase error types.
pub mod identity;
/// Domain names validation error types.
pub mod names;
/// libp2p network client error types.
pub mod network;
/// Sled storage engine error types.
pub mod storage;
/// OTA self-updater error types.
pub mod updater;
/// chiavdf Verifiable Delay Function error types.
pub mod vdf;

pub use dht::{PublishError, RecordRejectReason, RegistrationError, ResolutionError};
pub use dns::DnsError;
pub use drand::DrandError;
pub use governance::GovernanceError;
pub use identity::IdentityError;
pub use names::NamesError;
pub use network::NetworkClientError;
pub use storage::StorageError;
pub use updater::UpdaterError;
pub use vdf::{VdfError, VdfRejectReason};

/// The top-level error type for core Kinetic protocol operations.
///
/// Encapsulates all subsystem errors into a single unified enum used across
/// the core kernel boundaries.
#[derive(Error, Debug)]
pub enum KineticError {
    /// A VDF proof did not meet the required difficulty target.
    #[error("VDF proof verification failed")]
    InvalidVdfProof,

    /// Domain name validation failed. Wraps [`NamesError`].
    #[error("Invalid Domain Name: {0}")]
    InvalidName(#[from] NamesError),

    /// An Ed25519 or ML-DSA-65 signature failed verification.
    #[error("Signature verification failed")]
    InvalidSignature,

    /// The revealed data's hash does not match the previously published commitment.
    #[error("Hash commitment mismatch: revealed data does not match commitment")]
    CommitmentMismatch,

    /// A drand pulse was rejected as invalid (e.g. bad hex, wrong round).
    #[error("Invalid Drand pulse: {0}")]
    InvalidDrandPulse(String),

    /// A storage operation in Sled failed. Wraps [`StorageError`].
    #[error("Storage layer error: {0}")]
    StorageError(String),

    /// An unexpected internal engine failure.
    #[error("Internal engine error: {0}")]
    Internal(String),

    /// An OS I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A configuration value was missing or invalid.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// A cryptographic operation (hashing, signing, key derivation) failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// A P2P network interaction failed. Wraps [`NetworkClientError`].
    #[error("Network interaction failed: {0}")]
    NetworkError(String),
}

// ─── Severity ─────────────────────────────────────────────────────────────────

/// Alert and logging severity levels for Kinetic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected outcome, not a system problem (e.g., name not found).
    Info,
    /// Transient condition expected to self-recover (e.g., peer disconnect, timeout).
    Warning,
    /// Unexpected failure requiring attention (e.g., invalid VDF proof, corrupt record).
    Error,
    /// Security-critical failure requiring process halt or emergency reset.
    Critical,
}
