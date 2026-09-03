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
//! 1. **Stable Protocol Code**: Unique string code (e.g. `KIN-QRY-001`, `KIN-PUB-003`, `KIN-REG-005`).
//! 2. **RFC 7807 Type URI**: Web specification URI for standard error documentation.
//! 3. **Retryability Flag** ([`is_retryable`](ResolutionError::is_retryable)): Indicates if clients should retry.
//! 4. **Severity Classifier** ([`Severity`]): Directs logging and alert levels (`Info`, `Warning`, `Error`, `Critical`).
//! 5. **User Message** ([`user_message`](ResolutionError::user_message)): Clean, non-technical explanation for UIs.
//! 6. **Developer Details** ([`details`](ResolutionError::details)): Structured JSON payload for API extractors.
//!
//! ## Error Code Namespaces
//!
//! | Prefix | Error Type | Domain |
//! |---|---|---|
//! | `KIN-QRY-NNN` | [`ResolutionError`] | DHT name resolution |
//! | `KIN-PUB-NNN` | [`PublishError`] | DHT record publishing |
//! | `KIN-REG-NNN` | [`RegistrationError`] | Name registration flow |
//! | `KIN-VDF-NNN` | `VdfError` | VDF engine operations |
//! | `KIN-ACN-NNN` | `GovernanceError` | Council governance |
//! | `KIN-NRS-NNN` | `NrsError` | NRS zone parsing |
//! | `KIN-RND-NNN` | `DrandError` | Drand beacon |
//! | `KIN-IDN-NNN` | `IdentityError` | Node identity keys |
//! | `KIN-NAM-NNN` | `NamesError` | Name validation |
//! | `KIN-DBE-NNN` | `StorageError` | Embedded storage engine |
//! | `KIN-RPC-NNN` | `NetworkClientError` | P2P network client operations |
//! | `KIN-P2P-NNN` | `P2pError` | Swarm, mesh, and peer management |
//! | `KIN-PRX-NNN` | `ProxyError` (daemon/host) | Local HTTP proxy operations |
//! | `KIN-DHT-NNN` | `KineticStoreError` | Distributed Hash Table store logic |
//! | `KIN-SEC-NNN` | `SecurityError` | Proxy security exceptions and IP filtering |
//! | `KIN-SYS-NNN` | `SystemError` | Operating System execution and shutdown |
//! | `KIN-TEL-NNN` | `TelemetryError` | Tracing and correlation correlation IDs |
//! | `KIN-GTW-NNN` | `GatewayError` | IPFS/Storage Gateway proxy errors |
//! | `KIN-API-NNN` | `RestApiError` | REST API requests and HTTP framework |
//! | `KIN-CFG-NNN` | `ConfigError` | Configuration parsing and persistence |
//! | `KIN-KID-NNN` | `KidError` | KID document parsing and validation |
//! | `KIN-VER-NNN` | `SignatureVerifyError`| Cryptographic signature verification |
//! | `KIN-RVL-NNN` | `RevealValidationError`| Reveal payload parsing and verification |

use thiserror::Error;

/// Configuration parsing and persistence error types.
pub mod config;
/// REST API and HTTP framework error types.
pub mod api;
/// DHT name resolution error types.
pub mod dht;
/// Name validation error types.
pub mod names;
/// Drand random beacon error types.
pub mod drand;
/// VDF engine error types.
pub mod vdf;
/// Governance and consensus logic error types.
pub mod governance;
/// Node identity and key management error types.
pub mod identity;
/// P2P network client error types.
pub mod network;
/// P2P Swarm and Mesh connection error types.
pub mod p2p;
/// NRS zone parsing and validation error types.
pub mod nrs;
/// Operating System execution error types.
pub mod system;
/// Security validation error types.
pub mod security;
/// Embedded storage engine error types.
pub mod storage;
/// Telemetry and logging error types.
pub mod telemetry;
/// Gateway routing and fallback telemetry events.
pub mod gateway;

pub use config::ConfigError;
pub use dht::{PublishError, RecordRejectReason, RegistrationError, ResolutionError};
pub use drand::DrandError;
pub use gateway::GatewayError;
pub use governance::GovernanceError;
pub use identity::IdentityError;
pub use names::NamesError;
pub use network::NetworkClientError;
pub use nrs::NrsError;
pub use p2p::P2pError;
pub use security::SecurityError;
pub use storage::StorageError;
pub use system::SystemError;
pub use telemetry::TelemetryError;
pub use vdf::{VdfError, VdfRejectReason};
pub use api::RestApiError;

/// Top-level error type for core Kinetic protocol operations.
///
/// Encapsulates all subsystem errors into a single unified enum used across
/// core kernel API boundaries. Subsystem-specific errors should be used directly
/// inside their respective modules; this type is for cross-cutting operations
/// that span multiple domains.
///
/// # Protocol Context
///
/// This is the "catch-all" error type at kernel boundaries. Callers in `kinetic-daemon`
/// and `kinetic-network` that cross subsystem lines use this type. For richer context
/// (error codes, retryability, user messages), prefer the domain-specific error types.
#[derive(Error, Debug)]
pub enum KineticError {
    /// A VDF proof did not meet the required difficulty target.
    ///
    /// Raised when a Wesolowski VDF proof is structurally invalid or does not
    /// verify against its challenge hash. See [`VdfError`] for finer-grained variants.
    #[error("VDF proof verification failed")]
    InvalidVdfProof,

    /// Name validation failed.
    ///
    /// Wraps [`NamesError`] for names that violate LDH rules, exceed length limits,
    /// match reserved names (RFC 2606/6761), or are not apex names.
    #[error("Invalid Name: {0}")]
    InvalidName(#[from] NamesError),

    /// An Ed25519 or ML-DSA-65 signature failed verification.
    ///
    /// Ed25519 signatures are used for Libp2p transport identity and routing records.
    /// ML-DSA-65 signatures are used for the daemon identity and payload authorization (NameRecord/Reveal).
    #[error("Signature verification failed")]
    InvalidSignature,

    /// The revealed data's hash does not match the previously published commitment.
    ///
    /// Protocol invariant: a reveal is only accepted if
    /// `SHA-256(name || salt || payload) == stored_commitment_hash`. This variant
    /// fires when that invariant is violated.
    #[error("Hash commitment mismatch: revealed data does not match commitment")]
    CommitmentMismatch,

    /// A drand kyn was rejected as invalid.
    ///
    /// Raised when the kyn kyn number is wrong, the hex encoding is malformed,
    /// or the BLS signature does not verify against the Quicknet chain public key.
    #[error("Invalid Drand kyn: {0}")]
    InvalidDrandRound(String),

    /// A storage operation in the embedded database failed.
    ///
    /// Wraps the underlying embedded database error message as a string to avoid propagating
    /// the specific crate type across the API boundary.
    #[error("Storage layer error: {0}")]
    StorageError(String),

    /// An unexpected internal engine failure.
    ///
    /// Used only for truly unrecoverable states. Prefer domain-specific error
    /// variants for expected failure modes.
    #[error("Internal engine error: {0}")]
    Internal(String),

    /// A configuration value was missing or invalid.
    ///
    /// Raised by [`KineticConfig::load`](crate::config::KineticConfig::load) on
    /// parse failures and by startup validation when required fields are absent.
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// A cryptographic operation failed.
    ///
    /// Covers hashing, key derivation, discriminant generation, and other
    /// operations that are not covered by [`InvalidSignature`](Self::InvalidSignature).
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// A P2P network interaction failed.
    ///
    /// Wraps the network client error message. For richer context use
    /// [`NetworkClientError`] directly from `kinetic-network`.
    #[error("Network interaction failed: {0}")]
    NetworkError(String),
}

// ─── Severity ─────────────────────────────────────────────────────────────────

/// Alert and logging severity level for a Kinetic error.
///
/// Every domain error type implements a `severity()` method returning one of
/// these variants. The severity drives log level selection in
/// `KineticStoreError::log_warning` and alert routing in monitoring pipelines.
///
/// # Operational Meaning
///
/// | Variant | Log Level | Action Required |
/// |---|---|---|
/// | `Info` | `tracing::info!` | Normal protocol outcome; no action needed |
/// | `Warning` | `tracing::warn!` | Transient or expected condition; monitor |
/// | `Error` | `tracing::error!` | Unexpected failure; investigate |
/// | `Critical` | `tracing::error!` | Security or liveness threat; page on-call |
///
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected protocol outcome — not a system problem.
    ///
    /// Examples: name not found in DHT, commitment too recent, tie-break lost.
    Info,
    /// Transient condition expected to self-recover.
    ///
    /// Examples: peer disconnect, query timeout, rate-limit hit.
    Warning,
    /// Unexpected failure requiring investigation.
    ///
    /// Examples: invalid VDF proof received, corrupt record, bad signature.
    Error,
    /// Security-critical failure requiring immediate response.
    ///
    /// Examples: governance key missing, VDF unsupported on platform,
    /// node cannot participate in network operations.
    Critical,
}
