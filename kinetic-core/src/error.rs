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

// ─── Sub-enums ────────────────────────────────────────────────────────────────

/// Why a VDF proof was rejected.
#[derive(Error, Debug)]
pub enum VdfRejectReason {
    #[error("proof bytes are malformed")]
    MalformedProof,
    #[error("proof does not match the challenge")]
    ChallengeMismatch,
    #[error("VDF engine error: {0}")]
    EngineError(String),
    #[error("discriminant creation failed")]
    DiscriminantFailed,
}

/// Why a DHT record was rejected by the local store.
#[derive(Error, Debug)]
pub enum RecordRejectReason {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("VDF proof invalid")]
    InvalidVdf,
    #[error("registration has expired")]
    Expired,
    #[error("name already owned by a different key")]
    AlreadyOwned,
    #[error("name is in hibernation")]
    Hibernating,
    #[error("insufficient VDF iterations to claim ownership")]
    InsufficientIterations,
    #[error("lost XOR tie-break to stronger record")]
    TieBroken,
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("drand_randomness contains invalid hex")]
    InvalidDrandHex,
    #[error("public key bytes are malformed")]
    InvalidPublicKey,
    #[error("signature bytes are malformed")]
    MalformedSignature,
}

// ─── ResolutionError ──────────────────────────────────────────────────────────

/// Errors during DHT name resolution. Rich developer context, NOT serialized over wire.
/// Convert to `ApiError` at the HTTP/FFI boundary.
#[derive(Error, Debug)]
pub enum ResolutionError {
    #[error("Node is offline — no peers connected")]
    Offline,
    #[error("'{name}' not found after querying {peers_queried} peers")]
    NotFound { name: String, peers_queried: usize },
    #[error("'{name}' found but {count} record(s) failed VDF verification")]
    VdfVerificationFailed { name: String, count: usize },
    #[error("'{name}' registration has expired ({age} rounds old)")]
    Expired { name: String, age: u64 },
    #[error("Resolution timed out after {elapsed_ms}ms ({peers_queried} peers queried)")]
    Timeout {
        name: String,
        elapsed_ms: u64,
        peers_queried: usize,
    },
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl ResolutionError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "KIN-RES-001",
            Self::NotFound { .. } => "KIN-RES-002",
            Self::VdfVerificationFailed { .. } => "KIN-RES-003",
            Self::Expired { .. } => "KIN-RES-004",
            Self::Timeout { .. } => "KIN-RES-005",
            Self::Internal { .. } => "KIN-RES-006",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Offline | Self::Timeout { .. })
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Offline => Severity::Warning,
            Self::NotFound { .. } => Severity::Info,
            Self::VdfVerificationFailed { .. } => Severity::Error,
            Self::Expired { .. } => Severity::Info,
            Self::Timeout { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
        }
    }

    /// Clean user-facing message with no developer details.
    pub fn user_message(&self) -> String {
        match self {
            Self::Offline => {
                "You appear to be offline. Check your internet connection.".to_string()
            }
            Self::NotFound { name, .. } => {
                format!("'{}' is not registered on the Kinetic network.", name)
            }
            Self::VdfVerificationFailed { name, .. } => format!(
                "'{}' has an invalid cryptographic proof. This record may have been tampered with.",
                name
            ),
            Self::Expired { name, .. } => format!(
                "'{}' registration has expired. The owner needs to renew it.",
                name
            ),
            Self::Timeout { name, .. } => format!(
                "The network took too long to respond for '{}'. Please try again.",
                name
            ),
            Self::Internal { .. } => {
                "An internal network error occurred. Please try again.".to_string()
            }
        }
    }

    /// Structured developer-facing details for ApiError.details.
    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::NotFound { peers_queried, .. } => {
                serde_json::json!({ "peers_queried": peers_queried })
            }
            Self::Timeout {
                elapsed_ms,
                peers_queried,
                ..
            } => serde_json::json!({ "elapsed_ms": elapsed_ms, "peers_queried": peers_queried }),
            Self::VdfVerificationFailed { count, .. } => {
                serde_json::json!({ "failed_record_count": count })
            }
            Self::Expired { age, .. } => serde_json::json!({ "age_rounds": age }),
            _ => serde_json::Value::Null,
        }
    }
}

// ─── PublishError ─────────────────────────────────────────────────────────────

/// Errors when publishing records to the DHT.
#[derive(Error, Debug)]
pub enum PublishError {
    #[error("Node is offline — cannot publish to the DHT")]
    Offline,
    #[error("VDF proof is invalid: {0}")]
    InvalidProof(#[from] VdfRejectReason),
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned { name: String },
    #[error("All {count} DHT put operations failed")]
    AllFailed { count: usize },
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl PublishError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "KIN-PUB-001",
            Self::InvalidProof(_) => "KIN-PUB-002",
            Self::AlreadyOwned { .. } => "KIN-PUB-003",
            Self::AllFailed { .. } => "KIN-PUB-004",
            Self::Internal { .. } => "KIN-PUB-005",
        }
    }

    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Offline | Self::AllFailed { .. })
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Offline => Severity::Warning,
            Self::InvalidProof(_) => Severity::Error,
            Self::AlreadyOwned { .. } => Severity::Info,
            Self::AllFailed { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::Offline => "You appear to be offline. Cannot publish to the network.".to_string(),
            Self::InvalidProof(_) => "The VDF proof is invalid and was rejected.".to_string(),
            Self::AlreadyOwned { name } => {
                format!("'{}' is already registered under a different key.", name)
            }
            Self::AllFailed { .. } => {
                "The network rejected all publish attempts. Please try again.".to_string()
            }
            Self::Internal { .. } => "An internal error occurred during publishing.".to_string(),
        }
    }

    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::AllFailed { count } => serde_json::json!({ "failed_count": count }),
            Self::InvalidProof(r) => serde_json::json!({ "reason": r.to_string() }),
            _ => serde_json::Value::Null,
        }
    }
}

// ─── RegistrationError ────────────────────────────────────────────────────────

/// Errors during .kin name registration flow.
#[derive(Error, Debug)]
pub enum RegistrationError {
    #[error("Name '{name}' contains invalid characters")]
    InvalidName { name: String },
    #[error("VDF computation failed: {0}")]
    VdfFailed(#[from] VdfRejectReason),
    #[error("Commitment mismatch — reveal data does not match commitment")]
    CommitmentMismatch,
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned { name: String },
    #[error("A VDF registration is already in progress for '{name}'")]
    AlreadyInProgress { name: String },
    #[error("Registration rejected by the network: {reason}")]
    NetworkRejected { reason: RecordRejectReason },
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl RegistrationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidName { .. } => "KIN-REG-001",
            Self::VdfFailed(_) => "KIN-REG-002",
            Self::CommitmentMismatch => "KIN-REG-003",
            Self::AlreadyOwned { .. } => "KIN-REG-004",
            Self::AlreadyInProgress { .. } => "KIN-REG-005",
            Self::NetworkRejected { .. } => "KIN-REG-006",
            Self::Internal { .. } => "KIN-REG-006",
        }
    }

    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::VdfFailed(_))
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidName { .. } => Severity::Info,
            Self::VdfFailed(_) => Severity::Error,
            Self::CommitmentMismatch => Severity::Error,
            Self::AlreadyOwned { .. } => Severity::Info,
            Self::AlreadyInProgress { .. } => Severity::Info,
            Self::NetworkRejected { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidName { name } => format!("'{}' contains invalid characters. Use only lowercase letters, digits, and hyphens.", name),
            Self::VdfFailed(_) => "The VDF computation failed. Please try again.".to_string(),
            Self::CommitmentMismatch => "The registration data is inconsistent. Please restart the registration process.".to_string(),
            Self::AlreadyOwned { name } => format!("'{}' is already registered by someone else.", name),
            Self::AlreadyInProgress { name } => format!("A registration is already in progress for '{}'.", name),
            Self::NetworkRejected { reason } => format!("Registration was rejected: {}", reason),
            Self::Internal { .. } => "An internal error occurred during registration.".to_string(),
        }
    }

    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::NetworkRejected { reason } => {
                serde_json::json!({ "reject_reason": reason.to_string() })
            }
            _ => serde_json::Value::Null,
        }
    }
}
