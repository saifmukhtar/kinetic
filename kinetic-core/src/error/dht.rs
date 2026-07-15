use super::vdf::VdfRejectReason;
use super::Severity;
use thiserror::Error;

/// Why a DHT record was rejected by the local store.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RecordRejectReason {
    /// The record's Ed25519 signature did not verify against the public key.
    #[error("invalid signature")]
    InvalidSignature,
    /// The embedded VDF proof failed verification.
    #[error("VDF proof invalid")]
    InvalidVdf,
    /// The registration epoch has passed and the record is no longer valid.
    #[error("registration has expired")]
    Expired,
    /// The name is already owned by a different public key.
    #[error("name already owned by a different key")]
    AlreadyOwned,

    /// The VDF iteration count is below the minimum required for this name and round.
    #[error("insufficient VDF iterations to claim ownership")]
    InsufficientIterations,
    /// The record lost an XOR-distance tie-break to a competing record.
    #[error("lost XOR tie-break to stronger record")]
    TieBroken,
    /// The revealed data's hash does not match the stored commitment.
    #[error("commitment mismatch")]
    CommitmentMismatch,
    /// The `drand_randomness` field contains non-hex characters.
    #[error("drand_randomness contains invalid hex")]
    InvalidDrandHex,
    /// The public key bytes could not be parsed as a valid Ed25519 key.
    #[error("public key bytes are malformed")]
    InvalidPublicKey,
    /// The signature bytes are not 64 bytes long or are otherwise malformed.
    #[error("signature bytes are malformed")]
    MalformedSignature,
}

// ─── ResolutionError ──────────────────────────────────────────────────────────

/// Errors during DHT name resolution. Rich developer context, NOT serialized over wire.
/// Convert to `ApiError` at the HTTP/FFI boundary.
#[derive(Error, Debug)]
pub enum ResolutionError {
    /// The local node has no connected peers and cannot reach the DHT.
    #[error("Node is offline — no peers connected")]
    Offline,
    /// The name was not found after querying the given number of peers.
    #[error("'{name}' not found after querying {peers_queried} peers")]
    NotFound {
        /// The `.kin` name that was queried.
        name: String,
        /// Number of DHT peers that were contacted.
        peers_queried: usize,
    },
    /// The name was found but one or more of the returned records failed VDF verification.
    #[error("'{name}' found but {count} record(s) failed VDF verification")]
    VdfVerificationFailed {
        /// The `.kin` name that was queried.
        name: String,
        /// Number of records that failed verification.
        count: usize,
    },
    /// The name's registration has passed its validity window.
    #[error("'{name}' registration has expired ({age} rounds old)")]
    Expired {
        /// The `.kin` name that was queried.
        name: String,
        /// Age of the record in drand rounds.
        age: u64,
    },
    /// The resolution attempt timed out before a result was returned.
    #[error("Resolution timed out after {elapsed_ms}ms ({peers_queried} peers queried)")]
    Timeout {
        /// The `.kin` name that was queried.
        name: String,
        /// Wall-clock time elapsed during the query in milliseconds.
        elapsed_ms: u64,
        /// Number of DHT peers that were contacted before the timeout.
        peers_queried: usize,
    },
    /// An unexpected internal error occurred during resolution.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
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
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
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
    /// The local node has no connected peers and cannot write to the DHT.
    #[error("Node is offline — cannot publish to the DHT")]
    Offline,
    /// The VDF proof attached to the record failed verification.
    #[error("VDF proof is invalid: {0}")]
    InvalidProof(#[from] VdfRejectReason),
    /// The name is already owned by a different Ed25519 public key.
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned {
        /// The `.kin` name that is already registered.
        name: String,
    },
    /// Every DHT `PUT` attempt for this record failed.
    #[error("All {count} DHT put operations failed")]
    AllFailed {
        /// Number of failed PUT operations.
        count: usize,
    },
    /// An unexpected internal error occurred during the publish flow.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl PublishError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "KIN-PUB-001",
            Self::InvalidProof(_) => "KIN-PUB-002",
            Self::AlreadyOwned { .. } => "KIN-PUB-003",
            Self::AllFailed { .. } => "KIN-PUB-004",
            Self::Internal { .. } => "KIN-PUB-005",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Offline | Self::AllFailed { .. })
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Offline => Severity::Warning,
            Self::InvalidProof(_) => Severity::Error,
            Self::AlreadyOwned { .. } => Severity::Info,
            Self::AllFailed { .. } => Severity::Warning,
            Self::Internal { .. } => Severity::Error,
        }
    }

    /// Clean user-facing message with no developer details.
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

    /// Structured developer-facing details for [`ApiError`](crate::api_error::ApiError).
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
    /// The requested name contains characters not allowed by the Kinetic naming rules.
    #[error("Name '{name}' contains invalid characters")]
    InvalidName {
        /// The invalid name that was submitted.
        name: String,
    },
    /// The VDF computation step failed (e.g. chiavdf returned an error).
    #[error("VDF computation failed: {0}")]
    VdfFailed(#[from] VdfRejectReason),
    /// The revealed data's hash did not match the previously published commitment.
    #[error("Commitment mismatch — reveal data does not match commitment")]
    CommitmentMismatch,
    /// The name was claimed by a different key before this registration completed.
    #[error("'{name}' is already owned by a different key")]
    AlreadyOwned {
        /// The `.kin` name that is already registered.
        name: String,
    },
    /// A VDF task for this name is already running; only one at a time is permitted.
    #[error("A VDF registration is already in progress for '{name}'")]
    AlreadyInProgress {
        /// The `.kin` name whose registration is already running.
        name: String,
    },
    /// The network rejected the registration record for the stated reason.
    #[error("Registration rejected by the network: {reason}")]
    NetworkRejected {
        /// The specific reason the record was rejected.
        reason: RecordRejectReason,
    },
    /// An unexpected internal error occurred during the registration flow.
    #[error("Internal error: {message}")]
    Internal {
        /// Developer-facing description of what went wrong.
        message: String,
        /// Optional chain of underlying error causes.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl RegistrationError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
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

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::VdfFailed(_))
    }

    /// Severity level for logging and monitoring.
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

    /// Clean user-facing message with no developer details.
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

    /// Structured developer-facing details for [`ApiError`](crate::api_error::ApiError).
    pub fn details(&self) -> serde_json::Value {
        match self {
            Self::NetworkRejected { reason } => {
                serde_json::json!({ "reject_reason": reason.to_string() })
            }
            _ => serde_json::Value::Null,
        }
    }
}

impl PartialEq for ResolutionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (
                Self::NotFound {
                    name: a_n,
                    peers_queried: a_p,
                },
                Self::NotFound {
                    name: b_n,
                    peers_queried: b_p,
                },
            ) => a_n == b_n && a_p == b_p,
            (
                Self::VdfVerificationFailed {
                    name: a_n,
                    count: a_c,
                },
                Self::VdfVerificationFailed {
                    name: b_n,
                    count: b_c,
                },
            ) => a_n == b_n && a_c == b_c,
            (
                Self::Expired {
                    name: a_n,
                    age: a_a,
                },
                Self::Expired {
                    name: b_n,
                    age: b_a,
                },
            ) => a_n == b_n && a_a == b_a,
            (
                Self::Timeout {
                    name: a_n,
                    elapsed_ms: a_e,
                    peers_queried: a_p,
                },
                Self::Timeout {
                    name: b_n,
                    elapsed_ms: b_e,
                    peers_queried: b_p,
                },
            ) => a_n == b_n && a_e == b_e && a_p == b_p,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for ResolutionError {}

impl PartialEq for PublishError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Offline, Self::Offline) => true,
            (Self::InvalidProof(a), Self::InvalidProof(b)) => a == b,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AllFailed { count: a_c }, Self::AllFailed { count: b_c }) => a_c == b_c,
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for PublishError {}

impl PartialEq for RegistrationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidName { name: a_n }, Self::InvalidName { name: b_n }) => a_n == b_n,
            (Self::VdfFailed(a), Self::VdfFailed(b)) => a == b,
            (Self::CommitmentMismatch, Self::CommitmentMismatch) => true,
            (Self::AlreadyOwned { name: a_n }, Self::AlreadyOwned { name: b_n }) => a_n == b_n,
            (Self::AlreadyInProgress { name: a_n }, Self::AlreadyInProgress { name: b_n }) => {
                a_n == b_n
            }
            (Self::NetworkRejected { reason: a_r }, Self::NetworkRejected { reason: b_r }) => {
                a_r == b_r
            }
            (Self::Internal { message: a_m, .. }, Self::Internal { message: b_m, .. }) => {
                a_m == b_m
            }
            _ => false,
        }
    }
}
impl Eq for RegistrationError {}
