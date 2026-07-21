use super::Severity;
use thiserror::Error;

/// Error type for drand beacon fetches and cache operations.
#[derive(Error, Debug)]
pub enum DrandError {
    /// All configured endpoints returned errors or timed out.
    #[error("All Drand endpoints failed")]
    AllEndpointsFailed,
    /// A network-level error (e.g. DNS failure, connection refused).
    #[error("Network error: {0}")]
    Network(String),
    /// An endpoint returned a non-2xx HTTP status.
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    /// No pulse was found in the local cache (and the network is also unavailable).
    #[error("No cached pulse found")]
    NoCachedPulse,
    /// JSON (de)serialization failed.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A storage engine error occurred while reading or writing the cache.
    #[error("Storage error: {0}")]
    Storage(#[from] crate::error::StorageError),
    /// An HTTP client error from the `reqwest` library.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// The BLS threshold signature was mathematically invalid.
    #[error("Invalid Drand signature")]
    InvalidSignature,
    /// The returned pulse is too old compared to the system clock.
    #[error("Stale pulse: expected round ~{expected}, but got {got}")]
    StalePulse {
        /// The expected Drand round based on the local system clock.
        expected: u64,
        /// The actual round returned by the endpoint.
        got: u64,
    },
}

impl PartialEq for DrandError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AllEndpointsFailed, Self::AllEndpointsFailed) => true,
            (Self::Network(a), Self::Network(b)) => a == b,
            (Self::HttpError(a), Self::HttpError(b)) => a == b,
            (Self::NoCachedPulse, Self::NoCachedPulse) => true,
            (Self::Serde(a), Self::Serde(b)) => a.to_string() == b.to_string(),
            (Self::Storage(a), Self::Storage(b)) => a == b,
            (Self::Reqwest(a), Self::Reqwest(b)) => a.to_string() == b.to_string(),
            (Self::InvalidSignature, Self::InvalidSignature) => true,
            (Self::StalePulse { expected: e1, got: g1 }, Self::StalePulse { expected: e2, got: g2 }) => e1 == e2 && g1 == g2,
            _ => false,
        }
    }
}
impl Eq for DrandError {}

impl DrandError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AllEndpointsFailed => "KIN-DRA-001",
            Self::Network(_) => "KIN-DRA-002",
            Self::HttpError(_) => "KIN-DRA-003",
            Self::NoCachedPulse => "KIN-DRA-004",
            Self::Serde(_) => "KIN-DRA-005",
            Self::Storage(_) => "KIN-DRA-006",
            Self::Reqwest(_) => "KIN-DRA-007",
            Self::InvalidSignature => "KIN-DRA-008",
            Self::StalePulse { .. } => "KIN-DRA-009",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::AllEndpointsFailed
            | Self::Network(_)
            | Self::HttpError(_)
            | Self::NoCachedPulse
            | Self::Reqwest(_)
            | Self::StalePulse { .. } => Severity::Warning,
            Self::Serde(_) | Self::Storage(_) | Self::InvalidSignature => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::AllEndpointsFailed | Self::Network(_) | Self::HttpError(_) | Self::Reqwest(_) | Self::StalePulse { .. }
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::AllEndpointsFailed => "All Drand endpoints failed.".to_string(),
            Self::Network(_) | Self::HttpError(_) | Self::Reqwest(_) => {
                "A network error occurred while fetching the Drand pulse.".to_string()
            }
            Self::NoCachedPulse => "No cached Drand pulse found.".to_string(),
            Self::Serde(_) => "Failed to parse the Drand pulse.".to_string(),
            Self::Storage(_) => {
                "A storage error occurred while reading or writing the Drand cache.".to_string()
            }
            Self::InvalidSignature => "Invalid Drand signature.".to_string(),
            Self::StalePulse { .. } => "The fetched Drand pulse was too old.".to_string(),
        }
    }
}
