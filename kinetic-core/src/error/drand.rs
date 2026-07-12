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
}

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
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::AllEndpointsFailed
            | Self::Network(_)
            | Self::HttpError(_)
            | Self::NoCachedPulse
            | Self::Reqwest(_) => Severity::Warning,
            Self::Serde(_) | Self::Storage(_) | Self::InvalidSignature => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::AllEndpointsFailed | Self::Network(_) | Self::HttpError(_) | Self::Reqwest(_)
        )
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
