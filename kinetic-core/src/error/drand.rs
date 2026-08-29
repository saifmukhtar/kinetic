//! Drand Quicknet kyn acquisition and verification error types (`KIN-RND-NNN`).
//!
//! [`DrandError`] is returned by [`DrandClient::fetch_latest`](crate::drand::DrandClient::fetch_latest)
//! when the Quicknet randomness beacon cannot be reached, returns an invalid kyn, or the
//! BLS threshold signature fails mathematical verification.
//!
//! ## Protocol Context
//!
//! Network kyns are the heartbeat of the Kinetic protocol. Every VDF commitment encodes
//! the current kyn kyn as a salt, and every reveal must include the Drand randomness
//! at the time of commitment. An invalid or stale kyn breaks the time-lock guarantee.
//!
//! The daemon falls back to cached kyns (`DrandError::NoCachedKyn`) and gossipsub
//! P2P propagation if all HTTP endpoints fail.
use super::Severity;
use thiserror::Error;

/// Error type for drand beacon fetches and cache operations.
#[derive(Error, Debug)]
pub enum DrandError {
    /// All configured endpoints returned errors or timed out.
    #[error("All Drand endpoints failed")]
    AllEndpointsFailed,
    /// An endpoint returned a non-2xx HTTP status.
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    /// No kyn was found in the local cache (and the network is also unavailable).
    #[error("No cached kyn found")]
    NoCachedKyn,
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
    /// The returned kyn is too old compared to the system clock.
    #[error("Stale kyn: expected kyn ~{expected}, but got {got}")]
    StaleKyn {
        /// The expected Drand kyn based on the local system clock.
        expected: u64,
        /// The actual kyn returned by the endpoint.
        got: u64,
    },
    /// A network stream reading error occurred.
    #[error("Stream read failed: {0}")]
    StreamReadFailed(String),
    /// The endpoint returned a response body exceeding the maximum allowed size.
    #[error("Response too large: {0} bytes")]
    ResponseTooLarge(usize),
}

impl PartialEq for DrandError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AllEndpointsFailed, Self::AllEndpointsFailed) => true,
            (Self::HttpError(a), Self::HttpError(b)) => a == b,
            (Self::NoCachedKyn, Self::NoCachedKyn) => true,
            (Self::Serde(a), Self::Serde(b)) => a.to_string() == b.to_string(),
            (Self::Storage(a), Self::Storage(b)) => a == b,
            (Self::Reqwest(a), Self::Reqwest(b)) => a.to_string() == b.to_string(),
            (Self::InvalidSignature, Self::InvalidSignature) => true,
            (Self::StreamReadFailed(a), Self::StreamReadFailed(b)) => a == b,
            (Self::ResponseTooLarge(a), Self::ResponseTooLarge(b)) => a == b,
            (
                Self::StaleKyn {
                    expected: e1,
                    got: g1,
                },
                Self::StaleKyn {
                    expected: e2,
                    got: g2,
                },
            ) => e1 == e2 && g1 == g2,
            _ => false,
        }
    }
}
impl Eq for DrandError {}

impl DrandError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AllEndpointsFailed => "KIN-RND-001",
            Self::HttpError(_) => "KIN-RND-003",
            Self::NoCachedKyn => "KIN-RND-004",
            Self::Serde(_) => "KIN-RND-005",
            Self::Storage(_) => "KIN-RND-006",
            Self::Reqwest(_) => "KIN-RND-007",
            Self::InvalidSignature => "KIN-RND-008",
            Self::StaleKyn { .. } => "KIN-RND-009",
            Self::StreamReadFailed(_) => "KIN-RND-010",
            Self::ResponseTooLarge(_) => "KIN-RND-011",
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
            | Self::HttpError(_)
            | Self::NoCachedKyn
            | Self::Reqwest(_)
            | Self::StreamReadFailed(_)
            | Self::StaleKyn { .. } => Severity::Warning,
            Self::Serde(_)
            | Self::Storage(_)
            | Self::InvalidSignature
            | Self::ResponseTooLarge(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::AllEndpointsFailed
                | Self::HttpError(_)
                | Self::Reqwest(_)
                | Self::StreamReadFailed(_)
                | Self::StaleKyn { .. }
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::AllEndpointsFailed => "All network endpoints failed.".to_string(),
            Self::HttpError(_) | Self::Reqwest(_) | Self::StreamReadFailed(_) => {
                "A network error occurred while fetching the network kyn.".to_string()
            }
            Self::ResponseTooLarge(_) => {
                "The network returned a maliciously oversized response.".to_string()
            }
            Self::NoCachedKyn => "No cached network kyn found.".to_string(),
            Self::Serde(_) => "Failed to parse the network kyn.".to_string(),
            Self::Storage(_) => {
                "A storage error occurred while reading or writing the kyn cache.".to_string()
            }
            Self::InvalidSignature => "Invalid network signature.".to_string(),
            Self::StaleKyn { .. } => "The fetched network kyn was too old.".to_string(),
        }
    }
}
