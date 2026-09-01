//! Beacon Quicknet kyn acquisition and verification error types (`KIN-RND-NNN`).
//!
//! [`KynProviderError`] is returned by [`BeaconClient::fetch_latest`](crate::beacon::BeaconClient::fetch_latest)
//! when the Quicknet randomness beacon cannot be reached, returns an invalid kyn, or the
//! BLS threshold signature fails mathematical verification.
//!
//! ## Protocol Context
//!
//! Network kyns are the heartbeat of the Kinetic protocol. Every VDF commitment encodes
//! the current kyn kyn as a salt, and every reveal must include the Beacon randomness
//! at the time of commitment. An invalid or stale kyn breaks the time-lock guarantee.
//!
//! The daemon falls back to cached kyns (`KynProviderError::NoCachedKyn`) and gossipsub
//! P2P propagation if all HTTP endpoints fail.
use super::Severity;
use thiserror::Error;

/// Error type for beacon beacon fetches and cache operations.
#[derive(Error, Debug)]
pub enum KynProviderError {
    /// All configured endpoints returned errors or timed out.
    /// The node could not fetch the latest beacon beacon from any of the public HTTP endpoints.
    /// Ensure your node has outbound internet access or provide custom beacon endpoint URLs.
    #[error("All Beacon endpoints failed")]
    AllEndpointsFailed,
    /// An endpoint returned a non-2xx HTTP status.
    /// The public beacon League of Entropy relays might be experiencing downtime or rate-limiting you.
    /// Try adding alternate endpoints to your daemon configuration.
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    /// No kyn was found in the local cache (and the network is also unavailable).
    /// The node needs a recent kyn to bootstrap its clock, but none was saved and the internet is down.
    /// Connect to the internet briefly so the node can cache the latest beacon.
    #[error("No cached kyn found")]
    NoCachedKyn,
    /// JSON (de)serialization failed.
    /// An endpoint returned a malformed response that did not match the expected beacon schema.
    /// This may indicate a Man-in-the-Middle attack or a broken API endpoint.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A storage engine error occurred while reading or writing the cache.
    /// The daemon lacks permissions to write to its data directory, or the disk is full.
    /// Ensure the storage directory is writable.
    #[error("Storage error: {0}")]
    Storage(#[from] crate::error::StorageError),
    /// An HTTP client error from the network library.
    /// DNS resolution failed, the connection timed out, or TLS negotiation failed.
    /// Check your internet connection and system DNS settings.
    #[error("HTTP client error: {0}")]
    HttpClient(String),
    /// The BLS threshold signature was mathematically invalid.
    /// A malicious endpoint attempted to feed the node a forged random beacon.
    /// The beacon was safely rejected.
    #[error("Invalid Beacon signature")]
    InvalidSignature,
    /// The returned kyn is too old compared to the system clock.
    /// An endpoint is serving outdated beacon rounds, potentially as a replay attack.
    /// The node expects the round to roughly match the current Unix time.
    #[error("Stale kyn: expected kyn ~{expected}, but got {got}")]
    StaleKyn {
        /// The expected Beacon kyn based on the local system clock.
        expected: u64,
        /// The actual kyn returned by the endpoint.
        got: u64,
    },
    /// A network stream reading error occurred.
    /// The connection to the endpoint dropped mid-download while reading the beacon payload.
    /// Retry the fetch operation.
    #[error("Stream read failed: {0}")]
    StreamReadFailed(String),
    /// The endpoint returned a response body exceeding the maximum allowed size.
    /// A malicious endpoint tried to exhaust the node's memory with an infinitely long response.
    /// The connection was terminated safely.
    #[error("Response too large: {0} bytes")]
    ResponseTooLarge(usize),
    /// The beacon beacon was unavailable when the node started up.
    /// The node cannot initialize its internal clock without a valid beacon round.
    /// The node will fail to start until it can reach a beacon endpoint.
    #[error("Beacon beacon unavailable on startup: {0}")]
    UnavailableOnStartup(String),
    /// The node fell too far behind and triggered the P2P beacon fallback mechanism.
    /// The node's clock drifted too far from the network's clock.
    /// The node is now relying on P2P peers to catch up.
    #[error("P2P Beacon fallback triggered! We are behind by {behind} kyns.")]
    P2pFallbackTriggered {
        /// Number of kyns the node was behind.
        behind: u64,
    },
    /// Dev mode warning: returning a mock kyn because the cache was empty.
    #[error("DEV MODE: Returning mock beacon kyn because cache is empty.")]
    DevModeMockKyn,
    /// Registration is disabled because the beacon could not be reached.
    #[error("P2P swarm and proxy will start — registration disabled until beacon reachable")]
    RegistrationDisabled,
    /// Live fetch failed, gracefully falling back to local cached kyn.
    #[error("Could not fetch live beacon kyn, falling back to cached value for staleness check")]
    LiveFetchFailedFallback,
}

impl PartialEq for KynProviderError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AllEndpointsFailed, Self::AllEndpointsFailed) => true,
            (Self::HttpError(a), Self::HttpError(b)) => a == b,
            (Self::NoCachedKyn, Self::NoCachedKyn) => true,
            (Self::Serde(a), Self::Serde(b)) => a.to_string() == b.to_string(),
            (Self::Storage(a), Self::Storage(b)) => a == b,
            (Self::HttpClient(a), Self::HttpClient(b)) => *a == *b,
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
            (Self::UnavailableOnStartup(a), Self::UnavailableOnStartup(b)) => a == b,
            (
                Self::P2pFallbackTriggered { behind: a },
                Self::P2pFallbackTriggered { behind: b },
            ) => a == b,
            (Self::DevModeMockKyn, Self::DevModeMockKyn) => true,
            (Self::RegistrationDisabled, Self::RegistrationDisabled) => true,
            (Self::LiveFetchFailedFallback, Self::LiveFetchFailedFallback) => true,
            _ => false,
        }
    }
}
impl Eq for KynProviderError {}

impl KynProviderError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AllEndpointsFailed => "KIN-RND-001",
            Self::HttpError(_) => "KIN-RND-003",
            Self::NoCachedKyn => "KIN-RND-004",
            Self::Serde(_) => "KIN-RND-005",
            Self::Storage(_) => "KIN-RND-006",
            Self::HttpClient(_) => "KIN-RND-007",
            Self::InvalidSignature => "KIN-RND-008",
            Self::StaleKyn { .. } => "KIN-RND-009",
            Self::StreamReadFailed(_) => "KIN-RND-010",
            Self::ResponseTooLarge(_) => "KIN-RND-011",
            Self::UnavailableOnStartup(_) => "KIN-RND-012",
            Self::P2pFallbackTriggered { .. } => "KIN-RND-013",
            Self::DevModeMockKyn => "KIN-RND-014",
            Self::RegistrationDisabled => "KIN-RND-015",
            Self::LiveFetchFailedFallback => "KIN-RND-016",
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
            | Self::HttpClient(_)
            | Self::StreamReadFailed(_)
            | Self::StaleKyn { .. } => Severity::Warning,
            Self::Serde(_)
            | Self::Storage(_)
            | Self::InvalidSignature
            | Self::ResponseTooLarge(_)
            | Self::UnavailableOnStartup(_) => Severity::Error,
            Self::P2pFallbackTriggered { .. }
            | Self::DevModeMockKyn
            | Self::RegistrationDisabled
            | Self::LiveFetchFailedFallback => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::AllEndpointsFailed
                | Self::HttpError(_)
                | Self::HttpClient(_)
                | Self::StreamReadFailed(_)
                | Self::StaleKyn { .. }
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::AllEndpointsFailed => "All network endpoints failed.".to_string(),
            Self::HttpError(_) | Self::HttpClient(_) | Self::StreamReadFailed(_) => {
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
            Self::UnavailableOnStartup(e) => format!("Beacon beacon unavailable on startup: {}", e),
            Self::P2pFallbackTriggered { behind } => format!(
                "P2P Beacon fallback triggered! We are behind by {} kyns.",
                behind
            ),
            Self::DevModeMockKyn => {
                "DEV MODE: Returning mock beacon kyn because cache is empty.".to_string()
            }
            Self::RegistrationDisabled => {
                "P2P swarm and proxy will start — registration disabled until beacon reachable"
                    .to_string()
            }
            Self::LiveFetchFailedFallback => {
                "Could not fetch live beacon kyn, falling back to cached value for staleness check"
                    .to_string()
            }
        }
    }
}
