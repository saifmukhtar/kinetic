use super::Severity;
use thiserror::Error;

/// Error type for DNS zone payloads and record validation.
#[derive(Error, Debug)]
pub enum DnsError {
    /// The DNS JSON payload is nested too deeply.
    #[error("Payload rejected: JSON nested too deeply")]
    NestedTooDeeply,

    /// The DNS JSON payload could not be parsed.
    #[error("Failed to parse DNS zone: {0}")]
    ParseError(#[from] serde_json::Error),

    /// The zone contains more than the maximum allowed number of records.
    #[error("Maximum of 50 DNS records allowed per zone to prevent network bloat")]
    TooManyRecords,

    /// A DNS label has an invalid length (empty or >63 chars).
    #[error("Invalid label length: {0}")]
    InvalidLabelLength(String),

    /// A DNS label contains invalid characters.
    #[error("Invalid label character: {0}")]
    InvalidLabelCharacters(String),

    /// A CNAME record was provided alongside other records for the same label.
    #[error("CNAME record for '{0}' must be the only record")]
    InvalidCnameConfiguration(String),

    /// A TXT record exceeds the maximum allowed length (255 bytes).
    #[error("TXT record too long for label {0}")]
    TxtRecordTooLong(String),

    /// A CNAME target is empty or too long.
    #[error("CNAME target length invalid for label {0}")]
    InvalidCnameTarget(String),

    /// A PeerId string could not be parsed into a valid libp2p PeerId.
    #[error("Invalid PeerId string: {0}")]
    InvalidPeerId(String),

    /// A KID string does not start with the required `did:kin:` prefix.
    #[error("Invalid KID string (missing prefix): {0}")]
    InvalidKid(String),
}

impl DnsError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NestedTooDeeply => "KIN-DNS-001",
            Self::ParseError(_) => "KIN-DNS-002",
            Self::TooManyRecords => "KIN-DNS-003",
            Self::InvalidLabelLength(_) => "KIN-DNS-004",
            Self::InvalidLabelCharacters(_) => "KIN-DNS-005",
            Self::InvalidCnameConfiguration(_) => "KIN-DNS-006",
            Self::TxtRecordTooLong(_) => "KIN-DNS-007",
            Self::InvalidCnameTarget(_) => "KIN-DNS-008",
            Self::InvalidPeerId(_) => "KIN-DNS-009",
            Self::InvalidKid(_) => "KIN-DNS-010",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        // DNS validation failures are usually bad requests (Warning level from the node's perspective).
        Severity::Warning
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false // These are all deterministic validation failures
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
