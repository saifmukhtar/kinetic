//! DNS zone payload validation error types (`KIN-DNS-NNN`).
//!
//! Errors produced during [`DnsZone`](crate::types::dns::DnsZone) parsing and record-level
//! validation. A DNS zone is the JSON payload embedded inside a Kinetic reveal record;
//! every field must pass these checks before the zone is stored in the DHT.
//!
//! The 50-record limit and JSON nesting depth cap enforce the 80 KB DHT record size ceiling.
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

    /// A DNS label has an invalid length (empty or >62 chars).
    #[error("Invalid label length: {0}")]
    InvalidLabelLength(String),

    /// A DNS label contains invalid characters.
    #[error("Invalid label character: {0}")]
    InvalidLabelCharacters(String),

    /// A CNAME record was provided alongside incompatible records (KID is the only allowed coexistence).
    #[error("CNAME record for '{0}' must be the only routing record (KID is allowed)")]
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

    /// An IPFS CID string is invalid.
    #[error("Invalid IPFS CID string: {0}")]
    InvalidIpfsCid(String),
}

impl PartialEq for DnsError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NestedTooDeeply, Self::NestedTooDeeply) => true,
            (Self::ParseError(a), Self::ParseError(b)) => a.to_string() == b.to_string(),
            (Self::TooManyRecords, Self::TooManyRecords) => true,
            (Self::InvalidLabelLength(a), Self::InvalidLabelLength(b)) => a == b,
            (Self::InvalidLabelCharacters(a), Self::InvalidLabelCharacters(b)) => a == b,
            (Self::InvalidCnameConfiguration(a), Self::InvalidCnameConfiguration(b)) => a == b,
            (Self::TxtRecordTooLong(a), Self::TxtRecordTooLong(b)) => a == b,
            (Self::InvalidCnameTarget(a), Self::InvalidCnameTarget(b)) => a == b,
            (Self::InvalidPeerId(a), Self::InvalidPeerId(b)) => a == b,
            (Self::InvalidKid(a), Self::InvalidKid(b)) => a == b,
            (Self::InvalidIpfsCid(a), Self::InvalidIpfsCid(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for DnsError {}

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
            Self::InvalidIpfsCid(_) => "KIN-DNS-011",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
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

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::NestedTooDeeply => {
                "The DNS zone contains data that is nested too deeply.".to_string()
            }
            Self::ParseError(_) => "Failed to parse the DNS zone data.".to_string(),
            Self::TooManyRecords => {
                "The DNS zone contains too many records (maximum 50).".to_string()
            }
            Self::InvalidLabelLength(_) => "A DNS record label has an invalid length.".to_string(),
            Self::InvalidLabelCharacters(_) => {
                "A DNS record label contains invalid characters.".to_string()
            }
            Self::InvalidCnameConfiguration(_) => {
                "A CNAME record must be the only routing record for its label, except for cryptographic KID records.".to_string()
            }
            Self::TxtRecordTooLong(_) => {
                "A TXT record is too long (maximum 255 bytes).".to_string()
            }
            Self::InvalidCnameTarget(_) => "A CNAME target is invalid or too long.".to_string(),
            Self::InvalidPeerId(_) => "A PeerId string is invalid.".to_string(),
            Self::InvalidKid(_) => {
                "A KID string is invalid or missing the 'did:kin:' prefix.".to_string()
            }
            Self::InvalidIpfsCid(_) => "An IPFS CID string is invalid.".to_string(),
        }
    }
}
