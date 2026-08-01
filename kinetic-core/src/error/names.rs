//! Domain name validation error types (`KIN-NAM-NNN`).
//!
//! [`NamesError`] is returned by [`is_valid_apex_name`](crate::types::names::is_valid_apex_name)
//! when a submitted domain name fails any of the Kinetic naming rules:
//!
//! - **LDH rule** (RFC 5891): only lowercase letters, digits, and internal hyphens.
//! - **Length limits**: total ≤253 chars; each label ≤63 chars (RFC 1035).
//! - **Apex-only**: subdomains are managed by the apex owner, not the DHT directly.
//! - **Category 1 reserved** (RFC 2606/6761): `localhost`, `test`, `example`, etc.
//! - **Category 2 infrastructure**: `seed`, `explorer`, `docs`, etc. locked until Phase 2.
use super::Severity;
use thiserror::Error;

/// Errors related to domain name validation and RFC reserved name checks.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum NamesError {
    /// The name exceeds the 253 character limit or is completely empty.
    #[error("Name is empty or exceeds the 253 character limit")]
    NameTooLong,

    /// A single label (word between dots) exceeds 63 characters or is empty.
    #[error("Label is empty or exceeds the 63 character limit")]
    LabelTooLong,

    /// The name contains invalid characters not permitted by the LDH rule.
    #[error("Name contains invalid characters (only lowercase letters, digits, and internal hyphens allowed)")]
    InvalidCharacter,

    /// The name is a permanently reserved public utility name (e.g., localhost).
    #[error("Name is a protected public utility name (e.g., localhost, test)")]
    ReservedName,

    /// The name is reserved for critical network infrastructure.
    #[error("Name is a protected infrastructure name (e.g., seed, explorer)")]
    InfrastructureName,

    /// The name has an invalid TLD.
    #[error("Name has an invalid Top-Level Domain")]
    InvalidTLD,

    /// The name is a subdomain, but the operation requires an apex domain.
    #[error("Only apex domains are allowed (subdomains must be managed by the apex owner)")]
    NotAnApexDomain,
}

impl NamesError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NameTooLong => "KIN-NAM-001",
            Self::LabelTooLong => "KIN-NAM-002",
            Self::InvalidCharacter => "KIN-NAM-003",
            Self::ReservedName => "KIN-NAM-004",
            Self::InfrastructureName => "KIN-NAM-005",
            Self::InvalidTLD => "KIN-NAM-006",
            Self::NotAnApexDomain => "KIN-NAM-007",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        Severity::Warning
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::NameTooLong => {
                "The domain name is empty or exceeds the 253-character limit.".to_string()
            }
            Self::LabelTooLong => {
                "A label within the domain exceeds the 63-character limit.".to_string()
            }
            Self::InvalidCharacter => {
                "The domain name contains invalid characters. Only lowercase letters, digits, and internal hyphens are allowed.".to_string()
            }
            Self::ReservedName => {
                "This name is a permanently protected public utility name.".to_string()
            }
            Self::InfrastructureName => {
                "This name is reserved for critical network infrastructure.".to_string()
            }
            Self::InvalidTLD => {
                "The domain name does not end with a valid network TLD.".to_string()
            }
            Self::NotAnApexDomain => {
                "Only apex domain names (e.g. 'example.kin') can be registered directly.".to_string()
            }
        }
    }
}
