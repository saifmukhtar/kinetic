//! Name validation error types (`KIN-NAM-NNN`).
//!
//! [`NamesError`] is returned by [`is_valid_apex_name`](crate::types::names::is_valid_apex_name)
//! when a submitted name fails any of the Kinetic naming rules:
//!
//! - **LDH rule** (RFC 5891): only lowercase letters, digits, and internal hyphens.
//! - **Length limits**: total ≤253 chars; each label ≤63 chars (RFC 1035).
//! - **Apex-only**: subnames are managed by the apex owner, not the DHT directly.
//! - **Category 1 reserved** (RFC 2606/6761): `localhost`, `test`, `example`, etc.
//! - **Category 2 protocol names**: `seed`, `explorer`, `docs`, etc. locked until Phase 2.
use super::Severity;
use thiserror::Error;

/// Errors related to name validation and RFC reserved name checks.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum NamesError {
    /// The submitted name exceeds the strict 253-character limit or is completely empty.
    /// The Kinetic naming system strictly inherits RFC 1035 length limits to prevent buffer overflow vulnerabilities.
    /// Choose a shorter, concise name to ensure network compatibility.
    #[error("Name is empty or exceeds the 253 character limit")]
    NameTooLong,

    /// A single label (the word between dots) within the name exceeds the 63-character limit.
    /// The network enforces RFC 1035 label constraints for efficient DNS compatibility and routing.
    /// Break the name up using dots or choose a shorter label.
    #[error("Label is empty or exceeds the 63 character limit")]
    LabelTooLong,

    /// A single label (the word between dots) is completely empty.
    /// This usually occurs when consecutive dots are used (e.g., `foo..kin`) or a dot is placed at the start of the string.
    /// Ensure there is exactly one dot separating each valid label and no leading dots.
    #[error("Label is empty (e.g. consecutive dots)")]
    EmptyLabel,

    /// The name contains characters not permitted by the LDH (Letters, Digits, Hyphen) rule.
    /// To prevent homograph attacks and Unicode confusion, only a highly restricted character set is allowed.
    /// Ensure the name strictly contains only lowercase alphanumeric characters and internal hyphens. No emojis or spaces.
    #[error(
        "Name contains invalid characters (only lowercase letters, digits, and internal hyphens allowed)"
    )]
    InvalidCharacter,

    /// A hyphen was placed at the very start or end of a label (e.g., `-example` or `example-`).
    /// Hyphens must be strictly internal according to the LDH rule to prevent parsing ambiguities.
    /// Ensure all hyphens are strictly surrounded by valid alphanumeric characters.
    #[error("Labels cannot start or end with a hyphen")]
    InvalidHyphenPlacement,

    /// The name is a permanently reserved public utility name (e.g., `localhost`, `test`, `example`).
    /// These Category 1 names are strictly protected by RFC 2606 to prevent catastrophic network confusion.
    /// These names can never be registered on the Kinetic network. Choose a different name.
    #[error("Name is a protected public utility name (e.g., localhost, test)")]
    ReservedName,

    /// The name is reserved for critical network protocol functionality (e.g., `seed`, `explorer`, `docs`).
    /// These Category 2 names are locked by the core protocol to ensure official infrastructure remains secure.
    /// These names are locked until Phase 2 governance is activated. Choose a different name.
    #[error("Name is a protected protocol name (e.g., seed, explorer)")]
    ProtocolName,

    /// An operation was attempted on a subname (e.g., `sub.example.kin`), but the operation strictly requires an apex name.
    /// The core Kinetic DHT only manages apex names (`example.kin`) to prevent state bloat.
    /// Subnames must be managed independently by the apex owner via their local zone file.
    #[error("Only apex names are allowed (subnames must be managed by the apex owner)")]
    NotAnApexName,
}

impl NamesError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NameTooLong => "KIN-NAM-001",
            Self::LabelTooLong => "KIN-NAM-002",
            Self::EmptyLabel => "KIN-NAM-003",
            Self::InvalidCharacter => "KIN-NAM-004",
            Self::InvalidHyphenPlacement => "KIN-NAM-005",
            Self::ReservedName => "KIN-NAM-006",
            Self::ProtocolName => "KIN-NAM-007",
            Self::NotAnApexName => "KIN-NAM-008",
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
                "The name is empty or exceeds the 253-character limit.".to_string()
            }
            Self::LabelTooLong => {
                "A label within the name exceeds the 63-character limit.".to_string()
            }
            Self::EmptyLabel => {
                "A label within the name is empty (e.g. consecutive dots).".to_string()
            }
            Self::InvalidCharacter => {
                "The name contains invalid characters. Only lowercase letters, digits, and internal hyphens are allowed.".to_string()
            }
            Self::InvalidHyphenPlacement => {
                "Labels cannot start or end with a hyphen.".to_string()
            }
            Self::ReservedName => {
                "This name is a permanently protected public utility name.".to_string()
            }
            Self::ProtocolName => {
                "This name is reserved for critical network protocol functionality.".to_string()
            }
            Self::NotAnApexName => {
                "Only apex names (e.g. 'example.kin') can be registered directly.".to_string()
            }
        }
    }
}
