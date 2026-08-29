use thiserror::Error;

/// Error type returned by all operations in the `kinetic-kid` crate.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed DID String Prefix. The DID string does not start with the expected prefix.
    #[error("Invalid DID prefix, expected did:<method>:")]
    InvalidDidPrefix,
    /// Reserved error code for extreme future use (KIN-KID-002).
    #[error("Reserved error code (KIN-KID-002)")]
    Reserved002,
    /// DID String Hex Length Invalid. The method-specific ID is not exactly 64 characters long.
    #[error("DID method-specific ID must be exactly 64 characters long")]
    InvalidDidHexLength,
    /// DID String Non-Hex Characters. The method-specific ID contains invalid lowercase hexadecimal characters.
    #[error("DID method-specific ID must contain only lowercase hexadecimal characters")]
    InvalidDidHexCharacters,
    /// Identity Document JSON Parsing Failed.
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(String),
    /// Identity Document JCS Canonicalization Failed.
    #[error("Failed to canonicalize JSON (JCS): {0}")]
    CanonicalizationError(String),
    /// ML-DSA-65 Signature Invalid on Identity Document. The signature bytes are invalid or do not verify.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Missing Signature field on Identity Document or manifest.
    #[error("Missing signature in document")]
    MissingSignature,
    /// Base64 decode failed for Identity key/signature.
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    /// String field exceeds byte length limits.
    #[error("Field '{0}' exceeds maximum allowed byte length")]
    StringLengthExceeded(String),
    /// Manifest signed by key not authorized in KID document.
    #[error("Manifest signed by unauthorized key")]
    UnauthorizedManifestSignature,
    /// Too many keys in Identity Document (Max 20).
    #[error("Identity document exceeds maximum key bounds (max 20)")]
    KeyLimitExceeded,
    /// Too many service endpoints (Max 50).
    #[error("Capability manifest exceeds maximum service endpoints (max 50)")]
    ServiceLimitExceeded,
    /// Too many manifest pointers (Max 20).
    #[error("Manifest pointer exceeds maximum location bounds (max 20)")]
    LocationLimitExceeded,
    /// Manifest valid_from timestamp is in the future.
    #[error("Manifest valid_from is in the future")]
    InvalidValidFrom,
    /// Manifest has expired.
    #[error("Manifest has expired")]
    ManifestExpired,
    /// Genesis DID does not match SHA-256 of primary controller key.
    #[error(
        "KID document genesis binding failed: DID does not match SHA-256 of primary controller key (KIN-KID-015)"
    )]
    DidKeyMismatch,
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::JsonParseError(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64Error(err.to_string())
    }
}

/// Logging severity level for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Informational or client validation failure.
    Warning,
    /// Signature verification failure or security bound violation.
    Error,
}

impl Error {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDidPrefix => "KIN-KID-001",
            Self::Reserved002 => "KIN-KID-002",
            Self::InvalidDidHexLength => "KIN-KID-003",
            Self::InvalidDidHexCharacters => "KIN-KID-004",
            Self::JsonParseError(_) => "KIN-KID-005",
            Self::CanonicalizationError(_) => "KIN-KID-006",
            Self::InvalidSignature => "KIN-KID-007",
            Self::MissingSignature => "KIN-KID-008",
            Self::Base64Error(_) => "KIN-KID-009",
            Self::StringLengthExceeded(_) => "KIN-KID-010",
            Self::UnauthorizedManifestSignature => "KIN-KID-011",
            Self::KeyLimitExceeded => "KIN-KID-012",
            Self::InvalidValidFrom => "KIN-KID-013",
            Self::ManifestExpired => "KIN-KID-014",
            Self::DidKeyMismatch => "KIN-KID-015",
            Self::ServiceLimitExceeded => "KIN-KID-016",
            Self::LocationLimitExceeded => "KIN-KID-017",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn type_uri(&self) -> String {
        format!("https://kinetic.network/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidSignature
            | Self::UnauthorizedManifestSignature
            | Self::KeyLimitExceeded
            | Self::LocationLimitExceeded
            | Self::ServiceLimitExceeded
            | Self::StringLengthExceeded(_)
            | Self::DidKeyMismatch => Severity::Error,
            _ => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::InvalidDidPrefix => {
                "The DID string does not start with the expected 'did:<method>:' prefix.".to_string()
            }
            Self::Reserved002 => "Reserved error code.".to_string(),
            Self::InvalidDidHexLength => {
                "The DID method-specific ID must be exactly 64 hexadecimal characters long."
                    .to_string()
            }
            Self::InvalidDidHexCharacters => {
                "The DID method-specific ID must contain only lowercase hex characters.".to_string()
            }
            Self::JsonParseError(_) => "Failed to parse identity document JSON.".to_string(),
            Self::CanonicalizationError(_) => {
                "Failed to canonicalize identity document JSON.".to_string()
            }
            Self::InvalidSignature => {
                "The cryptographic signature on the identity document is invalid.".to_string()
            }
            Self::MissingSignature => {
                "The identity document is missing a required signature.".to_string()
            }
            Self::Base64Error(_) => "Failed to decode key or signature data.".to_string(),
            Self::UnauthorizedManifestSignature => {
                "The capability manifest was signed by an unauthorized key.".to_string()
            }
            Self::KeyLimitExceeded => {
                "Identity document exceeds maximum key bounds (max 20).".to_string()
            }
            Self::LocationLimitExceeded => {
                "Manifest pointer exceeds maximum location bounds (max 20).".to_string()
            }
            Self::ServiceLimitExceeded => {
                "Capability manifest exceeds maximum service endpoints (max 50).".to_string()
            }
            Self::StringLengthExceeded(field) => {
                format!("Field '{}' exceeds maximum allowed byte length.", field)
            }
            Self::InvalidValidFrom => {
                "Capability manifest valid_from timestamp is set in the future.".to_string()
            }
            Self::ManifestExpired => "Capability manifest has expired.".to_string(),
            Self::DidKeyMismatch => {
                "DID identity mismatch: the document identifier does not correspond to the primary controller key.".to_string()
            }
        }
    }
}
