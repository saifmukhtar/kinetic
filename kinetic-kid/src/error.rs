use thiserror::Error;

/// Error type returned by all operations in the `kinetic-kid` crate.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum KidError {
    /// The DID string does not start with the expected `did:kin:` prefix.
    #[error("Invalid DID prefix, expected did:kin:")]
    InvalidDidPrefix,
    /// The method-specific ID portion of the DID is not a valid hex-encoded hash.
    #[error("Invalid method-specific ID format")]
    InvalidDidFormat,
    /// The method-specific ID is not exactly 64 characters long.
    #[error("DID method-specific ID must be exactly 64 characters long")]
    InvalidDidHexLength,
    /// The method-specific ID contains invalid lowercase hexadecimal characters.
    #[error("DID method-specific ID must contain only lowercase hexadecimal characters")]
    InvalidDidHexCharacters,
    /// JSON deserialization failed.
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(String),
    /// JCS canonicalization failed.
    #[error("Failed to canonicalize JSON (JCS): {0}")]
    CanonicalizationError(String),
    /// The signature bytes are invalid or do not verify against any controller key.
    #[error("Invalid signature")]
    InvalidSignature,
    /// The document or manifest does not contain a signature field.
    #[error("Missing signature in document")]
    MissingSignature,
    /// Base64url decoding of a key or signature failed.
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    /// An ML-DSA-65 public key could not be parsed from the provided bytes.
    #[error("Key parse error: {0}")]
    KeyParseError(String),
    /// The manifest signature was produced by a key not listed in the KID document.
    #[error("Manifest signed by unauthorized key")]
    UnauthorizedManifestSignature,
    /// The document contains too many keys or endpoints, exceeding maximum bounds.
    #[error("Document exceeds maximum size bounds (DoS protection)")]
    TooManyKeys,
    /// The valid_from timestamp is set in the future beyond acceptable skew.
    #[error("Manifest valid_from is in the future")]
    InvalidValidFrom,
    /// The manifest has expired based on its expires_at timestamp.
    #[error("Manifest has expired")]
    ManifestExpired,
    /// The `kid` DID identifier does not match the SHA-256 hash of the primary controller key.
    /// Returned by `verify_genesis()` when publishing a KID document for the first time.
    #[error("KID document genesis binding failed: DID does not match SHA-256 of primary controller key (KIN-KID-015)")]
    DidKeyMismatch,
    /// A KID document update was rejected because it was not signed by a key
    /// that appeared in the previously stored version of this document.
    #[error("KID document update rejected: not authorized by any key in the existing document (KIN-KID-016)")]
    UnauthorizedKidUpdate,
}

impl From<serde_json::Error> for KidError {
    fn from(err: serde_json::Error) -> Self {
        KidError::JsonParseError(err.to_string())
    }
}

impl From<base64::DecodeError> for KidError {
    fn from(err: base64::DecodeError) -> Self {
        KidError::Base64Error(err.to_string())
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

impl KidError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDidPrefix => "KIN-KID-001",
            Self::InvalidDidFormat => "KIN-KID-002",
            Self::InvalidDidHexLength => "KIN-KID-003",
            Self::InvalidDidHexCharacters => "KIN-KID-004",
            Self::JsonParseError(_) => "KIN-KID-005",
            Self::CanonicalizationError(_) => "KIN-KID-006",
            Self::InvalidSignature => "KIN-KID-007",
            Self::MissingSignature => "KIN-KID-008",
            Self::Base64Error(_) => "KIN-KID-009",
            Self::KeyParseError(_) => "KIN-KID-010",
            Self::UnauthorizedManifestSignature => "KIN-KID-011",
            Self::TooManyKeys => "KIN-KID-012",
            Self::InvalidValidFrom => "KIN-KID-013",
            Self::ManifestExpired => "KIN-KID-014",
            Self::DidKeyMismatch => "KIN-KID-015",
            Self::UnauthorizedKidUpdate => "KIN-KID-016",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.network/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidSignature
            | Self::UnauthorizedManifestSignature
            | Self::TooManyKeys
            | Self::DidKeyMismatch
            | Self::UnauthorizedKidUpdate => Severity::Error,
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
                "The DID string does not start with the 'did:kin:' prefix.".to_string()
            }
            Self::InvalidDidFormat => "The DID method-specific ID is malformed.".to_string(),
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
            Self::KeyParseError(_) => "Failed to parse ML-DSA-65 verification key.".to_string(),
            Self::UnauthorizedManifestSignature => {
                "The capability manifest was signed by an unauthorized key.".to_string()
            }
            Self::TooManyKeys => {
                "Identity document exceeds maximum key or endpoint bounds.".to_string()
            }
            Self::InvalidValidFrom => {
                "Capability manifest valid_from timestamp is set in the future.".to_string()
            }
            Self::ManifestExpired => "Capability manifest has expired.".to_string(),
            Self::DidKeyMismatch => {
                "DID identity mismatch: the document identifier does not correspond to the primary controller key.".to_string()
            }
            Self::UnauthorizedKidUpdate => {
                "KID update rejected: the update must be signed by a key listed in the current identity document.".to_string()
            }
        }
    }
}
