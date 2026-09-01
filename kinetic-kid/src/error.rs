use thiserror::Error;

/// Error type returned by all operations in the `kinetic-kid` crate.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provided DID string does not start with the expected `did:kin:` prefix.
    /// The Kinetic identity system strictly requires all identifiers to follow the W3C DID specification format for the `kin` method.
    /// Prepend the 64-character identity hash with `did:kin:`.
    #[error("Invalid DID prefix, expected did:<method>:")]
    InvalidDidPrefix,

    /// Reserved error code (KIN-KID-002).
    /// This code is explicitly kept empty to maintain backward compatibility in the error taxonomy.
    /// This error should never be encountered in production.
    #[error("Reserved error code (KIN-KID-002)")]
    Reserved002,

    /// The method-specific ID portion of the DID is not exactly 64 characters long.
    /// Kinetic uses SHA-256 hashes for method IDs, which map strictly to 64 hexadecimal characters.
    /// Ensure you are passing a complete, untruncated SHA-256 hash in the DID string.
    #[error("DID method-specific ID must be exactly 64 characters long")]
    InvalidDidHexLength,

    /// The method-specific ID contains invalid characters.
    /// To prevent encoding ambiguity, the method ID must strictly contain only lowercase hexadecimal characters (0-9, a-f).
    /// Convert any uppercase hex characters to lowercase and remove any spaces or special characters.
    #[error("DID method-specific ID must contain only lowercase hexadecimal characters")]
    InvalidDidHexCharacters,

    /// The identity document or capability manifest could not be parsed from JSON.
    /// The payload is malformed, missing required fields, or has incorrect data types.
    /// Ensure the payload is a correctly formatted JSON object adhering to the DID Document specification.
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(String),

    /// The daemon failed to apply JCS (JSON Canonicalization Scheme) to the identity document.
    /// Canonicalization is strictly required before cryptographic signing to ensure the byte representation is deterministic across platforms.
    /// This usually indicates a deeply nested or malformed JSON payload that breaks RFC 8785 rules.
    #[error("Failed to canonicalize JSON (JCS): {0}")]
    CanonicalizationError(String),

    /// The ML-DSA-65 signature bytes on the Identity Document are invalid or do not verify.
    /// The payload was either tampered with in transit or signed by an incorrect private key.
    /// Ensure you are cryptographically signing the exact JCS-canonicalized bytes of the document.
    #[error("Invalid signature")]
    InvalidSignature,

    /// The Identity Document or capability manifest is missing a required `proof` signature field.
    /// By protocol design, all identity mutations and manifests must be cryptographically authenticated by the controller.
    /// You must attach a valid ML-DSA-65 signature proof to the document before publishing.
    #[error("Missing signature in document")]
    MissingSignature,

    /// The daemon failed to decode a base64-encoded cryptographic key or signature.
    /// The string contains invalid characters, is missing padding, or uses standard base64 instead of the required base64url encoding.
    /// Ensure all cryptographic fields strictly use standard base64url encoding without padding.
    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    /// A string field in the document exceeds the maximum allowed byte length.
    /// The network enforces strict string length bounds to prevent memory exhaustion attacks via massive payloads.
    /// Reduce the length of the specified field to comply with protocol limits.
    #[error("Field '{0}' exceeds maximum allowed byte length")]
    StringLengthExceeded(String),

    /// The capability manifest was signed by a key that is not authorized in the parent KID document.
    /// The network strictly verifies the delegation chain to ensure only authorized controllers can emit capability manifests.
    /// Verify that the signing key is officially listed as an active `assertionMethod` controller in the root KID Document.
    #[error("Manifest signed by unauthorized key")]
    UnauthorizedManifestSignature,

    /// The Identity Document contains more keys than the maximum allowed limit (20).
    /// This strict upper bound ensures fast cryptographic validation across the network and prevents state bloat.
    /// You must prune the identity document to remove unused or deprecated keys.
    #[error("Identity document exceeds maximum key bounds (max 20)")]
    KeyLimitExceeded,

    /// The capability manifest contains more service endpoints than the maximum allowed limit (50).
    /// This strict upper bound ensures fast DHT replication and prevents network bloat.
    /// Remove unused or redundant service endpoints to comply with the network bounds.
    #[error("Capability manifest exceeds maximum service endpoints (max 50)")]
    ServiceLimitExceeded,

    /// The Identity Document contains more manifest pointers than the maximum allowed limit (20).
    /// This strict upper bound ensures fast DHT replication and prevents network bloat.
    /// Remove unused capability locations to comply with the network bounds.
    #[error("Manifest pointer exceeds maximum location bounds (max 20)")]
    LocationLimitExceeded,

    /// The capability manifest's `valid_from` timestamp is set in the future.
    /// To prevent timing attacks and desync issues, capabilities cannot become valid at a future date.
    /// Ensure the issuer's system clock is synchronized via NTP and recreate the manifest.
    #[error("Manifest valid_from is in the future")]
    InvalidValidFrom,

    /// The capability manifest's expiration timestamp has passed.
    /// Capabilities are strictly time-bound to ensure keys and access rights can be reliably rotated.
    /// A new, freshly signed capability manifest must be generated and published.
    #[error("Manifest has expired")]
    ManifestExpired,

    /// The Genesis DID does not match the SHA-256 hash of the primary controller key.
    /// The initial DID must always be cryptographically bound to its root key to prevent hijacking during network bootstrap.
    /// Ensure the DID is exactly `did:kin:<sha256_of_key>`.
    #[error(
        "KID document genesis binding failed: DID does not match SHA-256 of primary controller key"
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
