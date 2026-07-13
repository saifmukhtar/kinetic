use thiserror::Error;

/// Error type returned by all operations in the `kinetic-kid` crate.
#[derive(Error, Debug)]
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
    JsonParseError(#[from] serde_json::Error),
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
    Base64Error(#[from] base64::DecodeError),
    /// An Ed25519 public key could not be parsed from the provided bytes.
    #[error("Key parse error: {0}")]
    KeyParseError(String),
    /// The manifest signature was produced by a key not listed in the KID document.
    #[error("Manifest signed by unauthorized key")]
    UnauthorizedManifestSignature,
}
