use thiserror::Error;

#[derive(Error, Debug)]
pub enum KidError {
    #[error("Invalid DID prefix, expected did:kin:")]
    InvalidDidPrefix,
    #[error("Invalid method-specific ID format")]
    InvalidDidFormat,
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Failed to canonicalize JSON (JCS): {0}")]
    CanonicalizationError(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing signature in document")]
    MissingSignature,
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Key parse error: {0}")]
    KeyParseError(String),
    #[error("Manifest signed by unauthorized key")]
    UnauthorizedManifestSignature,
}
