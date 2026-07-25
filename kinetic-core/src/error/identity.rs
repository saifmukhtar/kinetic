//! Node identity key errors (`KIN-IDN-NNN`).
//!
//! [`IdentityError`] is returned by [`load_keypair`](crate::types::load_keypair) and
//! `save_keypair` when the ML-DSA-65 identity file is
//! missing, truncated, or the BIP-39 seed phrase is malformed.
//!
//! The identity file at `{base_dir}/identity.key` stores the raw ML-DSA-65 signing
//! key bytes and is required for daemon startup. If it is absent, a new key is generated.
use super::Severity;
use thiserror::Error;

/// Error type for node identity keys and mnemonic parsing.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// An I/O error occurred while reading or writing the identity file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The identity file is corrupted (e.g. wrong byte length).
    #[error("Identity file is corrupted: {0}")]
    CorruptedIdentityFile(String),

    /// The identity file could not be found.
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    /// The provided BIP-39 mnemonic seed phrase is invalid.
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),
    /// Failed to decrypt the identity file.
    #[error("Failed to decrypt identity file: {0}")]
    DecryptionFailed(String),
}

impl PartialEq for IdentityError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::CorruptedIdentityFile(a), Self::CorruptedIdentityFile(b)) => a == b,
            (Self::IdentityNotFound(a), Self::IdentityNotFound(b)) => a == b,
            (Self::InvalidSeedPhrase(a), Self::InvalidSeedPhrase(b)) => a == b,
            (Self::DecryptionFailed(a), Self::DecryptionFailed(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for IdentityError {}

impl IdentityError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "KIN-IDN-001",
            Self::CorruptedIdentityFile(_) => "KIN-IDN-002",
            Self::IdentityNotFound(_) => "KIN-IDN-003",
            Self::InvalidSeedPhrase(_) => "KIN-IDN-004",
            Self::DecryptionFailed(_) => "KIN-IDN-005",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Io(_)
            | Self::CorruptedIdentityFile(_)
            | Self::IdentityNotFound(_)
            | Self::DecryptionFailed(_) => Severity::Error,
            Self::InvalidSeedPhrase(_) => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Io(_) => {
                "An I/O error occurred while reading or writing the identity file.".to_string()
            }
            Self::CorruptedIdentityFile(_) => {
                "The identity file is corrupted and cannot be used.".to_string()
            }
            Self::IdentityNotFound(_) => "The identity file could not be found.".to_string(),
            Self::InvalidSeedPhrase(_) => "The provided seed phrase is invalid.".to_string(),
            Self::DecryptionFailed(_) => {
                "Failed to decrypt the identity file. Incorrect password or corrupted payload."
                    .to_string()
            }
        }
    }
}
