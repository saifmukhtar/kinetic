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
}

impl IdentityError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "KIN-IDN-001",
            Self::CorruptedIdentityFile(_) => "KIN-IDN-002",
            Self::IdentityNotFound(_) => "KIN-IDN-003",
            Self::InvalidSeedPhrase(_) => "KIN-IDN-004",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Io(_) | Self::CorruptedIdentityFile(_) | Self::IdentityNotFound(_) => {
                Severity::Error
            }
            Self::InvalidSeedPhrase(_) => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
