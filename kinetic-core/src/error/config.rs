//! Configuration parsing and persistence error types (`KIN-CFG-NNN`).
use super::Severity;
use thiserror::Error;

/// Error type for configuration load, save, and validation failures.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Failed to create the directory for the configuration file.
    #[error("Failed to create config directory: {0}")]
    DirectoryCreationFailed(String),

    /// Failed to serialize the configuration to TOML.
    #[error("Failed to serialize config: {0}")]
    SerializationFailed(String),

    /// Failed to write the configuration to disk.
    #[error("Failed to write config file: {0}")]
    WriteFailed(String),
}

impl ConfigError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DirectoryCreationFailed(_) => "KIN-CFG-001",
            Self::SerializationFailed(_) => "KIN-CFG-002",
            Self::WriteFailed(_) => "KIN-CFG-003",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        Severity::Error
    }
}
