use super::Severity;
use thiserror::Error;

/// Errors originating from local storage
#[derive(Error, Debug)]
pub enum StorageError {
    /// The database file is locked by another instance of the kinetic daemon.
    #[error("Another instance of Kinetic daemon is already running (Database is locked).")]
    DatabaseLocked,
    /// The local Sled database has detected structural corruption.
    #[error("Storage corruption detected: {0}")]
    Corruption(String),
    /// A read, write, or delete operation failed at the storage engine level.
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),
}

impl StorageError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DatabaseLocked => "KIN-STO-001",
            Self::Corruption(_) => "KIN-STO-002",
            Self::OperationFailed(_) => "KIN-STO-003",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::DatabaseLocked => Severity::Critical,
            Self::Corruption(_) => Severity::Error,
            Self::OperationFailed(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::OperationFailed(_))
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        self.to_string()
    }
}
