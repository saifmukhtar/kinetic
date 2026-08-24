//! Redb embedded storage engine error types (`KIN-STO-NNN`).
//!
//! [`StorageError`] is returned by the [`StorageEngine`](crate::traits::StorageEngine)
//! implementation in `kinetic-storage` when the Redb B-tree database encounters
//! lock contention, structural corruption, or a failed read/write operation.
//!
//! `KIN-STO-001` (`DatabaseLocked`) is `Severity::Critical` — it means a second
//! daemon instance is competing for the same database file, which is a fatal condition.
use super::Severity;
use thiserror::Error;

/// Errors originating from local storage
#[derive(Error, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The database file is locked by another instance of the kinetic daemon.
    #[error("Another instance of Kinetic daemon is already running (Database is locked).")]
    DatabaseLocked,
    /// The local database has detected structural corruption.
    #[error("Storage corruption detected: {0}")]
    Corruption(String),
    /// A read operation failed at the storage engine level.
    #[error("Storage read failed: {0}")]
    ReadFailed(String),
    /// A write operation failed at the storage engine level.
    #[error("Storage write failed: {0}")]
    WriteFailed(String),
    /// A delete operation failed at the storage engine level.
    #[error("Storage delete failed: {0}")]
    DeleteFailed(String),
    /// A prefix scan operation failed at the storage engine level.
    #[error("Storage scan failed: {0}")]
    ScanFailed(String),
    /// The database failed to open or initialize.
    #[error("Storage initialization failed: {0}")]
    OpenFailed(String),
}

impl StorageError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DatabaseLocked => "KIN-STO-001",
            Self::Corruption(_) => "KIN-STO-002",
            Self::ReadFailed(_) => "KIN-STO-003",
            Self::WriteFailed(_) => "KIN-STO-004",
            Self::DeleteFailed(_) => "KIN-STO-005",
            Self::ScanFailed(_) => "KIN-STO-006",
            Self::OpenFailed(_) => "KIN-STO-007",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::DatabaseLocked => Severity::Critical,
            Self::Corruption(_) => Severity::Error,
            Self::ReadFailed(_)
            | Self::WriteFailed(_)
            | Self::DeleteFailed(_)
            | Self::ScanFailed(_)
            | Self::OpenFailed(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ReadFailed(_)
                | Self::WriteFailed(_)
                | Self::DeleteFailed(_)
                | Self::ScanFailed(_)
                | Self::OpenFailed(_)
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::DatabaseLocked => {
                "Another instance of Kinetic daemon is already running (Database is locked)."
                    .to_string()
            }
            Self::Corruption(_) => {
                "Storage corruption detected. The local database may need to be reset.".to_string()
            }
            Self::ReadFailed(_) => "A read operation failed on the local storage.".to_string(),
            Self::WriteFailed(_) => "A write operation failed on the local storage.".to_string(),
            Self::DeleteFailed(_) => "A delete operation failed on the local storage.".to_string(),
            Self::ScanFailed(_) => "A scan operation failed on the local storage.".to_string(),
            Self::OpenFailed(_) => "Failed to open the local storage database.".to_string(),
        }
    }
}
