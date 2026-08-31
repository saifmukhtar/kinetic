//! Embedded storage engine error types (`KIN-DBE-NNN`).
//!
//! [`StorageError`] is returned by the [`StorageEngine`](crate::traits::StorageEngine)
//! implementation in `kinetic-storage` when the embedded B-tree database encounters
//! lock contention, structural corruption, or a failed read/write operation.
//!
//! `KIN-DBE-001` (`DatabaseLocked`) is `Severity::Critical` — it means a second
//! daemon instance is competing for the same database file, which is a fatal condition.
use super::Severity;
use thiserror::Error;

/// Errors originating from local storage
#[derive(Error, Debug, PartialEq, Eq)]
pub enum StorageError {

    /// The daemon attempted to open the embedded database file, but it is exclusively locked.
    /// This typically means a second instance of the Kinetic daemon is already running on this machine.
    #[error("Another instance of Kinetic daemon is already running (Database is locked).")]
    DatabaseLocked,

    /// The database engine detected structural corruption in the B-tree on disk.
    /// This can happen after a hard power loss. The node may need to wipe its state and re-sync.
    #[error("Storage corruption detected: {0}")]
    Corruption(String),

    /// The local node failed to read a value from the database engine.
    /// This could indicate underlying disk issues or unreadable sectors.
    #[error("Storage read failed: {0}")]
    ReadFailed(String),

    /// The local node failed to write a value to the database engine.
    /// Ensure the disk is not completely full and the daemon has write permissions.
    #[error("Storage write failed: {0}")]
    WriteFailed(String),

    /// The local node failed to delete a record from the database.
    #[error("Storage delete failed: {0}")]
    DeleteFailed(String),

    /// The local node failed to iterate over a range of keys in the database.
    #[error("Storage scan failed: {0}")]
    ScanFailed(String),

    /// The daemon failed to initialize or create the database engine at startup.
    /// Check the filesystem permissions and ensure the target directory exists.
    #[error("Storage initialization failed: {0}")]
    OpenFailed(String),

    /// The bytes were successfully read from disk, but failed to deserialize into a valid Kinetic structure.
    /// This can happen after a daemon upgrade if the data schema changed without a migration.
    #[error("Storage deserialization failed: {0}")]
    DeserializationFailed(String),

    /// During node startup, the Kinetic Record Store (KRS) detected an invalid or expired NameRecord on disk.
    /// The daemon safely discarded it automatically. No action is required.
    #[error("Discarding invalid locally stored NameRecord")]
    InvalidRecordDiscarded,

    /// During node startup, the Kinetic Record Store (KRS) detected a heartbeat for a name that no longer exists.
    /// The daemon safely purged the orphan automatically. No action is required.
    #[error("Purging orphaned heartbeat")]
    OrphanedHeartbeatPurged,
}

impl StorageError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DatabaseLocked => "KIN-DBE-001",
            Self::Corruption(_) => "KIN-DBE-002",
            Self::ReadFailed(_) => "KIN-DBE-003",
            Self::WriteFailed(_) => "KIN-DBE-004",
            Self::DeleteFailed(_) => "KIN-DBE-005",
            Self::ScanFailed(_) => "KIN-DBE-006",
            Self::OpenFailed(_) => "KIN-DBE-007",
            Self::DeserializationFailed(_) => "KIN-DBE-008",
            Self::InvalidRecordDiscarded => "KIN-DBE-011",
            Self::OrphanedHeartbeatPurged => "KIN-DBE-012",
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
            Self::Corruption(_) | Self::DeserializationFailed(_) => Severity::Error,
            Self::ReadFailed(_)
            | Self::WriteFailed(_)
            | Self::DeleteFailed(_)
            | Self::ScanFailed(_)
            | Self::OpenFailed(_) => Severity::Error,
            Self::InvalidRecordDiscarded | Self::OrphanedHeartbeatPurged => Severity::Warning,
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
            Self::DeserializationFailed(_) => "Stored data could not be deserialized due to version mismatch or corruption.".to_string(),
            Self::InvalidRecordDiscarded => "An invalid or expired local record was safely discarded.".to_string(),
            Self::OrphanedHeartbeatPurged => "An orphaned heartbeat was safely purged from local storage.".to_string(),
        }
    }
}
