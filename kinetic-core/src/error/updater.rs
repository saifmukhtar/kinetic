use super::Severity;
use thiserror::Error;

/// Errors occurring during the OTA auto-update process.
#[derive(Error, Debug)]
pub enum UpdaterError {
    /// No update mirror URLs were provided in the governance action.
    #[error("No OTA mirrors provided")]
    NoMirrorsProvided,
    /// The update server returned an HTTP error code (e.g. 404, 500).
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    /// A network failure occurred while downloading the update.
    #[error("Network error: {0}")]
    NetworkError(String),
    /// An underlying reqwest HTTP client error occurred.
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    /// A filesystem error occurred while extracting or replacing the binary.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// The `self_replace` crate failed to swap the running executable.
    #[error("Self replace error: {0}")]
    SelfReplaceError(String),
    /// The downloaded binary's hash did not match the expected hash.
    #[error("OTA binary hash mismatch. Downloaded: {0}, Expected: {1}")]
    HashMismatch(String, String),
    /// After replacement, the new process failed to spawn.
    #[error("Failed to spawn updated process: {0}")]
    SpawnFailed(String),
}

impl UpdaterError {
    /// Stable protocol error code. Part of the Kinetic error taxonomy.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoMirrorsProvided => "KIN-OTA-001",
            Self::HttpError(_) => "KIN-OTA-002",
            Self::NetworkError(_) => "KIN-OTA-003",
            Self::ReqwestError(_) => "KIN-OTA-004",
            Self::IoError(_) => "KIN-OTA-005",
            Self::SelfReplaceError(_) => "KIN-OTA-006",
            Self::HashMismatch(..) => "KIN-OTA-007",
            Self::SpawnFailed(_) => "KIN-OTA-008",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("https://kinetic.dev/errors/{}", self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::NoMirrorsProvided
            | Self::HttpError(_)
            | Self::NetworkError(_)
            | Self::ReqwestError(_) => Severity::Warning,
            Self::IoError(_)
            | Self::SelfReplaceError(_)
            | Self::HashMismatch(..)
            | Self::SpawnFailed(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::HttpError(_) | Self::NetworkError(_) | Self::ReqwestError(_)
        )
    }

    /// Returns the `Display` representation as the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::NoMirrorsProvided => "Update failed: No download mirrors were provided by the governance action.".to_string(),
            Self::HttpError(code) => format!("Update failed due to a server error (HTTP {}). The node will try again later.", code),
            Self::NetworkError(_) | Self::ReqwestError(_) => "Update failed due to a network error. The node will try again later.".to_string(),
            Self::IoError(_) => "Update failed due to an issue writing the new version to disk.".to_string(),
            Self::SelfReplaceError(_) => "The node failed to seamlessly replace itself with the updated version.".to_string(),
            Self::HashMismatch(..) => "Update rejected: The downloaded software did not match the expected cryptographic hash. This could indicate file corruption or a security risk.".to_string(),
            Self::SpawnFailed(_) => "Update succeeded, but the node failed to restart automatically. You may need to manually restart it.".to_string(),
        }
    }
}
