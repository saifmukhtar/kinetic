//! Daemon shutdown signal error types (`KIN-SHU-NNN`).
//!
//! Emitted when the operating system fails to bind termination signals (Ctrl+C, SIGTERM).

use kinetic_types::error::Severity;
use thiserror::Error;

/// Error emitted when graceful shutdown listeners fail to bind to the OS.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ShutdownError {
    /// Failed to bind to the SIGINT (Ctrl+C) keyboard signal.
    #[error("Failed to bind Ctrl+C handler: {0}")]
    SigIntBindingFailed(String),
    /// Failed to bind to the POSIX SIGTERM signal.
    #[error("Failed to bind SIGTERM handler: {0}")]
    SigTermBindingFailed(String),
}

impl ShutdownError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SigIntBindingFailed(_) => "KIN-SHU-001",
            Self::SigTermBindingFailed(_) => "KIN-SHU-002",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        Severity::Warning
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::SigIntBindingFailed(_) => {
                "Graceful keyboard shutdown is disabled (Ctrl+C listener failed).".to_string()
            }
            Self::SigTermBindingFailed(_) => {
                "Graceful system shutdown is disabled (SIGTERM listener failed).".to_string()
            }
        }
    }
}
