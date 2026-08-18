//! Telemetry and logging error types (`KIN-TEL-NNN`).
//!
//! Emitted when internal diagnostics, loggers, or tracing scopes encounter an error.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Error emitted when asynchronous tracing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TelemetryError {
    /// A network function requested a correlation ID, but no async tracing scope was initialized.
    #[error("Missing request ID scope for telemetry")]
    MissingCorrelationId,
}

impl TelemetryError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCorrelationId => "KIN-TEL-001",
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
            Self::MissingCorrelationId => {
                "Internal logging is missing a correlation ID.".to_string()
            }
        }
    }
}
