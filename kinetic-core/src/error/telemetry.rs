//! Telemetry and logging error types (`KIN-TEL-NNN`).
//!
//! Emitted when internal diagnostics, loggers, or tracing scopes encounter an error.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Error emitted when asynchronous tracing fails.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TelemetryError {
    /// A network function requested a correlation ID, but no async tracing scope was initialized.
    /// This happens if a network operation is spawned outside of the main HTTP router tracing span.
    /// Ensure all tasks are properly instrumented with `#[tracing::instrument]`.
    #[error("Missing request ID scope for telemetry")]
    MissingCorrelationId,
    /// Failed to broadcast telemetry data to the network.
    /// The node could not push its periodic health metrics to the diagnostic mesh.
    /// Check your P2P connections or disable telemetry in the config if not desired.
    #[error("Failed to broadcast telemetry: {0}")]
    BroadcastFailed(String),
}

impl TelemetryError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCorrelationId => "KIN-TEL-001",
            Self::BroadcastFailed(_) => "KIN-TEL-002",
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
            Self::BroadcastFailed(_) => {
                "Failed to broadcast node telemetry to the P2P network.".to_string()
            }
        }
    }
}
