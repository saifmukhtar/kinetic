//! Unified error types and severity levels for Kinetic types.
//!
//! Provides the core [`Severity`] classification enum and taxonomy interfaces
//! used across all domain-specific error types in the `kinetic-types` crate.

use serde::{Deserialize, Serialize};

/// Alert and logging severity level for a Kinetic error.
///
/// Every domain error type in the Kinetic network implements a `severity()` method
/// returning one of these variants to drive log filtering and UI alert levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Expected protocol outcome or benign condition; no action needed.
    Info,
    /// Transient or non-fatal condition; client may retry or monitor.
    Warning,
    /// Standard operation failure requiring client attention or error handling.
    Error,
    /// Critical protocol, cryptographic, or safety violation.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}
