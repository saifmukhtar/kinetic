//! Unified error taxonomy and severity classifications.
//!
//! Provides the core [`Severity`] classification enum used across all 
//! domain-specific error types in the Kinetic architecture to drive deterministic 
//! logging, alerting, and failure boundaries.

use serde::{Deserialize, Serialize};

/// Alert and logging severity level for a Kinetic network error.
///
/// Every domain error type in the Kinetic network implements a `severity()` method
/// returning one of these variants. This decoupling allows the routing layer to 
/// universally filter logs and UI alerts without needing to understand the underlying 
/// error context.
///
/// # Semantic Output Boundary
/// The integer order of these variants (0-3) is mathematically significant for 
/// strict magnitude comparisons (`Info < Warning < Error < Critical`).
///
/// # Examples
/// ```rust
/// use kinetic_types::error::Severity;
///
/// // Severity is strictly mathematically ordered for log filtering.
/// assert!(Severity::Info < Severity::Warning);
/// assert!(Severity::Error > Severity::Warning);
/// assert!(Severity::Critical >= Severity::Error);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Formats the severity into a standardized uppercase string (e.g., `"CRITICAL"`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        // Because of PartialOrd and Ord, the order of variants top-to-bottom
        // defines their mathematical magnitude. Info < Warning < Error < Critical.
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);

        // Ensure >= works for log filtering
        assert!(Severity::Critical >= Severity::Error);
        assert!(Severity::Error >= Severity::Error);
        assert!(Severity::Warning >= Severity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Warning.to_string(), "WARNING");
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
