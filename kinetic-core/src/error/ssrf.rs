//! SSRF Security validation error types (`KIN-SEC-NNN`).
//!
//! Provides strict telemetry errors for IP-based Server-Side Request Forgery attacks.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Specifies the exact reason why an IP address was blocked by the SSRF security middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SsrfError {
    /// The IP address is a local loopback address (e.g., 127.0.0.1 or ::1).
    #[error("Loopback address detected")]
    Loopback,
    /// The IP address is in a private subnet (e.g., 10.0.0.0/8, 192.168.0.0/16).
    #[error("Private address detected")]
    Private,
    /// The IP address is the unspecified address (e.g., 0.0.0.0 or ::).
    #[error("Unspecified network address")]
    Unspecified,
    /// The IP address is inside a Carrier-Grade NAT block (e.g., 100.64.0.0/10).
    #[error("Carrier-Grade NAT detected")]
    CgNat,
    /// The IP address routes locally via multicast, broadcast, or link-local routing.
    #[error("Multicast, broadcast, or link-local address")]
    LocalNetworkRouting,
    /// The IP address is an IPv6 address that maps or translates directly to an internal IPv4 address.
    #[error("IPv4-mapped IPv6 address exploit")]
    Ipv6MappedExploit,
    /// The IP address uses NAT64 to mask an internal destination.
    #[error("NAT64 translation block")]
    Nat64,
    /// The IP address is a reserved, experimental, or documentation address block.
    #[error("Reserved or documentation IP address")]
    Reserved,
}

impl SsrfError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Loopback => "KIN-SEC-001",
            Self::Private => "KIN-SEC-002",
            Self::Unspecified => "KIN-SEC-003",
            Self::CgNat => "KIN-SEC-004",
            Self::LocalNetworkRouting => "KIN-SEC-005",
            Self::Ipv6MappedExploit => "KIN-SEC-006",
            Self::Nat64 => "KIN-SEC-007",
            Self::Reserved => "KIN-SEC-008",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        Severity::Critical
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Loopback => "Security block: Loopback proxying is prohibited.".to_string(),
            Self::Private => "Security block: Private network proxying is prohibited.".to_string(),
            Self::Unspecified => {
                "Security block: Unspecified address proxying is prohibited.".to_string()
            }
            Self::CgNat => "Security block: Carrier-Grade NAT bypass exploit blocked.".to_string(),
            Self::LocalNetworkRouting => {
                "Security block: Local network routing bypass exploit blocked.".to_string()
            }
            Self::Ipv6MappedExploit => {
                "Security block: IPv4-mapped IPv6 bypass exploit blocked.".to_string()
            }
            Self::Nat64 => "Security block: NAT64 translation bypass exploit blocked.".to_string(),
            Self::Reserved => {
                "Security block: Reserved IP address proxying is prohibited.".to_string()
            }
        }
    }
}
