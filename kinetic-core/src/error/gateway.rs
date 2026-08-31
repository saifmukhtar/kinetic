//! IPFS/Storage Gateway proxy error types (`KIN-GTW-NNN`).
//!
//! Tracks the telemetry of IPFS gateway routing, fallback logic, and failures.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Gateway routing and fallback telemetry events.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GatewayError {
    /// The proxy is routing an IPFS request to a designated storage gateway.
    /// The node intercepted an `ipfs://` protocol request and is translating it to a standard HTTP gateway request.
    /// This is an informational telemetry event. No action is required.
    #[error("Proxying request to gateway: {0}")]
    ProxyingToGateway(String),

    /// A specific storage gateway returned an HTTP failure status (e.g., 404 Not Found, 502 Bad Gateway).
    /// The gateway is online but could not locate the requested CID on the IPFS network before timing out.
    /// The node will automatically fall back and attempt the next configured gateway in the list.
    #[error("Gateway {0} failed with {1}")]
    GatewayFailedWithStatus(String, String),

    /// A specific storage gateway was completely unreachable due to a network or transport error.
    /// The gateway may be offline, its domain may have expired, or a firewall is blocking the connection.
    /// The node will automatically fall back and attempt the next configured gateway in the list.
    #[error("Gateway {0} unreachable: {1}")]
    GatewayUnreachable(String, String),

    /// All configured storage gateways failed to resolve the target CID.
    /// The requested file is likely no longer pinned or hosted anywhere on the global IPFS network.
    /// The proxy request failed. Ensure the IPFS CID is still actively pinned by a storage provider.
    #[error("All storage gateways failed to resolve target: {0}")]
    AllGatewaysFailed(String),
}

impl GatewayError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProxyingToGateway(_) => "KIN-GTW-001",
            Self::GatewayFailedWithStatus(_, _) => "KIN-GTW-002",
            Self::GatewayUnreachable(_, _) => "KIN-GTW-003",
            Self::AllGatewaysFailed(_) => "KIN-GTW-004",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::ProxyingToGateway(_) => Severity::Info,
            Self::GatewayFailedWithStatus(_, _) | Self::GatewayUnreachable(_, _) => Severity::Warning,
            Self::AllGatewaysFailed(_) => Severity::Error,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::AllGatewaysFailed(_) => false,
            _ => true,
        }
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::ProxyingToGateway(_) => "Routing IPFS request to a storage gateway.".to_string(),
            Self::GatewayFailedWithStatus(_, _) => "A storage gateway failed to return the file.".to_string(),
            Self::GatewayUnreachable(_, _) => "A storage gateway is currently unreachable.".to_string(),
            Self::AllGatewaysFailed(_) => "All available storage gateways failed to load the requested content.".to_string(),
        }
    }
}
