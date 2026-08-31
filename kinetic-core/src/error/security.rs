//! Security validation error types (`KIN-SEC-NNN`).
//!
//! Provides strict telemetry errors for IP-based Server-Side Request Forgery attacks,
//! payload size limits, and path traversal blocks across all HTTP proxy layers.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Specifies the exact reason why a request was blocked by the security middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SecurityError {
    /// The IP address provided or resolved is a local loopback address (e.g., 127.0.0.1 or ::1).
    /// The proxy strictly prohibits connecting to the local machine to prevent Server-Side Request Forgery (SSRF).
    /// The request was dropped. Do not attempt to route proxy traffic back into the local node.
    #[error("Loopback address detected")]
    Loopback,
    
    /// The IP address is in a private subnet (e.g., 10.0.0.0/8, 192.168.0.0/16).
    /// The proxy blocks connections to private LAN IPs to prevent attackers from mapping or exploiting internal networks.
    /// The request was dropped.
    #[error("Private address detected")]
    Private,
    
    /// The IP address is the unspecified address (e.g., 0.0.0.0 or ::).
    /// Connecting to the unspecified address can sometimes bypass OS-level firewalls or route to localhost.
    /// The request was dropped.
    #[error("Unspecified network address")]
    Unspecified,
    
    /// The IP address is inside a Carrier-Grade NAT block (e.g., 100.64.0.0/10).
    /// CGNAT addresses are typically not publicly routable and can be abused to exploit ISP infrastructure.
    /// The request was dropped.
    #[error("Carrier-Grade NAT detected")]
    CgNat,
    
    /// The IP address routes locally via multicast, broadcast, or link-local routing.
    /// These addresses target the local network segment and are prohibited to prevent lateral network scanning.
    /// The request was dropped.
    #[error("Multicast, broadcast, or link-local address")]
    LocalNetworkRouting,
    
    /// The IP address is an IPv6 address that maps or translates directly to an internal IPv4 address.
    /// This is a common SSRF technique to bypass naive IPv4 filtering by encapsulating the attack payload in IPv6.
    /// The request was dropped.
    #[error("IPv4-mapped IPv6 address exploit")]
    Ipv6MappedExploit,
    
    /// The IP address uses NAT64 translation to mask an internal destination.
    /// NAT64 blocks can be abused to bypass IP filtering logic.
    /// The request was dropped.
    #[error("NAT64 translation block")]
    Nat64,
    
    /// The IP address is a reserved, experimental, or documentation address block.
    /// These addresses are not meant for public internet routing and are blocked to adhere to RFC 6890.
    /// The request was dropped.
    #[error("Reserved or documentation IP address")]
    Reserved,
    
    /// An NRS DNS resolution returned an A/AAAA record that points to a forbidden, internal IP address.
    /// An attacker registered a Kinetic domain pointing to a local IP to trick the proxy into launching an SSRF attack.
    /// The DNS resolution and request were immediately dropped.
    #[error("NRS A/AAAA record resolved to a forbidden IP address")]
    NrsSsrfBlocked,
    
    /// The HTTP proxy blocked a malicious path traversal attempt (e.g., `../`).
    /// Path traversal sequences can be used to escape routing boundaries and access unauthorized files or endpoints.
    /// Ensure all requested proxy paths are properly normalized.
    #[error("Path traversal attempt blocked")]
    PathTraversalAttempt,
    
    /// The HTTP request payload exceeds the maximum allowed size configured for the proxy.
    /// The daemon strictly limits request body sizes to prevent memory exhaustion and Denial of Service (DoS) attacks.
    /// Reduce the size of the payload or upload the data in smaller chunks.
    #[error("Proxy request payload exceeds maximum allowed size")]
    PayloadTooLarge,
    
    /// The HTTP method is unsupported or blocked by the proxy layer.
    /// The proxy only supports standard web methods to prevent exotic HTTP verb smuggling.
    /// Use a standard HTTP method (GET, POST, PUT, DELETE, PATCH).
    #[error("Invalid HTTP method blocked by proxy")]
    InvalidMethod,
    
    /// The upstream backend server returned a response payload that exceeds the maximum safety limit.
    /// The proxy limits the size of forwarded responses to prevent the upstream server from exhausting the node's memory.
    /// The connection to the backend was terminated. Ensure the upstream service pages or chunks large responses.
    #[error("Proxy response payload exceeds maximum allowed size")]
    BackendResponseTooLarge,
    
    /// The Web2 proxy bridge resolved a target host to a dangerous or internal IP address.
    /// Even in standard Web2 mode, the daemon prevents you from inadvertently proxying traffic into malicious infrastructure.
    /// The request was dropped.
    #[error("Web2 Bridge target resolved to a dangerous IP")]
    DangerousIpBlocked,
    
    /// The daemon is running in Dev Mode and allowed proxy forwarding to a private IP address.
    /// This warning is emitted to remind developers that this behavior is intentionally insecure and strictly for local testing.
    /// Disable `--dev` flag in production environments.
    #[error("Dev mode allowed private IP forwarding")]
    DevModePrivateIp,
    
    /// The proxy detected a loop attempting to connect to the node's own backend port.
    /// Proxying traffic back into the daemon's own proxy or API ports causes infinite loops and resource exhaustion.
    /// The request was dropped. Ensure external routing logic does not resolve to the local Kinetic node.
    #[error("Proxy loop detected and blocked")]
    ProxyLoop,
}

impl SecurityError {
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
            Self::NrsSsrfBlocked => "KIN-SEC-009",
            Self::PathTraversalAttempt => "KIN-SEC-010",
            Self::PayloadTooLarge => "KIN-SEC-011",
            Self::InvalidMethod => "KIN-SEC-012",
            Self::BackendResponseTooLarge => "KIN-SEC-013",
            Self::DangerousIpBlocked => "KIN-SEC-014",
            Self::DevModePrivateIp => "KIN-SEC-015",
            Self::ProxyLoop => "KIN-SEC-016",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::DevModePrivateIp => Severity::Warning,
            _ => Severity::Critical,
        }
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
            Self::Unspecified => "Security block: Unspecified address proxying is prohibited.".to_string(),
            Self::CgNat => "Security block: Carrier-Grade NAT bypass exploit blocked.".to_string(),
            Self::LocalNetworkRouting => "Security block: Local network routing bypass exploit blocked.".to_string(),
            Self::Ipv6MappedExploit => "Security block: IPv4-mapped IPv6 bypass exploit blocked.".to_string(),
            Self::Nat64 => "Security block: NAT64 translation bypass exploit blocked.".to_string(),
            Self::Reserved => "Security block: Reserved IP address proxying is prohibited.".to_string(),
            Self::NrsSsrfBlocked => "Security block: Domain resolved to a prohibited internal IP address.".to_string(),
            Self::PathTraversalAttempt => "Security block: Malicious path traversal attempt blocked.".to_string(),
            Self::PayloadTooLarge => "Security block: Request payload size exceeded.".to_string(),
            Self::InvalidMethod => "Security block: Invalid HTTP method used.".to_string(),
            Self::BackendResponseTooLarge => "Security block: Backend response payload size exceeded.".to_string(),
            Self::DangerousIpBlocked => "Security block: Target resolved to a dangerous IP address.".to_string(),
            Self::DevModePrivateIp => "Warning: Forwarding to a private IP (allowed in dev mode only).".to_string(),
            Self::ProxyLoop => "Security block: Detected a loop attempting to connect to the node's own port.".to_string(),
        }
    }
}
