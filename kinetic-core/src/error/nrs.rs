//! NRS zone payload validation error types (`KIN-NRS-NNN`).
//!
//! Errors produced during [`NrsZone`](crate::types::nrs::NrsZone) parsing and record-level
//! validation. A NRS zone is the JSON payload embedded inside a Kinetic reveal record;
//! every field must pass these checks before the zone is stored in the DHT.
//!
//! The 50-record limit and JSON nesting depth cap enforce the 80 KB DHT record size ceiling.
use super::Severity;
use thiserror::Error;

/// Error type for NRS zone payloads and record validation.
#[derive(Error, Debug)]
pub enum NrsError {
    /// The NRS JSON payload could not be parsed.
    /// Ensure the payload is a valid JSON object adhering to the NRS zone schema.
    #[error("Failed to parse NRS zone: {0}")]
    ParseError(#[from] serde_json::Error),

    /// The zone contains more than the maximum allowed number of records (50).
    /// This strict bound prevents network bloat and ensures fast DHT replication. Remove unnecessary records.
    #[error("Maximum of 50 NRS records allowed per zone to prevent network bloat")]
    TooManyRecords,

    /// A NRS label has an invalid length (empty or >62 chars).
    /// NRS labels must strictly adhere to RFC 1035 length limits.
    #[error("Invalid label length: {0}")]
    InvalidLabelLength(String),

    /// A NRS label contains invalid characters.
    /// NRS labels must contain only lowercase alphanumeric characters and internal hyphens (LDH rule).
    #[error("Invalid label character: {0}")]
    InvalidLabelCharacters(String),

    /// A CNAME record was provided alongside incompatible records.
    /// Per RFC 1034, a CNAME must be the only routing record for its label, except for cryptographic KID records which are allowed.
    #[error("CNAME record for '{0}' must be the only routing record (KID is allowed)")]
    InvalidCnameConfiguration(String),

    /// A TXT record exceeds the maximum allowed length (255 bytes).
    /// Break the data into multiple TXT records or host the payload on IPFS instead.
    #[error("TXT record too long for label {0}")]
    TxtRecordTooLong(String),

    /// A CNAME target is empty or too long.
    /// Ensure the CNAME target is a valid, fully-qualified domain name.
    #[error("CNAME target length invalid for label {0}")]
    InvalidCnameTarget(String),

    /// A PeerId string could not be parsed into a valid libp2p PeerId.
    /// Ensure the PeerId is correctly base58 encoded.
    #[error("Invalid PeerId string: {0}")]
    InvalidPeerId(String),

    /// A KID string does not start with the required `did:kin:` prefix.
    /// Ensure the KID strictly follows the Kinetic Decentralized Identifier specification.
    #[error("Invalid KID string (missing prefix): {0}")]
    InvalidKid(String),

    /// An IPFS CID string is invalid.
    /// Ensure the CID is a valid v0 or v1 IPFS Content Identifier.
    #[error("Invalid IPFS CID string: {0}")]
    InvalidIpfsCid(String),

    /// Multiple CNAME records are assigned to the same label.
    /// This strictly violates RFC 1034. A label may only point to a single canonical name.
    #[error("Multiple CNAME records found for label '{0}', which violates RFC 1034")]
    MultipleCnames(String),

    /// The upstream DNS resolver failed to complete a query via proxy.
    /// Check the network connection or the upstream DNS server's availability.
    #[error("Upstream resolve error: {0}")]
    UpstreamResolveError(String),

    /// The local node failed to send a DNS request to the upstream resolver.
    /// Ensure the network interface is up and the resolver IP is reachable.
    #[error("Failed to send request: {0}")]
    DnsRequestFailed(String),

    /// An internal execution error occurred in the NRS server binary.
    /// Review the node's system logs for the underlying failure cause.
    #[error("NRS Server execution error: {0}")]
    NrsServerExecutionError(String),

    /// The local node failed to resolve the DNS TXT seed domain for network bootstrapping.
    /// The node will be unable to discover peers automatically until DNS is restored.
    #[error("Failed to resolve DNS TXT seed domain or found no multiaddrs: {0}")]
    SeedDomainResolutionFailed(String),

    /// The local node failed to initialize the DNS resolver.
    /// Check the local system's `/etc/resolv.conf` or network configuration.
    #[error("Failed to initialize DNS resolver: {0}")]
    DnsResolverInitFailed(String),

    /// A standard DNS lookup failed for a specific domain.
    /// The domain may not exist, or the upstream nameserver is unreachable.
    #[error("DNS lookup failed for {0}: {1}")]
    DnsLookupFailed(String, String),

    /// The Kinetic Web2 Bridge failed to resolve a Kinetic name.
    /// This usually indicates the name is not registered or the DHT is unreachable.
    #[error("Web2 Bridge: Failed to resolve {0}: {1}")]
    Web2BridgeResolveFailed(String, String),

    /// The Kinetic Web2 Bridge successfully resolved a name, but no IPs were found in its NRS zone.
    /// Ensure the name's NRS zone contains valid A or AAAA records.
    #[error("Web2 Bridge: No IPs found for {0}")]
    Web2BridgeNoIpsFound(String),
}

impl PartialEq for NrsError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ParseError(a), Self::ParseError(b)) => a.to_string() == b.to_string(),
            (Self::TooManyRecords, Self::TooManyRecords) => true,
            (Self::InvalidLabelLength(a), Self::InvalidLabelLength(b)) => a == b,
            (Self::InvalidLabelCharacters(a), Self::InvalidLabelCharacters(b)) => a == b,
            (Self::InvalidCnameConfiguration(a), Self::InvalidCnameConfiguration(b)) => a == b,
            (Self::TxtRecordTooLong(a), Self::TxtRecordTooLong(b)) => a == b,
            (Self::InvalidCnameTarget(a), Self::InvalidCnameTarget(b)) => a == b,
            (Self::InvalidPeerId(a), Self::InvalidPeerId(b)) => a == b,
            (Self::InvalidKid(a), Self::InvalidKid(b)) => a == b,
            (Self::InvalidIpfsCid(a), Self::InvalidIpfsCid(b)) => a == b,
            (Self::MultipleCnames(a), Self::MultipleCnames(b)) => a == b,
            (Self::UpstreamResolveError(a), Self::UpstreamResolveError(b)) => a == b,
            (Self::DnsRequestFailed(a), Self::DnsRequestFailed(b)) => a == b,
            (Self::NrsServerExecutionError(a), Self::NrsServerExecutionError(b)) => a == b,
            (Self::SeedDomainResolutionFailed(a), Self::SeedDomainResolutionFailed(b)) => a == b,
            (Self::DnsResolverInitFailed(a), Self::DnsResolverInitFailed(b)) => a == b,
            (Self::DnsLookupFailed(d1, e1), Self::DnsLookupFailed(d2, e2)) => d1 == d2 && e1 == e2,
            (Self::Web2BridgeResolveFailed(d1, e1), Self::Web2BridgeResolveFailed(d2, e2)) => {
                d1 == d2 && e1 == e2
            }
            (Self::Web2BridgeNoIpsFound(a), Self::Web2BridgeNoIpsFound(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for NrsError {}

impl NrsError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MultipleCnames(_) => "KIN-NRS-001",
            Self::ParseError(_) => "KIN-NRS-002",
            Self::TooManyRecords => "KIN-NRS-003",
            Self::InvalidLabelLength(_) => "KIN-NRS-004",
            Self::InvalidLabelCharacters(_) => "KIN-NRS-005",
            Self::InvalidCnameConfiguration(_) => "KIN-NRS-006",
            Self::TxtRecordTooLong(_) => "KIN-NRS-007",
            Self::InvalidCnameTarget(_) => "KIN-NRS-008",
            Self::InvalidPeerId(_) => "KIN-NRS-009",
            Self::InvalidKid(_) => "KIN-NRS-010",
            Self::InvalidIpfsCid(_) => "KIN-NRS-011",
            Self::UpstreamResolveError(_) => "KIN-NRS-050",
            Self::DnsRequestFailed(_) => "KIN-NRS-051",
            Self::NrsServerExecutionError(_) => "KIN-NRS-052",
            Self::SeedDomainResolutionFailed(_) => "KIN-NRS-053",
            Self::DnsResolverInitFailed(_) => "KIN-NRS-054",
            Self::DnsLookupFailed(..) => "KIN-NRS-055",
            Self::Web2BridgeResolveFailed(..) => "KIN-NRS-056",
            Self::Web2BridgeNoIpsFound(_) => "KIN-NRS-057",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::NrsServerExecutionError(_) | Self::DnsResolverInitFailed(_) => Severity::Error,
            Self::UpstreamResolveError(_)
            | Self::DnsRequestFailed(_)
            | Self::SeedDomainResolutionFailed(_)
            | Self::DnsLookupFailed(..)
            | Self::Web2BridgeResolveFailed(..)
            | Self::Web2BridgeNoIpsFound(_) => Severity::Warning,
            _ => Severity::Warning, // Parsing failures are usually bad requests
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::UpstreamResolveError(_)
                | Self::DnsRequestFailed(_)
                | Self::SeedDomainResolutionFailed(_)
                | Self::DnsLookupFailed(..)
                | Self::Web2BridgeResolveFailed(..)
        )
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::ParseError(_) => "Failed to parse the NRS zone data.".to_string(),
            Self::TooManyRecords => {
                "The NRS zone contains too many records (maximum 50).".to_string()
            }
            Self::InvalidLabelLength(_) => "A NRS record label has an invalid length.".to_string(),
            Self::InvalidLabelCharacters(_) => {
                "A NRS record label contains invalid characters.".to_string()
            }
            Self::InvalidCnameConfiguration(_) => {
                "A CNAME record must be the only routing record for its label, except for cryptographic KID records.".to_string()
            }
            Self::TxtRecordTooLong(_) => {
                "A TXT record is too long (maximum 255 bytes).".to_string()
            }
            Self::InvalidCnameTarget(_) => "A CNAME target is invalid or too long.".to_string(),
            Self::InvalidPeerId(_) => "A PeerId string is invalid.".to_string(),
            Self::InvalidKid(_) => {
                "A KID string is invalid or missing the 'did:kin:' prefix.".to_string()
            }
            Self::InvalidIpfsCid(_) => "An IPFS CID string is invalid.".to_string(),
            Self::MultipleCnames(_) => {
                "Multiple CNAME records are not allowed for a single label.".to_string()
            }
            Self::UpstreamResolveError(_) => "Failed to resolve DNS query via upstream proxy.".to_string(),
            Self::DnsRequestFailed(_) => "Failed to send request to DNS resolver.".to_string(),
            Self::NrsServerExecutionError(_) => "NRS Server execution failed.".to_string(),
            Self::SeedDomainResolutionFailed(_) => "Failed to resolve network bootstrap seed domain.".to_string(),
            Self::DnsResolverInitFailed(_) => "Failed to initialize DNS resolver.".to_string(),
            Self::DnsLookupFailed(..) => "DNS lookup failed for the specified domain.".to_string(),
            Self::Web2BridgeResolveFailed(..) => "Kinetic Web2 Bridge failed to resolve the name.".to_string(),
            Self::Web2BridgeNoIpsFound(_) => "Kinetic Web2 Bridge found the name, but no IPs were assigned.".to_string(),
        }
    }
}
