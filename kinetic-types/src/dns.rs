//! DNS zone definitions, record schemas, and host routing records.
//!
//! Defines the canonical representation of DNS zone files published to the Kinetic network.
//! In addition to standard internet record types (`A`, `AAAA`, `CNAME`, `TXT`), Kinetic DNS
//! supports decentralized primitives including P2P Peer IDs (`PeerId`), Key Identifiers (`KID`),
//! and IPFS content identifiers (`IPFS`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed DNS zone mapping subdomain labels to collections of [`DnsRecord`] entries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZone {
    /// Mapping from subdomain label (e.g. `@`, `www`, `api`) to a list of associated DNS records.
    #[serde(default)]
    pub records: HashMap<String, Vec<DnsRecord>>,
}

/// Strongly typed DNS record variant supported by the Kinetic network resolver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DnsRecord {
    /// Standard IPv4 address record.
    A(std::net::Ipv4Addr),
    /// Standard IPv6 address record.
    AAAA(std::net::Ipv6Addr),
    /// Canonical Name record aliasing one domain to another.
    CNAME(String),
    /// Arbitrary text record for domain verification and metadata.
    TXT(String),
    /// libp2p Peer ID record for direct peer-to-peer transport routing.
    PeerId(String),
    /// Key Identifier (KID) reference pointing to an authorized identity document.
    KID(String),
    /// IPFS Content Identifier (CID) for decentralized static content delivery.
    IPFS(String),
    /// Fallback variant capturing unknown or future DNS record types.
    #[serde(other)]
    Other,
}

/// Host routing record mapping a decentralized host identifier to an active P2P peer ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRoutingRecord {
    /// Unique host identifier string.
    pub host_id: String,
    /// Currently assigned libp2p PeerId.
    pub current_peer_id: String,
    /// The Drand pulse round when this record was created.
    pub drand_pulse: u64,
    /// Owner signature over [`signable_bytes`](HostRoutingRecord::signable_bytes).
    pub signature: Vec<u8>,
}

impl HostRoutingRecord {
    /// Serializes the host routing record into length-prefixed bytes for signing.
    ///
    /// # Returns
    ///
    /// Concatenated byte vector prefixed with the network routing header string (`{network_id}-routing-v1`).
    pub fn signable_bytes(&self, network_id: &str) -> Vec<u8> {
        let prefix_suffix = b"-routing-v1";
        let mut bytes = Vec::with_capacity(
            network_id.len()
                + prefix_suffix.len()
                + 4
                + self.host_id.len()
                + 4
                + self.current_peer_id.len()
                + 8,
        );
        bytes.extend_from_slice(network_id.as_bytes());
        bytes.extend_from_slice(prefix_suffix);
        bytes.extend_from_slice(&(self.host_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.host_id.as_bytes());
        bytes.extend_from_slice(&(self.current_peer_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.current_peer_id.as_bytes());
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes
    }
}
