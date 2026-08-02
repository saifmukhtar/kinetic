use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DNS Zone
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZone {
    /// Records
    #[serde(default)]
    pub records: HashMap<String, Vec<DnsRecord>>,
}

/// DNS Record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DnsRecord {
    /// IPv4
    A(std::net::Ipv4Addr),
    /// IPv6
    AAAA(std::net::Ipv6Addr),
    /// CNAME
    CNAME(String),
    /// TXT
    TXT(String),
    /// PeerId
    PeerId(String),
    /// KID
    KID(String),
    /// IPFS
    IPFS(String),
    /// Other
    #[serde(other)]
    Other,
}

/// Host routing record mapping a host identifier to a P2P peer ID.
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
    /// Concatenated byte vector prefixed with the network routing header string.
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

