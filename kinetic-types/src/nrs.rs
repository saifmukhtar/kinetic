//! NRS zone definitions, record schemas, and host routing records.
//!
//! Defines the canonical representation of NRS zone files published to the Kinetic network.
//! In addition to standard internet record types (`A`, `AAAA`, `CNAME`, `TXT`), Kinetic NRS
//! supports decentralized primitives including P2P Peer IDs (`PeerId`), Kinetic Identity Documents (`KID`),
//! and IPFS content identifiers (`IPFS`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed NRS zone mapping subdomain labels to collections of [`NrsRecord`] entries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NrsZone {
    /// Mapping from subdomain label (e.g. `@`, `www`, `api`) to a list of associated NRS records.
    #[serde(default)]
    pub records: HashMap<String, Vec<NrsRecord>>,
}

/// Strongly typed NRS record variant supported by the Kinetic network resolver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum NrsRecord {
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
    /// Kinetic Identity Document (KID) reference pointing to an authorized identity document.
    KID(String),
    /// IPFS Content Identifier (CID) for decentralized static content delivery.
    IPFS(String),
    /// Fallback variant capturing unknown or future NRS record types.
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
    /// The Drand kyn kyn when this record was created.
    pub drand_kyn: u64,
    /// Owner signature over [`signable_bytes`](HostRoutingRecord::signable_bytes).
    pub signature: Vec<u8>,
}

impl HostRoutingRecord {
    /// Serializes the host routing record into length-prefixed bytes for signing.
    ///
    /// # Returns
    ///
    /// Concatenated byte vector prefixed with the network routing header string (`{network_id}-routing-v1`).
    pub fn signable_bytes(&self, network_salt: &[u8; 32]) -> Vec<u8> {
        let name_separator = b"-nrs-routing-v1";
        let mut bytes = Vec::with_capacity(
            network_salt.len()
                + name_separator.len()
                + 4
                + self.host_id.len()
                + 4
                + self.current_peer_id.len()
                + 8,
        );
        bytes.extend_from_slice(network_salt);
        bytes.extend_from_slice(name_separator);
        bytes.extend_from_slice(&(self.host_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.host_id.as_bytes());
        bytes.extend_from_slice(&(self.current_peer_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.current_peer_id.as_bytes());
        bytes.extend_from_slice(&self.drand_kyn.to_be_bytes());
        bytes
    }
}
