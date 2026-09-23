//! Name Resolution System (NRS) zone definitions, record schemas, and host routing records.
//!
//! Defines the canonical representation of NRS zone files published to the Kinetic network.
//! In addition to standard internet record types (`A`, `AAAA`, `CNAME`, `TXT`), Kinetic NRS
//! supports decentralized primitives including P2P Peer IDs (`PeerId`), Kinetic Identity Documents (`KID`),
//! and IPFS content identifiers (`IPFS`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed NRS zone mapping subname labels to collections of [`NrsRecord`] entries.
///
/// The zone acts identically to a traditional DNS zone file, but is published securely
/// into the Kinetic network's decentralized DHT.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NrsZone {
    /// Mapping from subname label (e.g., `@`, `www`, `api`) to a list of associated NRS records.
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
    /// Canonical Name record aliasing one name to another.
    CNAME(String),
    /// Arbitrary text record for name verification and metadata.
    TXT(String),
    /// Network peer identifier for direct peer-to-peer transport routing.
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
    /// Currently assigned P2P network peer ID.
    pub current_peer_id: String,
    /// The Kyn when this record was created.
    pub kyn: kinetic_kyn::types::TargetKyn,
    /// Host signature over [`signable_bytes`](HostRoutingRecord::signable_bytes).
    #[serde(with = "crate::sig_serde::delegated_sig_serde")]
    pub host_signature: kinetic_primitives::keypairs::DelegatedSignature,
}

impl HostRoutingRecord {
    /// Serializes the host routing record into a canonical byte string for host signature verification.
    ///
    /// The byte layout is:
    /// `network_salt` (32 bytes) + `b"-nrs-routing-v1"` + `u32_be(host_id.len())` + `host_bytes` + `u32_be(peer_id.len())` + `peer_bytes` + `u64_be(kyn)`
    ///
    /// # Security
    /// Enforces Cross-Network Replay Protection. By incorporating the 32-byte
    /// `network_salt` and the literal `b"-nrs-routing-v1"`, a routing record signed for
    /// the `.kin` network cannot be maliciously replayed on other networks.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::nrs::HostRoutingRecord;
    ///
    /// let routing = HostRoutingRecord {
    ///     host_id: "host-123".to_string(),
    ///     current_peer_id: "12D3KooW...".to_string(),
    ///     kyn: kinetic_kyn::types::Kyn(150000),
    ///     host_signature: vec![],
    /// };
    ///
    /// let salt = [0x42; 32];
    /// let bytes = routing.signable_bytes(&salt);
    /// assert!(bytes.len() > 32);
    /// ```
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
        bytes.extend_from_slice(&self.kyn.to_be_bytes());
        bytes
    }
}
