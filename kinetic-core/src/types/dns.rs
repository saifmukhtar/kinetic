//! DNS zone models, record types, and host routing structures.
//!
//! Handles standard DNS record types ([`A`](DnsRecord::A), [`AAAA`](DnsRecord::AAAA), [`CNAME`](DnsRecord::CNAME), [`TXT`](DnsRecord::TXT))
//! as well as Kinetic-native decentralized record types ([`PeerId`](DnsRecord::PeerId), [`KID`](DnsRecord::KID), [`IPFS`](DnsRecord::IPFS)).

use serde::{Deserialize, Serialize};

/// Represents a DNS zone mapping subdomain labels to lists of [`DnsRecord`] entries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZone {
    /// HashMap mapping dot-separated labels (e.g. `"@"`, `"blog"`) to record vectors.
    #[serde(default)]
    pub records: std::collections::HashMap<String, Vec<DnsRecord>>,
}

/// Supported DNS record types and their associated payload values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DnsRecord {
    /// Standard IPv4 address record.
    A(std::net::Ipv4Addr),
    /// Standard IPv6 address record.
    AAAA(std::net::Ipv6Addr),
    /// Canonical Name alias pointing to another domain.
    CNAME(String),
    /// Text record (max 255 bytes).
    TXT(String),
    /// libp2p PeerId record pointing to a P2P node address.
    PeerId(String),
    /// Key Identifier DID document reference (must begin with `did:kin:`).
    KID(String),
    /// InterPlanetary File System (IPFS) Content Identifier (CID).
    IPFS(String),
}

/// Host routing record mapping a host identifier to a P2P peer ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRoutingRecord {
    /// Unique host identifier string.
    pub host_id: String,
    /// Currently assigned libp2p PeerId.
    pub current_peer_id: String,
    /// Unix timestamp of record creation.
    pub timestamp: u64,
    /// Owner signature over [`signable_bytes`](HostRoutingRecord::signable_bytes).
    pub signature: Vec<u8>,
}

impl HostRoutingRecord {
    /// Serializes the host routing record into length-prefixed bytes for signing.
    ///
    /// # Returns
    ///
    /// Concatenated byte vector prefixed with the network routing header string.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-routing-v1").as_bytes();
        let mut bytes = Vec::with_capacity(
            prefix.len() + 4 + self.host_id.len() + 4 + self.current_peer_id.len() + 8,
        );
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&(self.host_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.host_id.as_bytes());
        bytes.extend_from_slice(&(self.current_peer_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.current_peer_id.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}

impl DnsZone {
    /// Parses a raw JSON payload into a [`DnsZone`] and validates its structure.
    ///
    /// Uses `serde_json`'s built-in recursion limit to prevent
    /// stack-overflow DoS attacks ("JSON bombs") when handling untrusted network data.
    ///
    /// # Errors
    ///
    /// - Returns `JsonError` if JSON deserialization fails.
    /// - Returns `DnsError` variants from `validate` if the logical payload validation rules fail.
    pub fn parse_payload(payload: &[u8]) -> Result<Self, crate::error::DnsError> {
        let mut zone = serde_json::from_slice::<DnsZone>(payload)?;

        let mut lower_records: std::collections::HashMap<String, Vec<DnsRecord>> =
            std::collections::HashMap::new();
        for (k, v) in zone.records.drain() {
            lower_records.entry(k.to_lowercase()).or_default().extend(v);
        }
        zone.records = lower_records;

        zone.validate()?;
        Ok(zone)
    }

    /// Validates all records within the DNS zone for structural correctness and network limits.
    ///
    /// # Errors
    ///
    /// - Returns [`DnsError::TooManyRecords`](crate::error::DnsError::TooManyRecords) if the zone contains more than 50 total records.
    /// - Returns [`DnsError::InvalidLabelLength`](crate::error::DnsError::InvalidLabelLength) if a label is empty or exceeds 63 characters.
    /// - Returns [`DnsError::InvalidLabelCharacters`](crate::error::DnsError::InvalidLabelCharacters) if a label contains invalid characters or leading/trailing hyphens.
    /// - Returns [`DnsError::InvalidCnameConfiguration`](crate::error::DnsError::InvalidCnameConfiguration) if a CNAME coexists with other records on the same label.
    /// - Returns [`DnsError::TxtRecordTooLong`](crate::error::DnsError::TxtRecordTooLong) if a TXT record exceeds 255 bytes.
    /// - Returns [`DnsError::InvalidCnameTarget`](crate::error::DnsError::InvalidCnameTarget) if a CNAME target is empty or > 253 characters.
    /// - Returns [`DnsError::InvalidPeerId`](crate::error::DnsError::InvalidPeerId) if a `PeerId` string fails libp2p parsing.
    /// - Returns [`DnsError::InvalidKid`](crate::error::DnsError::InvalidKid) if a `KID` string does not begin with `did:kin:`.
    /// - Returns [`DnsError::InvalidIpfsCid`](crate::error::DnsError::InvalidIpfsCid) if an `IPFS` CID string is invalid.
    pub fn validate(&self) -> Result<(), crate::error::DnsError> {
        let mut total_records = 0;

        for (label, records) in &self.records {
            total_records += records.len();
            if total_records > 50 {
                return Err(crate::error::DnsError::TooManyRecords);
            }
            if label.is_empty() || label.len() > 63 {
                return Err(crate::error::DnsError::InvalidLabelLength(label.clone()));
            }
            if label != "@" && label != "*" {
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(crate::error::DnsError::InvalidLabelCharacters(
                        label.clone(),
                    ));
                }
                for c in label.chars() {
                    if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                        return Err(crate::error::DnsError::InvalidLabelCharacters(
                            label.clone(),
                        ));
                    }
                }
            }

            let has_cname = records.iter().any(|r| matches!(r, DnsRecord::CNAME(_)));
            if has_cname && records.len() > 1 {
                return Err(crate::error::DnsError::InvalidCnameConfiguration(
                    label.clone(),
                ));
            }

            for record in records {
                match record {
                    DnsRecord::A(_) | DnsRecord::AAAA(_) => {}
                    DnsRecord::TXT(txt) => {
                        if txt.len() > 255 {
                            return Err(crate::error::DnsError::TxtRecordTooLong(label.clone()));
                        }
                    }
                    DnsRecord::CNAME(cname) => {
                        if cname.is_empty() || cname.len() > 253 {
                            return Err(crate::error::DnsError::InvalidCnameTarget(label.clone()));
                        }
                    }
                    DnsRecord::PeerId(peer_id_str) => {
                        use std::str::FromStr;
                        if libp2p_identity::PeerId::from_str(peer_id_str).is_err() {
                            return Err(crate::error::DnsError::InvalidPeerId(peer_id_str.clone()));
                        }
                    }
                    DnsRecord::KID(kid_str) => {
                        if !kid_str.starts_with(crate::constants::DID_PREFIX) {
                            tracing::warn!("Rejecting non-Kinetic DID CNAME: {}", kid_str);
                            return Err(crate::error::DnsError::InvalidKid(kid_str.clone()));
                        }
                    }
                    DnsRecord::IPFS(cid) => {
                        if cid.is_empty() || cid.len() > 100 {
                            return Err(crate::error::DnsError::InvalidIpfsCid(cid.clone()));
                        }
                        if !cid.starts_with("Qm") && !cid.starts_with('b') {
                            return Err(crate::error::DnsError::InvalidIpfsCid(cid.clone()));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DnsError;

    #[test]
    fn test_parse_payload_success() {
        let json = r#"{"records": {"@": [{"type": "PeerId", "value": "12D3KooWNvSVhMTBqYq5AStb2H8s1uA5PpH8Zt9vEHQo6bC8vJ2K"}]}}"#;
        let zone = DnsZone::parse_payload(json.as_bytes()).unwrap();
        if let Some(records) = zone.records.get("@") {
            assert_eq!(records.len(), 1);
            if let DnsRecord::PeerId(ref pid) = records[0] {
                assert_eq!(pid, "12D3KooWNvSVhMTBqYq5AStb2H8s1uA5PpH8Zt9vEHQo6bC8vJ2K");
            } else {
                panic!("Expected PeerId");
            }
        } else {
            panic!("Expected @ record");
        }
    }

    #[test]
    fn test_error_too_many_records() {
        let mut zone = DnsZone::default();
        let mut records = Vec::new();
        for _ in 0..51 {
            records.push(DnsRecord::TXT("test".to_string()));
        }
        zone.records.insert("@".to_string(), records);

        let result = zone.validate();
        assert_eq!(result.unwrap_err(), DnsError::TooManyRecords);
    }

    #[test]
    fn test_error_invalid_label_length() {
        let mut zone = DnsZone::default();
        let long_label = "a".repeat(64);
        zone.records
            .insert(long_label.clone(), vec![DnsRecord::TXT("test".to_string())]);

        let result = zone.validate();
        assert_eq!(
            result.unwrap_err(),
            DnsError::InvalidLabelLength(long_label)
        );

        let mut zone_empty = DnsZone::default();
        zone_empty
            .records
            .insert("".to_string(), vec![DnsRecord::TXT("test".to_string())]);
        assert_eq!(
            zone_empty.validate().unwrap_err(),
            DnsError::InvalidLabelLength("".to_string())
        );
    }

    #[test]
    fn test_error_invalid_label_characters() {
        let mut zone = DnsZone::default();
        zone.records.insert(
            "-starts-with-hyphen".to_string(),
            vec![DnsRecord::TXT("test".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::InvalidLabelCharacters("-starts-with-hyphen".to_string())
        );

        let mut zone2 = DnsZone::default();
        zone2.records.insert(
            "invalid!char".to_string(),
            vec![DnsRecord::TXT("test".to_string())],
        );
        assert_eq!(
            zone2.validate().unwrap_err(),
            DnsError::InvalidLabelCharacters("invalid!char".to_string())
        );
    }

    #[test]
    fn test_error_invalid_cname_configuration() {
        let mut zone = DnsZone::default();
        zone.records.insert(
            "www".to_string(),
            vec![
                DnsRecord::CNAME("target.kin".to_string()),
                DnsRecord::TXT("other record".to_string()),
            ],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::InvalidCnameConfiguration("www".to_string())
        );
    }

    #[test]
    fn test_error_txt_record_too_long() {
        let mut zone = DnsZone::default();
        let long_txt = "a".repeat(256);
        zone.records
            .insert("@".to_string(), vec![DnsRecord::TXT(long_txt)]);
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::TxtRecordTooLong("@".to_string())
        );
    }

    #[test]
    fn test_error_invalid_cname_target() {
        let mut zone = DnsZone::default();
        let long_cname = "a".repeat(254);
        zone.records
            .insert("@".to_string(), vec![DnsRecord::CNAME(long_cname)]);
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::InvalidCnameTarget("@".to_string())
        );
    }

    #[test]
    fn test_error_invalid_peer_id() {
        let mut zone = DnsZone::default();
        zone.records.insert(
            "@".to_string(),
            vec![DnsRecord::PeerId("not-a-peer-id".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::InvalidPeerId("not-a-peer-id".to_string())
        );
    }

    #[test]
    fn test_error_invalid_kid() {
        let mut zone = DnsZone::default();
        zone.records.insert(
            "@".to_string(),
            vec![DnsRecord::KID("did:eth:123".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            DnsError::InvalidKid("did:eth:123".to_string())
        );
    }
}
