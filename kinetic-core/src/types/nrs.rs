//! DNS zone models, record types, and host routing structures.
//!
//! Handles standard DNS record types ([`A`](NrsRecord::A), [`AAAA`](NrsRecord::AAAA), [`CNAME`](NrsRecord::CNAME), [`TXT`](NrsRecord::TXT))
//! as well as Kinetic-native decentralized record types ([`PeerId`](NrsRecord::PeerId), [`KID`](NrsRecord::KID), [`IPFS`](NrsRecord::IPFS)).

pub use kinetic_types::nrs::{HostRoutingRecord, NrsRecord, NrsZone};

/// Extension trait for NrsZone containing validation and parsing logic.
pub trait NrsZoneExt: Sized {
    /// Parses a raw JSON payload into a [`NrsZone`] and validates its structure.
    fn parse_payload(payload: &[u8]) -> Result<Self, crate::error::NrsError>;

    /// Validates all records within the DNS zone for structural correctness and network limits.
    fn validate(&self) -> Result<(), crate::error::NrsError>;
}

impl NrsZoneExt for NrsZone {
    /// Parses a raw JSON payload into a [`NrsZone`] and validates its structure.
    ///
    /// Uses `serde_json`'s built-in recursion limit to prevent
    /// stack-overflow DoS attacks ("JSON bombs") when handling untrusted network data.
    ///
    /// # Errors
    ///
    /// - Returns `JsonError` if JSON deserialization fails.
    /// - Returns `NrsError` variants from `validate` if the logical payload validation rules fail.
    fn parse_payload(payload: &[u8]) -> Result<Self, crate::error::NrsError> {
        let mut zone = serde_json::from_slice::<NrsZone>(payload)?;

        let mut lower_records: std::collections::HashMap<String, Vec<NrsRecord>> =
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
    /// - Returns [`NrsError::TooManyRecords`](crate::error::NrsError::TooManyRecords) if the zone contains more than 50 total records.
    /// - Returns [`NrsError::InvalidLabelLength`](crate::error::NrsError::InvalidLabelLength) if a label is empty or exceeds 63 characters.
    /// - Returns [`NrsError::InvalidLabelCharacters`](crate::error::NrsError::InvalidLabelCharacters) if a label contains invalid characters or leading/trailing hyphens.
    /// - Returns [`NrsError::InvalidCnameConfiguration`](crate::error::NrsError::InvalidCnameConfiguration) if a CNAME coexists with other records (except `KID`) on the same label.
    /// - Returns [`NrsError::TxtRecordTooLong`](crate::error::NrsError::TxtRecordTooLong) if a TXT record exceeds 255 bytes.
    /// - Returns [`NrsError::InvalidCnameTarget`](crate::error::NrsError::InvalidCnameTarget) if a CNAME target is empty or > 253 characters.
    /// - Returns [`NrsError::InvalidPeerId`](crate::error::NrsError::InvalidPeerId) if a `PeerId` string fails libp2p parsing.
    /// - Returns [`NrsError::InvalidKid`](crate::error::NrsError::InvalidKid) if a `KID` string does not begin with `did:kin:`.
    /// - Returns [`NrsError::InvalidIpfsCid`](crate::error::NrsError::InvalidIpfsCid) if an `IPFS` CID string is invalid.
    fn validate(&self) -> Result<(), crate::error::NrsError> {
        let total_records: usize = self.records.values().map(|vec| vec.len()).sum();
        if total_records > 50 {
            return Err(crate::error::NrsError::TooManyRecords);
        }

        for (label, records) in &self.records {
            if label.is_empty() || label.len() > 63 {
                return Err(crate::error::NrsError::InvalidLabelLength(label.clone()));
            }
            if label != "@" && label != "*" {
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(crate::error::NrsError::InvalidLabelCharacters(
                        label.clone(),
                    ));
                }
                for c in label.chars() {
                    if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                        return Err(crate::error::NrsError::InvalidLabelCharacters(
                            label.clone(),
                        ));
                    }
                }
            }

            let cname_count = records
                .iter()
                .filter(|r| matches!(r, NrsRecord::CNAME(_)))
                .count();
            if cname_count > 1 {
                return Err(crate::error::NrsError::MultipleCnames(label.clone()));
            }
            if cname_count > 0 {
                // By default (RFC 1034), a CNAME must be the only record on its label.
                // However, RFC 4035 (DNSSEC) explicitly allows cryptographic identity records
                // (like RRSIG and NSEC) to coexist with CNAMEs because they provide proof of identity
                // rather than conflicting routing data. We map this exception to Web3 by allowing
                // the `KID` (Kinetic Identity Document) record to coexist with a CNAME.
                let has_forbidden = records
                    .iter()
                    .any(|r| !matches!(r, NrsRecord::CNAME(_) | NrsRecord::KID(_)));
                if has_forbidden {
                    return Err(crate::error::NrsError::InvalidCnameConfiguration(
                        label.clone(),
                    ));
                }
            }

            for record in records {
                match record {
                    NrsRecord::A(_) | NrsRecord::AAAA(_) => {}
                    NrsRecord::TXT(txt) => {
                        if txt.len() > 255 {
                            return Err(crate::error::NrsError::TxtRecordTooLong(label.clone()));
                        }
                    }
                    NrsRecord::CNAME(cname) => {
                        if cname.is_empty() || cname.len() > 253 {
                            return Err(crate::error::NrsError::InvalidCnameTarget(label.clone()));
                        }
                        for c in cname.chars() {
                            if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
                                return Err(crate::error::NrsError::InvalidCnameTarget(
                                    label.clone(),
                                ));
                            }
                        }
                    }
                    NrsRecord::PeerId(peer_id_str) => {
                        use std::str::FromStr;
                        if libp2p_identity::PeerId::from_str(peer_id_str).is_err() {
                            return Err(crate::error::NrsError::InvalidPeerId(peer_id_str.clone()));
                        }
                    }
                    NrsRecord::KID(kid_str) => {
                        if !kid_str.starts_with(crate::constants::DID_PREFIX) {
                            return Err(crate::error::NrsError::InvalidKid(kid_str.clone()));
                        }
                    }
                    NrsRecord::IPFS(cid) => {
                        if cid.is_empty() || cid.len() > 100 {
                            return Err(crate::error::NrsError::InvalidIpfsCid(cid.clone()));
                        }
                        if !cid.starts_with("Qm") && !cid.starts_with('b') {
                            return Err(crate::error::NrsError::InvalidIpfsCid(cid.clone()));
                        }
                    }
                    NrsRecord::Other => {}
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::NrsError;

    #[test]
    fn test_parse_payload_success() {
        let json = r#"{"records": {"@": [{"type": "PeerId", "value": "12D3KooWNvSVhMTBqYq5AStb2H8s1uA5PpH8Zt9vEHQo6bC8vJ2K"}]}}"#;
        let zone = NrsZone::parse_payload(json.as_bytes()).unwrap();
        if let Some(records) = zone.records.get("@") {
            assert_eq!(records.len(), 1);
            if let NrsRecord::PeerId(ref pid) = records[0] {
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
        let mut zone = NrsZone::default();
        let mut records = Vec::new();
        for _ in 0..51 {
            records.push(NrsRecord::TXT("test".to_string()));
        }
        zone.records.insert("@".to_string(), records);

        let result = zone.validate();
        assert_eq!(result.unwrap_err(), NrsError::TooManyRecords);
    }

    #[test]
    fn test_error_invalid_label_length() {
        let mut zone = NrsZone::default();
        let long_label = "a".repeat(64);
        zone.records
            .insert(long_label.clone(), vec![NrsRecord::TXT("test".to_string())]);

        let result = zone.validate();
        assert_eq!(
            result.unwrap_err(),
            NrsError::InvalidLabelLength(long_label)
        );

        let mut zone_empty = NrsZone::default();
        zone_empty
            .records
            .insert("".to_string(), vec![NrsRecord::TXT("test".to_string())]);
        assert_eq!(
            zone_empty.validate().unwrap_err(),
            NrsError::InvalidLabelLength("".to_string())
        );
    }

    #[test]
    fn test_error_invalid_label_characters() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "-starts-with-hyphen".to_string(),
            vec![NrsRecord::TXT("test".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidLabelCharacters("-starts-with-hyphen".to_string())
        );

        let mut zone2 = NrsZone::default();
        zone2.records.insert(
            "invalid!char".to_string(),
            vec![NrsRecord::TXT("test".to_string())],
        );
        assert_eq!(
            zone2.validate().unwrap_err(),
            NrsError::InvalidLabelCharacters("invalid!char".to_string())
        );
    }

    #[test]
    fn test_error_invalid_cname_configuration() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "www".to_string(),
            vec![
                NrsRecord::CNAME("target.kin".to_string()),
                NrsRecord::TXT("other record".to_string()),
            ],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidCnameConfiguration("www".to_string())
        );
    }

    #[test]
    fn test_cname_kid_coexistence() {
        // CNAME and KID are allowed to coexist (RFC 4035 / Web3 mapping)
        let mut zone = NrsZone::default();
        zone.records.insert(
            "www".to_string(),
            vec![
                NrsRecord::CNAME("target.kin".to_string()),
                NrsRecord::KID("did:kin:123".to_string()),
            ],
        );
        assert!(zone.validate().is_ok());
    }

    #[test]
    fn test_error_txt_record_too_long() {
        let mut zone = NrsZone::default();
        let long_txt = "a".repeat(256);
        zone.records
            .insert("@".to_string(), vec![NrsRecord::TXT(long_txt)]);
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::TxtRecordTooLong("@".to_string())
        );
    }

    #[test]
    fn test_error_invalid_cname_target() {
        let mut zone = NrsZone::default();
        let long_cname = "a".repeat(254);
        zone.records
            .insert("@".to_string(), vec![NrsRecord::CNAME(long_cname)]);
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidCnameTarget("@".to_string())
        );
    }

    #[test]
    fn test_error_invalid_peer_id() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "@".to_string(),
            vec![NrsRecord::PeerId("not-a-peer-id".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidPeerId("not-a-peer-id".to_string())
        );
    }

    #[test]
    fn test_error_invalid_kid() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "@".to_string(),
            vec![NrsRecord::KID("did:eth:123".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidKid("did:eth:123".to_string())
        );
    }
    #[test]
    fn test_error_multiple_cnames() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "www".to_string(),
            vec![
                NrsRecord::CNAME("target1.kin".to_string()),
                NrsRecord::CNAME("target2.kin".to_string()),
            ],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::MultipleCnames("www".to_string())
        );
    }

    #[test]
    fn test_error_invalid_cname_target_chars() {
        let mut zone = NrsZone::default();
        zone.records.insert(
            "www".to_string(),
            vec![NrsRecord::CNAME("https://hacker.com/?q=evil".to_string())],
        );
        assert_eq!(
            zone.validate().unwrap_err(),
            NrsError::InvalidCnameTarget("www".to_string())
        );
    }
}
