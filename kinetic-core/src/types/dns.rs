use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZone {
    #[serde(default)]
    pub records: std::collections::HashMap<String, Vec<DnsRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DnsRecord {
    A(std::net::Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    CNAME(String),
    TXT(String),
    PeerId(String),
    KID(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRoutingRecord {
    pub host_id: String,
    pub current_peer_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl HostRoutingRecord {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.host_id.as_bytes());
        bytes.extend_from_slice(self.current_peer_id.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}

impl DnsZone {
    pub fn parse_payload(payload: &[u8]) -> Result<Self, crate::error::DnsError> {
        let mut depth = 0;
        let mut in_string = false;
        let mut escape = false;
        for &b in payload {
            if escape {
                escape = false;
                continue;
            }
            match b {
                b'"' => in_string = !in_string,
                b'\\' if in_string => escape = true,
                b'{' | b'[' if !in_string => {
                    depth += 1;
                    if depth > 10 {
                        return Err(crate::error::DnsError::NestedTooDeeply);
                    }
                }
                b'}' | b']' if !in_string && depth > 0 => {
                    depth -= 1;
                }
                _ => {}
            }
        }

        let mut zone = serde_json::from_slice::<DnsZone>(payload)?;

        let mut lower_records = std::collections::HashMap::new();
        for (k, v) in zone.records.drain() {
            lower_records.insert(k.to_lowercase(), v);
        }
        zone.records = lower_records;

        zone.validate()?;
        Ok(zone)
    }

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
                    return Err(crate::error::DnsError::InvalidLabelCharacters(label.clone()));
                }
                for c in label.chars() {
                    if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                        return Err(crate::error::DnsError::InvalidLabelCharacters(label.clone()));
                    }
                }
            }

            let has_cname = records.iter().any(|r| matches!(r, DnsRecord::CNAME(_)));
            if has_cname && records.len() > 1 {
                return Err(crate::error::DnsError::InvalidCnameConfiguration(label.clone()));
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
                        if !kid_str.starts_with("did:kin:") {
                            return Err(crate::error::DnsError::InvalidKid(kid_str.clone()));
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

    #[test]
    fn test_parse_payload() {
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
}
