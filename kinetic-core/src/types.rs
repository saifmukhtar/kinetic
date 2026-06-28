use serde::{Serialize, Deserialize};

/// Normalizes a name by ensuring it is lowercase and ends with exactly one `.kin`.
pub fn normalize_name(name: &str) -> String {
    let mut norm = name.to_lowercase();
    while norm.ends_with('.') {
        norm.pop();
    }
    if !norm.ends_with(".kin") {
        norm.push_str(".kin");
    }
    norm
}

/// Validates that a name is exactly an apex domain (e.g., `saif.kin` and not `blog.saif.kin`)
pub fn is_valid_apex_name(name: &str) -> bool {
    let norm = normalize_name(name);
    norm.split('.').count() == 2
}

/// Extracts the apex domain from a potentially subdomain string.
/// For example, `blog.saif.kin` -> `saif.kin`
pub fn extract_apex_domain(name: &str) -> String {
    let norm = normalize_name(name);
    let parts: Vec<&str> = norm.split('.').collect();
    if parts.len() >= 2 {
        let last_two = &parts[parts.len() - 2..];
        format!("{}.{}", last_two[0], last_two[1])
    } else {
        norm
    }
}

/// Maximum age of a VDF proof in drand rounds (~1 year at 30s/round)
pub const RESQUARING_EPOCH_ROUNDS: u64 = 1_051_200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfProof {
    /// The serialized mathematical proof (e.g., from the Chia Class Group VDF)
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    pub name: String,
    pub commitment: Commitment,
}

fn default_protocol_version() -> u8 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
    /// The human-readable handle being registered
    pub name: String,
    /// The actual data bound to this name (e.g. an IP address)
    pub payload: Vec<u8>,
    /// The cryptographic salt used to prevent dictionary attacks prior to reveal
    pub salt: [u8; 32],
    /// The specific Drand pulse round number bound to this commitment
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    /// The VDF proof solving the sequential puzzle
    pub vdf_proof: VdfProof,
    /// The public key claiming this name
    pub pubkey: Vec<u8>,
    /// The signature of the reveal tuple to prevent front-running hijacking
    pub signature: Vec<u8>,
}

impl Reveal {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if self.protocol_version >= 2 {
            bytes.push(self.protocol_version);
        }
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.pubkey);
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub name: String,
    pub latest_drand_pulse: u64,
    pub signature: Vec<u8>,
}

impl Heartbeat {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_drand_pulse.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hibernation {
    pub name: String,
    pub drand_pulse: u64,
    pub drand_randomness: String,
    pub iterations: u64,
    pub vdf_proof: VdfProof,
    pub pubkey: Vec<u8>,
    pub salt: [u8; 32],
    pub signature: Vec<u8>,
}

impl Hibernation {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HIBERNATION");
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.drand_pulse.to_be_bytes());
        bytes.extend_from_slice(self.drand_randomness.as_bytes());
        bytes.extend_from_slice(&self.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.vdf_proof.proof_bytes);
        bytes.extend_from_slice(&self.pubkey);
        bytes.extend_from_slice(&self.salt);
        bytes
    }
}

pub const M_REDUNDANCY: u8 = 5;

/// Deterministically derive the `M` Kademlia DHT storage keys for a given name.
/// This prevents single-key eclipse attacks.
pub fn derive_storage_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Sha256, Digest};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);
    
    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update(&[i]);
        hasher.update(b"kinetic-dht-v1");
        
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}


pub fn load_or_create_keypair() -> Result<ed25519_dalek::SigningKey, crate::error::KineticError> {
    use std::path::PathBuf;
    use directories::ProjectDirs;
    use std::fs;

    let key_path = std::env::var("KINETIC_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            ProjectDirs::from("com", "kinetic", "kinetic")
                .map(|d| d.config_dir().join("id.bin"))
                .unwrap_or_else(|| PathBuf::from("/tmp/kinetic_id.bin"))
        });

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Ok(ed25519_dalek::SigningKey::from_bytes(&array));
        }
    }

    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        return Err(crate::error::KineticError::CryptoError("Random generation failed".to_string()));
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let _ = fs::write(&key_path, signing_key.to_bytes())?;
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys("alice.kin");
        assert_eq!(keys.len(), 5);
        
        // Ensure keys are unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
        
        // Ensure determinism
        let keys2 = derive_storage_keys("alice.kin");
        assert_eq!(keys, keys2);
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("SAIF.KIN"), "saif.kin");
        assert_eq!(normalize_name("saif..."), "saif.kin");
        assert_eq!(normalize_name("saif"), "saif.kin");
        assert_eq!(normalize_name("blog.saif.kin."), "blog.saif.kin");
    }

    #[test]
    fn test_is_valid_apex_name() {
        assert!(is_valid_apex_name("saif.kin"));
        assert!(is_valid_apex_name("saif")); // gets normalized
        assert!(!is_valid_apex_name("blog.saif.kin"));
    }

    #[test]
    fn test_extract_apex_domain() {
        assert_eq!(extract_apex_domain("blog.saif.kin"), "saif.kin");
        assert_eq!(extract_apex_domain("saif.kin"), "saif.kin");
        assert_eq!(extract_apex_domain("api.v1.saif.kin"), "saif.kin");
    }

    #[test]
    fn test_signable_bytes() {
        let reveal = Reveal {
            protocol_version: 2,
            name: "test.kin".to_string(),
            payload: vec![1, 2, 3],
            salt: [0u8; 32],
            drand_pulse: 100,
            drand_randomness: "random".to_string(),
            iterations: 1000,
            vdf_proof: VdfProof { proof_bytes: vec![4, 5, 6] },
            pubkey: vec![7, 8, 9],
            signature: vec![],
        };
        let bytes = reveal.signable_bytes();
        assert_eq!(bytes[0], 2); // Protocol version
        assert!(bytes.len() > 10);
    }
}

/// Represents a Decentralized DNS Zone stored in the DHT payload
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsZone {
    #[serde(default)]
    pub records: std::collections::HashMap<String, Vec<DnsRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DnsRecord {
    A(String),
    AAAA(String),
    CNAME(String),
    TXT(String),
    PeerId(String),
}

impl DnsZone {
    pub fn parse_payload(payload: &[u8]) -> Result<Self, crate::error::KineticError> {
        serde_json::from_slice::<DnsZone>(payload)
            .map_err(|e| crate::error::KineticError::ParseError(e))
    }
}

#[cfg(test)]
mod zone_tests {
    use super::*;

    #[test]
    fn test_parse_payload() {
        let json = r#"{"records": {"@": [{"type": "PeerId", "value": "12D3K"}]}}"#;
        let zone = DnsZone::parse_payload(json.as_bytes()).unwrap();
        if let Some(records) = zone.records.get("@") {
            assert_eq!(records.len(), 1);
            if let DnsRecord::PeerId(ref pid) = records[0] {
                assert_eq!(pid, "12D3K");
            } else {
                panic!("Expected PeerId");
            }
        } else {
            panic!("Expected @ record");
        }
    }
}
