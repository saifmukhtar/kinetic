use serde::{Deserialize, Serialize};

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

pub const KINETIC_TLDS: &[&str] = &[
    "co.uk.kin",
    "uk.kin",
    "co.kin",
    "id.kin",
    "app.kin",
    "dapp.kin",
    "kin",
];

/// Validates that a name is exactly an apex domain (e.g., `saif.kin` and not `blog.saif.kin`)
pub fn is_valid_apex_name(name: &str) -> bool {
    let norm = normalize_name(name);

    // DNS specification limits labels to 63 characters and total length to 253.
    if norm.len() > 253 || norm.is_empty() {
        return false;
    }
    for part in norm.split('.') {
        if part.len() > 63 || part.is_empty() {
            return false;
        }
    }

    let apex = extract_apex_domain(&norm);
    norm == apex
}

/// Extracts the apex domain from a potentially subdomain string.
/// For example, `blog.saif.kin` -> `saif.kin`
/// `blog.saif.co.uk.kin` -> `saif.co.uk.kin`
pub fn extract_apex_domain(name: &str) -> String {
    let norm = normalize_name(name);

    for tld in KINETIC_TLDS {
        if norm.ends_with(&format!(".{}", tld)) || norm == *tld {
            let without_tld = norm.strip_suffix(&format!(".{}", tld)).unwrap_or(&norm);
            if without_tld.is_empty() || without_tld == norm {
                return norm;
            }
            let parts: Vec<&str> = without_tld.split('.').collect();
            let apex_label = parts.last().unwrap_or(&"");
            return format!("{}.{}", apex_label, tld);
        }
    }

    // Fallback
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

/// Maximum allowed size for a Decentralized DNS Zone payload (64 KB)
pub const MAX_PAYLOAD_SIZE: usize = 65_536;

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

fn default_protocol_version() -> u8 {
    2
}

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
    pub fn validate(&self) -> Result<(), crate::error::KineticError> {
        if self.protocol_version != 2 {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid protocol version {}. Only protocol version 2 is supported.",
                self.protocol_version
            )));
        }

        if !crate::types::is_valid_apex_name(&self.name) {
            return Err(crate::error::KineticError::Internal(format!(
                "Invalid name '{}'. Only apex domains are allowed.",
                self.name
            )));
        }

        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(crate::error::KineticError::Internal(format!(
                "Payload size {} exceeds MAX_PAYLOAD_SIZE {}",
                self.payload.len(),
                MAX_PAYLOAD_SIZE
            )));
        }
        Ok(())
    }

    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Edge Case 29: Protocol Version is the absolute truth
        bytes.push(self.protocol_version);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub name: String,
    pub payload: Vec<u8>,
    pub delegated_to_pubkey: Vec<u8>,
    pub mobile_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub hashcash_nonce: u64,
}

impl DelegationRequest {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DELEGATION");
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.delegated_to_pubkey);
        bytes.extend_from_slice(&self.hashcash_nonce.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfJobRequest {
    pub challenge_hash: [u8; 32],
    pub name_length: u8,
    pub hashcash_nonce: u64,
    pub drand_pulse: u64,
}

pub const M_REDUNDANCY: u8 = 32;
pub const MIN_DIFFICULTY: u32 = 20; // Example minimum difficulty

/// Deterministically derive the `M` Kademlia DHT storage keys for a given name.
/// This prevents single-key eclipse attacks.
pub fn derive_storage_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update([i]);
        hasher.update(b"kinetic-dht-v1");

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

/// Derive the `M` Kademlia DHT keys for heartbeat liveness signals.
/// These are deliberately separate from `derive_storage_keys` so heartbeat records
/// never overwrite or pollute the Reveal keyspace used by resolvers.
pub fn derive_heartbeat_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(b"kinetic-hb-v1"); // distinct domain separator
        hasher.update(normalized.as_bytes());
        hasher.update([i]);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

pub fn load_or_create_keypair() -> Result<ed25519_dalek::SigningKey, crate::error::KineticError> {
    use directories::ProjectDirs;
    use std::fs;
    use std::path::PathBuf;

    let key_path = std::env::var("KINETIC_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            ProjectDirs::from("com", "kinetic", "kinetic")
                .map(|d| d.config_dir().join("id.bin"))
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(".kinetic/id.bin")
                })
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
        } else {
            return Err(crate::error::KineticError::CryptoError(
                format!("Identity file is corrupted! Expected 32 bytes, found {}. Please restore from a backup or manually delete the file to generate a new identity.", bytes.len())
            ));
        }
    }

    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        return Err(crate::error::KineticError::CryptoError(
            "Random generation failed".to_string(),
        ));
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);

    // Atomic write to prevent file corruption during generation
    let tmp_path = key_path.with_extension("tmp");
    fs::write(&tmp_path, signing_key.to_bytes())?;
    fs::rename(tmp_path, &key_path)?;

    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys("saif.kin");
        assert_eq!(keys.len(), 32);

        // Ensure determinism
        let keys2 = derive_storage_keys("SAIF.KIN");
        assert_eq!(keys, keys2);

        // Ensure keys are unique
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
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
            vdf_proof: VdfProof {
                proof_bytes: vec![4, 5, 6],
            },
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
        // Prevent deeply nested JSON payloads from overflowing the stack on small mobile threads.
        // A DnsZone schema is flat (max depth ~4), so anything > 10 is malicious.
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
                        return Err(crate::error::KineticError::Internal(
                            "Payload rejected: JSON nested too deeply".to_string(),
                        ));
                    }
                }
                b'}' | b']' if !in_string && depth > 0 => {
                    depth -= 1;
                }
                _ => {}
            }
        }

        serde_json::from_slice::<DnsZone>(payload)
            .map_err(crate::error::KineticError::ParseError)
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
