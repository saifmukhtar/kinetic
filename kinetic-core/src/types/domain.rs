use serde::{Deserialize, Serialize};
use super::names::normalize_name;
use super::vdf::VdfProof;

pub const M_REDUNDANCY: u8 = 32;
pub const MIN_DIFFICULTY: u32 = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

pub fn derive_heartbeat_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(b"kinetic-hb-v1");
        hasher.update(normalized.as_bytes());
        hasher.update([i]);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::names::DOT_TLD;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys(&format!("{}{}", "saif", DOT_TLD));
        assert_eq!(keys.len(), 32);

        let keys2 = derive_storage_keys("SAIF.KIN");
        assert_eq!(keys, keys2);

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
}
