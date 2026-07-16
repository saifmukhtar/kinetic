use super::names::normalize_name;
use crate::constants::M_REDUNDANCY;
use serde::{Deserialize, Serialize};

/// Represents a heartbeat indicating that a domain is actively maintained.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub name: String,
    pub latest_drand_pulse: u64,
    pub signature: Vec<u8>,
}

impl Heartbeat {
    /// Serializes the heartbeat data into a byte vector for cryptographic signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.name.len() + 8);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_drand_pulse.to_be_bytes());
        bytes
    }
}

/// Derives a set of storage keys from a given domain name.
/// Returns a vector of 32-byte arrays representing the keys.
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

/// Derives a set of heartbeat keys from a given domain name.
/// Returns a vector of 32-byte arrays representing the keys.
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
    use crate::constants::TLD_SUFFIX;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys(&format!("{}{}", "saif", TLD_SUFFIX));
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
