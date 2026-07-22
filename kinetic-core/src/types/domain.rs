//! Domain heartbeat payloads and DHT storage key derivation.
//!
//! Provides structures for domain heartbeats and SHA-256-based DHT key derivation
//! that implements M=32 redundant storage assignment.
//!
//! ## DHT Key Derivation
//!
//! Every domain is stored at `M_REDUNDANCY` (32) distinct DHT keys to improve availability
//! and resist single-peer failures. Each key is derived as:
//! `SHA-256(name_bytes || [i] || "{NETWORK_ID}-dht-v1")`
//!
//! The `{NETWORK_ID}` suffix prevents key collisions between different Kinetic TLD networks.

use super::names::normalize_name;
use crate::constants::M_REDUNDANCY;
use serde::{Deserialize, Serialize};

/// Represents a heartbeat proof indicating that a `.kin` domain is actively maintained by its owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Domain name associated with this heartbeat.
    pub name: String,
    /// Latest drand round number proving heartbeat recency.
    pub latest_drand_pulse: u64,
    /// Owner's ML-DSA-65 post-quantum signature over [`signable_bytes`](Heartbeat::signable_bytes).
    pub signature: Vec<u8>,
}

impl Heartbeat {
    /// Serializes this heartbeat payload into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `{NETWORK_ID}-heartbeat-v1` + `u32_be(name.len())` + `name_bytes` + `u64_be(latest_drand_pulse)`
    ///
    /// The `{NETWORK_ID}` prefix prevents heartbeat signatures from being replayed
    /// across different Kinetic TLD networks.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-heartbeat-v1").as_bytes();
        let mut bytes = Vec::with_capacity(prefix.len() + 4 + self.name.len() + 8);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_drand_pulse.to_be_bytes());
        bytes
    }
}

/// Derives the set of DHT storage keys for a given domain name.
///
/// Produces exactly [`M_REDUNDANCY`](crate::constants::M_REDUNDANCY) (32) distinct 32-byte keys
/// via `SHA-256(name_bytes || [i] || "{NETWORK_ID}-dht-v1")` for `i in 0..32`.
/// The name is normalized (lowercased, TLD-suffixed) before hashing.
///
/// The `{NETWORK_ID}` suffix ensures keys are unique per TLD network even if the same
/// domain name exists on multiple Kinetic-derived networks.
///
/// # Returns
///
/// A `Vec<[u8; 32]>` of length 32, each element being a unique Kademlia DHT key.
pub fn derive_storage_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update([i]);
        hasher.update(concat!(env!("KINETIC_NETWORK_ID"), "-dht-v1").as_bytes());

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

/// Derives the set of DHT heartbeat keys for a given domain name.
///
/// Produces exactly [`M_REDUNDANCY`](crate::constants::M_REDUNDANCY) (32) distinct 32-byte keys
/// via `SHA-256("{NETWORK_ID}-hb-v1" || name_bytes || [i])` for `i in 0..32`.
///
/// Heartbeat keys are intentionally in a different namespace from storage keys
/// (the prefix ordering differs) to prevent store/heartbeat key collisions.
///
/// # Returns
///
/// A `Vec<[u8; 32]>` of length 32, each element being a unique Kademlia heartbeat key.
pub fn derive_heartbeat_keys(name: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(concat!(env!("KINETIC_NETWORK_ID"), "-hb-v1").as_bytes());
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
