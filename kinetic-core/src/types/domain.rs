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


pub use kinetic_types::domain::DomainRecord;

pub use kinetic_types::domain::Heartbeat;

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
pub fn derive_storage_keys(name: &str, network_id: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hasher.update([i]);
        hasher.update(network_id.as_bytes());
        hasher.update(b"-dht-v1");

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
pub fn derive_heartbeat_keys(name: &str, network_id: &str) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(network_id.as_bytes());
        hasher.update(b"-hb-v1");
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
        let keys = derive_storage_keys(
            &format!("{}{}", "saifmukhtar", TLD_SUFFIX),
            env!("KINETIC_NETWORK_ID"),
        );
        assert_eq!(keys.len(), 32);

        let keys2 = derive_storage_keys("SAIFMUKHTAR.KIN", env!("KINETIC_NETWORK_ID"));
        assert_eq!(keys, keys2);

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
}
