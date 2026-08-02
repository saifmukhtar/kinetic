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

pub use kinetic_types::domain::{
    derive_heartbeat_keys, derive_storage_keys, DomainRecord, Heartbeat, M_REDUNDANCY,
};

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
