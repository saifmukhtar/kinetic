//! Name heartbeat payloads and DHT storage key derivation.
//!
//! Provides structures for name heartbeats and SHA-256-based DHT key derivation
//! that implements M=32 redundant storage assignment.
//!
//! ## DHT Key Derivation
//!
//! Every name is stored at `M_REDUNDANCY` (32) distinct DHT keys to improve availability
//! and resist single-peer failures. Each key is derived as:
//! `SHA-256(network_salt || "storage" || normalized_name || [i])`
//!
//! The `network_salt` prevents key collisions between different Kinetic NSP networks.

pub use kinetic_types::name_record::{
    Heartbeat, M_REDUNDANCY, NameRecord, derive_heartbeat_keys, derive_storage_keys,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NSP_SUFFIX;

    #[test]
    fn test_derive_storage_keys() {
        let keys = derive_storage_keys(
            &format!("{}{}", "saifmukhtar", NSP_SUFFIX),
            crate::constants::NETWORK_SALT,
        );
        assert_eq!(keys.len(), 32);

        let keys2 = derive_storage_keys("SAIFMUKHTAR.KIN", crate::constants::NETWORK_SALT);
        assert_eq!(keys, keys2);

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
}
