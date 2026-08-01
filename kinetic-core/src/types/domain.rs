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

/// Represents the two different ways a domain can be owned on the Kinetic network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DomainRecord {
    /// A standard domain registered via Proof of Work and VDF.
    Standard(kinetic_verify::Reveal),
    /// A premium domain granted directly by the Governance Root Key.
    Premium {
        /// The domain name.
        name: String,
        /// The ML-DSA-65 public key of the domain owner.
        pubkey: Vec<u8>,
        /// The unix timestamp in seconds when this grant was approved.
        granted_at: u64,
        /// The zone payload associated with the domain.
        payload: Vec<u8>,
        /// The owner's ML-DSA-65 signature authorizing the payload.
        signature: Vec<u8>,
    },
}

impl DomainRecord {
    /// Returns the domain name.
    pub fn name(&self) -> &str {
        match self {
            Self::Standard(r) => &r.name,
            Self::Premium { name, .. } => name,
        }
    }

    /// Returns the public key of the owner.
    pub fn pubkey(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.pubkey,
            Self::Premium { pubkey, .. } => pubkey,
        }
    }

    /// Returns the zone payload.
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.payload,
            Self::Premium { payload, .. } => payload,
        }
    }

    /// Returns the ML-DSA-65 signature.
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.signature,
            Self::Premium { signature, .. } => signature,
        }
    }

    /// Verifies the ownership signature attached to this domain record.
    ///
    /// For [`Standard`](DomainRecord::Standard) records, this checks the owner's ML-DSA-65
    /// signature on the VDF reveal payload against the VDF parameters.
    /// For [`Premium`](DomainRecord::Premium) records, this verifies the owner's ML-DSA-65
    /// signature over the `name || payload || network_id` bytes to authenticate the zone payload.
    ///
    /// # Errors
    ///
    /// Returns [`KineticError::InvalidSignature`](crate::error::KineticError::InvalidSignature)
    /// if the signature fails cryptographic verification or if the public key or signature bytes
    /// are structurally malformed.
    pub fn verify_signature(&self, network_id: &str) -> Result<(), crate::error::KineticError> {
        match self {
            Self::Standard(reveal) => {
                reveal.verify_signature(network_id).map_err(|_| crate::error::KineticError::InvalidSignature)
            }
            Self::Premium { name, payload, signature, pubkey, .. } => {
                use ml_dsa::signature::Verifier;
                use ml_dsa::KeyInit;
                let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pubkey)
                    .map_err(|_| crate::error::KineticError::InvalidSignature)?;
                
                let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                    .map_err(|_| crate::error::KineticError::InvalidSignature)?;

                let mut signable = Vec::new();
                signable.extend_from_slice(name.as_bytes());
                signable.extend_from_slice(payload);
                signable.extend_from_slice(network_id.as_bytes());

                verifying_key.verify(&signable, &sig)
                    .map_err(|_| crate::error::KineticError::InvalidSignature)
            }
        }
    }
}

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
    pub fn signable_bytes(&self, network_id: &str) -> Vec<u8> {
        let prefix_suffix = b"-heartbeat-v1";
        let mut bytes = Vec::with_capacity(network_id.len() + prefix_suffix.len() + 4 + self.name.len() + 8);
        bytes.extend_from_slice(network_id.as_bytes());
        bytes.extend_from_slice(prefix_suffix);
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
        let keys = derive_storage_keys(&format!("{}{}", "saif", TLD_SUFFIX), env!("KINETIC_NETWORK_ID"));
        assert_eq!(keys.len(), 32);

        let keys2 = derive_storage_keys("SAIF.KIN", env!("KINETIC_NETWORK_ID"));
        assert_eq!(keys, keys2);

        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
}
