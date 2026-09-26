//! Name records, ownership models, and heartbeat proofs.
//!
//! On the Kinetic network, name ownership is structured into three distinct classes:
//!
//! 1. **Standard Names** ([`NameEnvelope::Standard`]): Registered trustlessly via Proof of Patience
//!    and Verifiable Delay Function (VDF) computation. Ownership is proven via the reveal record.
//!
//! To maintain active routing and prove name liveness, standard owners periodically publish [`Heartbeat`]
//! proofs signed with their `DelegatedPrivKey`s (or `ControllerPrivKey`s).

#![allow(clippy::collapsible_if)]
use kinetic_primitives::keypairs::IdentityPubKey;
use serde::{Deserialize, Serialize};

/// Represents a heartbeat proof indicating that a `.kin` name is actively maintained by its owner.
///
/// The network requires heartbeats to ensure that abandoned names do not permanently
/// pollute the active routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Name associated with this heartbeat.
    pub name: String,
    /// Latest Kyn number proving heartbeat recency.
    pub latest_kyn: kinetic_kyn::types::Kyn,
    /// Owner's cryptographic signature over [`signable_bytes`](Heartbeat::signable_bytes).
    #[serde(with = "crate::sig_serde::identity_sig_serde")]
    pub owner_signature: kinetic_primitives::keypairs::IdentitySignature,
    /// Optional delegated authorization proof (AuthorizedUpdate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Box<crate::identity::AuthorizedManifest>>,
}

impl Heartbeat {
    /// Generates the canonical byte representation of the heartbeat for signing.
    ///
    /// By deliberately binding the signature to both the `network_salt` and the literal `b"-heartbeat-v1"`, a heartbeat signed for
    /// the `.kin` network cannot be maliciously replayed on other networks.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::name_record::Heartbeat;
    ///
    /// let hb = Heartbeat {
    ///     name: "example".to_string(),
    ///     latest_kyn: kinetic_kyn::types::Kyn(12345),
    ///     owner_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
    ///     authorization: None,
    /// };
    /// let salt = [0x42; 32];
    /// let bytes = hb.signable_bytes(&salt);
    /// assert!(bytes.len() > 32);
    /// ```
    pub fn signable_bytes(&self, network_salt: &[u8; 32]) -> Vec<u8> {
        let name_separator = b"-heartbeat-v1";
        let auth_sig_len = match &self.authorization {
            Some(auth) => 4 + auth.owner_signature.len(),
            None => 0,
        };
        let mut bytes = Vec::with_capacity(
            network_salt.len() + name_separator.len() + 4 + self.name.len() + 8 + 1 + auth_sig_len,
        );
        bytes.extend_from_slice(network_salt);
        bytes.extend_from_slice(name_separator);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&self.latest_kyn.to_be_bytes());
        if let Some(auth) = &self.authorization {
            bytes.push(1);
            bytes.extend_from_slice(&(auth.owner_signature.len() as u32).to_be_bytes());
            bytes.extend_from_slice(auth.owner_signature.as_bytes());
        } else {
            bytes.push(0);
        }
        bytes
    }
}

/// Represents the different ways a name can be owned on the Kinetic network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type")]
pub enum NameEnvelope {
    /// A standard name registered via Proof of Patience and VDF.
    Standard(Box<crate::vdf::Reveal>),
}

impl NameEnvelope {
    /// Returns the name.
    pub fn name(&self) -> &str {
        match self {
            Self::Standard(r) => &r.name,
        }
    }

    /// Returns the public key of the owner.
    pub fn pubkey(&self) -> &IdentityPubKey {
        match self {
            Self::Standard(r) => &r.pubkey,
        }
    }

    /// Returns the zone payload.
    pub fn embedded_nrs(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.embedded_nrs,
        }
    }

    /// Returns the Identity signature over the payload.
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Standard(r) => r.identity_signature.as_bytes(),
        }
    }

    /// Returns the optional delegated authorization proof.
    pub fn authorization(&self) -> Option<&crate::identity::AuthorizedManifest> {
        match self {
            Self::Standard(r) => r.authorization.as_deref(),
        }
    }
}

/// Redundancy factor for DHT storage and heartbeat replication across the network.
pub const M_REDUNDANCY: u8 = 32;

/// Normalizes a given name string for consistent key derivation.
///
/// Converts the name to lowercase and strips trailing dots to ensure that
/// `Example.kin.` and `example.kin` route to the exact same DHT storage arrays.
///
/// # Examples
/// ```rust
/// use kinetic_types::name_record::normalize_name;
///
/// assert_eq!(normalize_name("EXAmple.kin."), "example.kin");
/// ```
pub fn normalize_name(name: &str) -> String {
    let mut norm = name.to_lowercase();
    while norm.ends_with('.') {
        norm.pop();
    }
    norm
}

/// Derives the set of DHT storage keys for a given name and network salt.
///
/// Produces exactly 32 distinct 32-byte keys via:
/// `SHA-256(network_salt || "storage" || normalized_name || [i])` for `i in 0..32`.
pub fn derive_storage_keys(name: &str, network_salt: &[u8; 32]) -> Vec<[u8; 32]> {
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut data = Vec::with_capacity(32 + 7 + normalized.len() + 1);
        data.extend_from_slice(network_salt);
        data.extend_from_slice(b"storage");
        data.extend_from_slice(normalized.as_bytes());
        data.push(i);

        keys.push(kinetic_primitives::sha256(&data));
    }
    keys
}

/// Derives the set of DHT heartbeat keys for a given name and network salt.
///
/// Produces exactly 32 distinct 32-byte keys via:
/// `SHA-256(network_salt || "heartbeat" || normalized_name || [i])` for `i in 0..32`.
pub fn derive_heartbeat_keys(name: &str, network_salt: &[u8; 32]) -> Vec<[u8; 32]> {
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut data = Vec::with_capacity(32 + 9 + normalized.len() + 1);
        data.extend_from_slice(network_salt);
        data.extend_from_slice(b"heartbeat");
        data.extend_from_slice(normalized.as_bytes());
        data.push(i);

        keys.push(kinetic_primitives::sha256(&data));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_storage_keys_consistency() {
        let network_salt = &[0u8; 32];
        let keys1 = derive_storage_keys("mywebsite.kin", network_salt);
        let keys2 = derive_storage_keys("MYWEBSITE.KIN.", network_salt);
        assert_eq!(keys1.len(), 32);
        assert_eq!(keys1, keys2);

        // Ensure each index key is unique
        for i in 0..keys1.len() {
            for j in i + 1..keys1.len() {
                assert_ne!(keys1[i], keys1[j]);
            }
        }
    }

    #[test]
    fn test_derive_heartbeat_keys_consistency() {
        let network_salt = &[0u8; 32];
        let hb_keys = derive_heartbeat_keys("mywebsite.kin", network_salt);
        let storage_keys = derive_storage_keys("mywebsite.kin", network_salt);
        assert_eq!(hb_keys.len(), 32);
        // Heartbeat keys must not collide with storage keys
        assert_ne!(hb_keys, storage_keys);
    }
}
