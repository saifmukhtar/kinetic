//! Name records, ownership models, and heartbeat proofs.
//!
//! On the Kinetic network, name ownership is structured into two distinct classes:
//!
//! 1. **Standard Names** ([`NameRecord::Standard`]): Registered trustlessly via Proof-of-Work
//!    and Verifiable Delay Function (VDF) computation. Ownership is proven via the reveal record.
//! 2. **Prime Names** ([`NameRecord::Prime`]): 1/2-character prime names granted directly
//!    by the Governance Root Authority key.
//!
//! To maintain active routing and prove name liveness, owners periodically publish [`Heartbeat`]
//! proofs signed with their ML-DSA-65 post-quantum private keys.

#![allow(clippy::collapsible_if)]
use serde::{Deserialize, Serialize};

/// Represents a heartbeat proof indicating that a `.kin` name is actively maintained by its owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Name associated with this heartbeat.
    pub name: String,
    /// Latest drand kyn number proving heartbeat recency.
    pub latest_drand_kyn: u64,
    /// Owner's ML-DSA-65 post-quantum signature over [`signable_bytes`](Heartbeat::signable_bytes).
    pub signature: Vec<u8>,
    /// Optional delegated authorization proof (Fat Heartbeat).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Box<crate::identity::AuthorizedManifest>>,
}

impl Heartbeat {
    /// Serializes this heartbeat payload into a canonical byte string for owner signature verification.
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
        bytes.extend_from_slice(&self.latest_drand_kyn.to_be_bytes());
        if let Some(auth) = &self.authorization {
            bytes.push(1);
            bytes.extend_from_slice(&(auth.owner_signature.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&auth.owner_signature);
        } else {
            bytes.push(0);
        }
        bytes
    }
}

/// Represents the two different ways a name can be owned on the Kinetic network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type")]
pub enum NameRecord {
    /// A standard name registered via Proof of Work and VDF.
    Standard(Box<crate::vdf::Reveal>),
    /// A 1/2-letter Prime name granted directly by the Governance Root Key. Requires heartbeats.
    Prime {
        /// The name.
        name: String,
        /// The ML-DSA-65 public key of the name owner.
        pubkey: Vec<u8>,
        /// The unix timestamp in kyns when this grant was approved.
        granted_at: u64,
        /// The zone payload associated with the name.
        payload: Vec<u8>,
        /// The owner's ML-DSA-65 signature authorizing the payload.
        signature: Vec<u8>,
        /// Optional delegated authorization proof for DNS updates.
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization: Option<Box<crate::identity::AuthorizedManifest>>,
    },
    /// An immortal Infrastructure name granted directly by the Governance Root Key. No heartbeats.
    Infra {
        /// The name.
        name: String,
        /// The ML-DSA-65 public key of the name owner.
        pubkey: Vec<u8>,
        /// The unix timestamp in kyns when this grant was approved.
        granted_at: u64,
        /// The zone payload associated with the name.
        payload: Vec<u8>,
        /// The owner's ML-DSA-65 signature authorizing the payload.
        signature: Vec<u8>,
        /// Optional delegated authorization proof for DNS updates.
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization: Option<Box<crate::identity::AuthorizedManifest>>,
    },
}

impl NameRecord {
    /// Returns the name.
    pub fn name(&self) -> &str {
        match self {
            Self::Standard(r) => &r.name,
            Self::Prime { name, .. } | Self::Infra { name, .. } => name,
        }
    }

    /// Returns the public key of the owner.
    pub fn pubkey(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.pubkey,
            Self::Prime { pubkey, .. } | Self::Infra { pubkey, .. } => pubkey,
        }
    }

    /// Returns the zone payload.
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.payload,
            Self::Prime { payload, .. } | Self::Infra { payload, .. } => payload,
        }
    }

    /// Returns the ML-DSA-65 signature.
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Standard(r) => &r.signature,
            Self::Prime { signature, .. } | Self::Infra { signature, .. } => signature,
        }
    }

    /// Verifies the ownership signature attached to this name record.
    pub fn verify_signature(
        &self,
        network_salt: &[u8; 32],
    ) -> Result<(), crate::vdf::VdfVerifyError> {
        match self {
            Self::Standard(reveal) => reveal.verify_signature(network_salt),
            Self::Prime {
                name,
                payload,
                signature,
                pubkey,
                authorization,
                ..
            }
            | Self::Infra {
                name,
                payload,
                signature,
                pubkey,
                authorization,
                ..
            } => {
                use ml_dsa::KeyInit;
                use ml_dsa::signature::Verifier;
                let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pubkey)
                    .map_err(|_| crate::vdf::VdfVerifyError::MalformedPublicKey)?;

                let mut signable = Vec::new();
                signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
                signable.extend_from_slice(name.as_bytes());
                signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                signable.extend_from_slice(payload);
                signable.extend_from_slice(network_salt);

                // Note: The signature could either be from the Name Owner directly, OR from
                // an authorized delegated key (if `authorization` is present).
                if let Some(auth) = authorization {
                    let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                        .map_err(|_| crate::vdf::VdfVerifyError::MalformedSignature)?;

                    let kid_doc = auth
                        .kid_doc
                        .as_ref()
                        .ok_or(crate::vdf::VdfVerifyError::DelegatedAuthorizationInvalid)?;

                    let mut verified = false;
                    for ck in &kid_doc.controller_keys {
                        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
                        if ck.key_type == "ML-DSA-65" {
                            if let Ok(pk_bytes) = b64_url.decode(&ck.public_key) {
                                if let Ok(vk) =
                                    ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(
                                        &pk_bytes,
                                    )
                                {
                                    if vk.verify(&signable, &sig).is_ok() {
                                        verified = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if verified {
                        // 2. We also MUST verify that the Owner actually granted this capability.
                        let auth_signable = auth.signable_bytes(network_salt);
                        let auth_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(
                            auth.owner_signature.as_slice(),
                        )
                        .map_err(|_| crate::vdf::VdfVerifyError::DelegatedAuthorizationInvalid)?;

                        verifying_key
                            .verify(&auth_signable, &auth_sig)
                            .map_err(|_| {
                                crate::vdf::VdfVerifyError::DelegatedAuthorizationInvalid
                            })?;

                        let has_cap = auth
                            .manifest
                            .services
                            .iter()
                            .any(|s| s.service_type == "kinetic.capability.dns_update");
                        if !has_cap {
                            return Err(crate::vdf::VdfVerifyError::DelegatedCapabilityMissing);
                        }

                        Ok(())
                    } else {
                        Err(crate::vdf::VdfVerifyError::InvalidSignature)
                    }
                } else {
                    verifying_key
                        .verify(
                            &signable,
                            &ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                                .map_err(|_| crate::vdf::VdfVerifyError::MalformedSignature)?,
                        )
                        .map_err(|_| crate::vdf::VdfVerifyError::InvalidSignature)
                }
            }
        }
    }
}

/// Redundancy factor for DHT storage and heartbeat replication across the network.
pub const M_REDUNDANCY: u8 = 32;

/// Normalizes a given name string for consistent key derivation.
/// Converts the name to lowercase and strips trailing dots.
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
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(network_salt);
        hasher.update(b"storage");
        hasher.update(normalized.as_bytes());
        hasher.update([i]);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        keys.push(key);
    }
    keys
}

/// Derives the set of DHT heartbeat keys for a given name and network salt.
///
/// Produces exactly 32 distinct 32-byte keys via:
/// `SHA-256(network_salt || "heartbeat" || normalized_name || [i])` for `i in 0..32`.
pub fn derive_heartbeat_keys(name: &str, network_salt: &[u8; 32]) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_name(name);
    let mut keys = Vec::with_capacity(M_REDUNDANCY as usize);

    for i in 0..M_REDUNDANCY {
        let mut hasher = Sha256::new();
        hasher.update(network_salt);
        hasher.update(b"heartbeat");
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
