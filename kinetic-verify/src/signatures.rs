//! Cryptographic signature verification for Kinetic network payloads.
//!
//! This module provides the [`VerifySignature`] extension trait, which ensures
//! that state-mutating payloads (like [`NameRecord`] mappings and [`Reveal`] actions)
//! possess mathematically valid Identity signatures before they are accepted.
//! 
//! It includes logic for direct Owner signatures as well as bounded Delegated identity signatures.

use crate::error::SignatureVerifyError;
use kinetic_types::name_record::NameRecord;
use kinetic_types::vdf::Reveal;

/// Extension trait for verifying Identity/Delegated signatures over Kinetic payloads.
pub trait VerifySignature {
    /// Verifies the Identity or Delegated signature against the payload's canonical bytes.
    ///
    /// # Errors
    ///
    /// - Returns [`SignatureVerifyError::InvalidSignature`] if the cryptographic verification fails.
    /// - Returns [`SignatureVerifyError::DelegatedScopeViolation`] if a delegated signature attempts to act outside its granted name.
    /// - Returns [`SignatureVerifyError::DelegatedCapabilityMissing`] if the delegated identity lacks the required capability.
    /// - Returns [`SignatureVerifyError::DelegatedKidDocumentMissing`] if the required Kinetic Identity Document is not provided.
    /// - Returns [`SignatureVerifyError::DelegatedAuthorizationInvalid`] if the root authorization signature is corrupt.
    ///
    /// # Security
    ///
    /// This function acts as the strict cryptographic boundary for the network. It must 
    /// perfectly serialize the signable byte payload—including the `network_salt`—before 
    /// verification to completely mitigate cross-network (e.g., testnet to mainnet) replay attacks.
    fn verify_signature(&self, network_salt: &[u8; 32]) -> Result<(), SignatureVerifyError>;
}

impl VerifySignature for Reveal {
    fn verify_signature(&self, network_salt: &[u8; 32]) -> Result<(), SignatureVerifyError> {
        let signable = self.signable_bytes(network_salt);

        if let Some(auth) = &self.authorization {
            if auth.name != self.name {
                return Err(SignatureVerifyError::DelegatedScopeViolation);
            }

            let auth_signable = auth.signable_bytes(network_salt);
            if self.pubkey.verify(&auth_signable, &auth.owner_signature).is_err() {
                return Err(SignatureVerifyError::DelegatedAuthorizationInvalid);
            }

            let has_cap = auth
                .manifest
                .services
                .iter()
                .any(|s| s.service_type == "kinetic.capability.dns_update");
            if !has_cap {
                return Err(SignatureVerifyError::DelegatedCapabilityMissing);
            }

            let kid_doc = auth
                .kid_doc
                .as_ref()
                .ok_or(SignatureVerifyError::DelegatedKidDocumentMissing)?;
            let mut verified = false;
            for ck in &kid_doc.controller_keys {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
                if ck.key_type == "Delegated"
                    && let Ok(pubkey_bytes) = b64_url.decode(&ck.public_key)
                {
                    let temp_pubkey = kinetic_primitives::kinetic_keypair::DelegatedPubKey(pubkey_bytes);
                    if temp_pubkey.verify(&signable, &self.identity_signature).is_ok() {
                        verified = true;
                        break;
                    }
                }
            }

            if !verified {
                return Err(SignatureVerifyError::InvalidSignature);
            }
        } else if self.pubkey.verify(&signable, &self.identity_signature).is_err() {
            return Err(SignatureVerifyError::InvalidSignature);
        }

        if let Some(prev) = &self.previous_proof {
            let prev_signable = prev.signable_bytes(network_salt);
            if self.pubkey.verify(&prev_signable, &prev.identity_signature).is_err() {
                return Err(SignatureVerifyError::InvalidSignature);
            }
        }

        Ok(())
    }
}

impl VerifySignature for NameRecord {
    fn verify_signature(&self, network_salt: &[u8; 32]) -> Result<(), SignatureVerifyError> {
        match self {
            Self::Standard(reveal) => reveal.verify_signature(network_salt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignatureVerifyError;
    use kinetic_types::name_record::NameRecord;
    use kinetic_types::vdf::{Reveal, VdfProof};

    fn generate_identity_keypair() -> kinetic_primitives::kinetic_keypair::IdentityPrivKey {
        kinetic_primitives::kinetic_keypair::IdentityPrivKey::generate()
    }

    fn generate_delegated_keypair() -> kinetic_primitives::kinetic_keypair::DelegatedPrivKey {
        kinetic_primitives::kinetic_keypair::DelegatedPrivKey::generate()
    }

    fn sign_identity_payload(
        sk: &kinetic_primitives::kinetic_keypair::IdentityPrivKey,
        name: &str,
        payload: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        let mut signable = Vec::new();
        signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
        signable.extend_from_slice(name.as_bytes());
        signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        signable.extend_from_slice(payload);
        signable.extend_from_slice(salt);
        sk.sign(&signable)
    }

    fn sign_delegated_payload(
        sk: &kinetic_primitives::kinetic_keypair::DelegatedPrivKey,
        name: &str,
        payload: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        let mut signable = Vec::new();
        signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
        signable.extend_from_slice(name.as_bytes());
        signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        signable.extend_from_slice(payload);
        signable.extend_from_slice(salt);
        sk.sign(&signable)
    }

    #[test]
    fn test_reveal_serialization_and_verification() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let network_salt = &[7u8; 32];

        let mut reveal = Reveal {
            protocol_version: 1,
            name: "isolated-test.kin".to_string(),
            payload: vec![10, 20, 30],
            salt: [3u8; 32],
            kyn: kinetic_kyn::types::Kyn(9999),
            beacon_signature: "aabbcc".to_string(),
            iterations: 500,
            vdf_proof: VdfProof {
                proof_bytes: vec![0, 0, 0],
            },
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            identity_signature: vec![],
            authorization: None,
            previous_proof: None,
        };

        // Sign the Reveal
        let signable = reveal.signable_bytes(network_salt);
        reveal.identity_signature = identity_sk.sign(&signable);

        // Must verify successfully
        assert!(reveal.verify_signature(network_salt).is_ok());

        // Corrupt signature
        reveal.identity_signature[0] ^= 0xFF;
        assert!(matches!(
            reveal.verify_signature(network_salt),
            Err(SignatureVerifyError::InvalidSignature)
        ));
    }
}
