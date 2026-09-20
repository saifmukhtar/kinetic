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
            Self::Prime {
                name,
                payload,
                owner_signature,
                pubkey,
                authorization,
                ..
            }
            | Self::Infra {
                name,
                payload,
                owner_signature,
                pubkey,
                authorization,
                ..
            } => {
                let mut signable = Vec::new();
                signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
                signable.extend_from_slice(name.as_bytes());
                signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                signable.extend_from_slice(payload);
                signable.extend_from_slice(network_salt);

                // Note: The signature could either be from the Name Owner directly, OR from
                // an authorized delegated key (if `authorization` is present).
                if let Some(auth) = authorization {
                    if auth.name != *name {
                        return Err(SignatureVerifyError::DelegatedScopeViolation);
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
                            if temp_pubkey.verify(&signable, owner_signature).is_ok() {
                                verified = true;
                                break;
                            }
                        }
                    }

                    if verified {
                        // 2. We also MUST verify that the Owner actually granted this capability.
                        let auth_signable = auth.signable_bytes(network_salt);
                        if pubkey.verify(&auth_signable, &auth.owner_signature).is_err() {
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

                        Ok(())
                    } else {
                        Err(SignatureVerifyError::InvalidSignature)
                    }
                } else {
                    pubkey.verify(&signable, owner_signature)
                        .map_err(|_| SignatureVerifyError::InvalidSignature)
                }
            }
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
    fn test_prime_signature_valid() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let sig = sign_identity_payload(&identity_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_ok());
    }

    #[test]
    fn test_prime_signature_invalid() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let mut sig = sign_identity_payload(&identity_sk, name, payload, network_salt);

        // Corrupt the signature slightly
        sig[0] ^= 1;

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_err());
    }

    #[test]
    fn test_network_salt_isolation() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let mainnet_salt = &[1u8; 32];
        let testnet_salt = &[2u8; 32];

        let name = "kin";
        let payload = b"data";

        let sig = sign_identity_payload(&identity_sk, name, payload, mainnet_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: None,
        };

        // Verifying with TESTNET salt MUST fail
        assert!(record.verify_signature(testnet_salt).is_err());
    }

    fn generate_auth(
        identity_sk: &kinetic_primitives::kinetic_keypair::IdentityPrivKey,
        bot_vk_bytes: &[u8],
        capability: &str,
        network_salt: &[u8; 32],
    ) -> kinetic_types::identity::AuthorizedManifest {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};

        let mock_did = kinetic_kid::did::Did::new(
            "did:kin:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut auth = kinetic_types::identity::AuthorizedManifest {
            name: "kin".to_string(),
            manifest: kinetic_kid::manifest::Manifest {
                doc_type: "kinetic.manifest.v1".to_string(),
                kid: mock_did.clone(),
                version: 1,
                valid_from: kinetic_kyn::types::UTime(0),
                expires_at: None,
                services: vec![kinetic_kid::manifest::Service {
                    id: "updater".to_string(),
                    service_type: capability.to_string(),
                    protocol: "https".to_string(),
                    endpoint: "https://example.com".to_string(),
                }],
                signature: None,
            },
            kid_doc: Some(kinetic_kid::document::Document {
                doc_type: "kinetic.kid.v1".to_string(),
                kid: mock_did,
                created_at: kinetic_kyn::types::UTime(0),
                controller_keys: vec![kinetic_kid::document::ControllerKey {
                    id: "key-1".to_string(),
                    key_type: "Delegated".to_string(),
                    public_key: b64_url.encode(bot_vk_bytes),
                }],
                manifest: None,
                revocation_keys: vec![],
                deactivated: false,
                signature: None,
            }),
            owner_signature: vec![],
        };

        let auth_signable = auth.signable_bytes(network_salt);
        auth.owner_signature = identity_sk.sign(&auth_signable);
        auth
    }

    #[test]
    fn test_delegated_signature_valid() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let delegated_sk = generate_delegated_keypair();
        let delegated_vk_bytes = delegated_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];

        let auth = generate_auth(
            &identity_sk,
            &delegated_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );

        let name = "kin";
        let payload = b"data";

        // BOT signs the payload!
        let sig = sign_delegated_payload(&delegated_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // Should pass since bot is authorized
        assert!(record.verify_signature(network_salt).is_ok());
    }

    #[test]
    fn test_delegated_signature_missing_capability() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let delegated_sk = generate_delegated_keypair();
        let delegated_vk_bytes = delegated_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];

        // WRONG CAPABILITY!
        let auth = generate_auth(
            &identity_sk,
            &delegated_vk_bytes,
            "kinetic.capability.chat",
            network_salt,
        );

        let name = "kin";
        let payload = b"data";

        let sig = sign_delegated_payload(&delegated_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // MUST FAIL because capability is missing
        assert!(matches!(
            record.verify_signature(network_salt),
            Err(SignatureVerifyError::DelegatedCapabilityMissing)
        ));
    }

    #[test]
    fn test_delegated_signature_invalid_owner_grant() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let delegated_sk = generate_delegated_keypair();
        let delegated_vk_bytes = delegated_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];

        let mut auth = generate_auth(
            &identity_sk,
            &delegated_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );
        // Corrupt owner signature!
        auth.owner_signature[10] ^= 1;

        let name = "kin";
        let payload = b"data";

        let sig = sign_delegated_payload(&delegated_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes),
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // MUST FAIL because owner grant is corrupt
        assert!(matches!(
            record.verify_signature(network_salt),
            Err(SignatureVerifyError::DelegatedAuthorizationInvalid)
        ));
    }

    #[test]
    fn test_delegated_signature_cross_name_escalation() {
        let identity_sk = generate_identity_keypair();
        let identity_vk_bytes = identity_sk.to_pubkey().0;
        let delegated_sk = generate_delegated_keypair();
        let delegated_vk_bytes = delegated_sk.to_pubkey().0;
        let network_salt = &[1u8; 32];

        // Owner authorizes the bot for "test-domain" ONLY
        let mut auth = generate_auth(
            &identity_sk,
            &delegated_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );
        auth.name = "test-domain".to_string();
        // Resign the auth object since we changed the name
        let auth_signable = auth.signable_bytes(network_salt);
        auth.owner_signature = identity_sk.sign(&auth_signable);

        // Bot tries to use this authorization to illegally takeover "prod-domain" (which is also owned by the same owner)
        let name = "prod-domain";
        let payload = b"malicious-payload";

        let sig = sign_delegated_payload(&delegated_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(identity_vk_bytes), // Owner's pubkey
            kyn: kinetic_kyn::types::Kyn(1000),
            payload: payload.to_vec(),
            owner_signature: sig,
            authorization: Some(Box::new(auth)), // Bot attaches the valid auth for "test-domain"
        };

        // MUST FAIL because the auth object's name does not match the record's name
        assert!(matches!(
            record.verify_signature(network_salt),
            Err(SignatureVerifyError::DelegatedScopeViolation)
        ));
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn proptest_malformed_bytes_rejection(
            name in ".*",
            payload in any::<Vec<u8>>(),
            sig in any::<Vec<u8>>(),
            pubkey in any::<Vec<u8>>(),
        ) {
            let network_salt = &[0u8; 32];
            let record = NameRecord::Prime {
                name,
                pubkey: kinetic_primitives::kinetic_keypair::IdentityPubKey(pubkey),
                kyn: kinetic_kyn::types::Kyn(1234),
                payload,
                owner_signature: sig,
                authorization: None,
            };

            // Should gracefully fail without panicking
            let _ = record.verify_signature(network_salt);
        }
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
            drand_signature: "aabbcc".to_string(),
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
