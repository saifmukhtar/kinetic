use crate::error::SignatureVerifyError;
use kinetic_types::name_record::NameRecord;
use kinetic_types::vdf::Reveal;

/// Extension trait for verifying post-quantum signatures over Kinetic payloads.
pub trait VerifySignature {
    /// Verifies the ML-DSA-65 post-quantum signature against the payload's canonical bytes.
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
            if kinetic_primitives::verify_mldsa(&self.pubkey, &auth_signable, &auth.owner_signature)
                .is_err()
            {
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
                if ck.key_type == "ML-DSA-65"
                    && let Ok(pubkey_bytes) = b64_url.decode(&ck.public_key)
                        && kinetic_primitives::verify_mldsa(
                            &pubkey_bytes,
                            &signable,
                            &self.signature,
                        )
                        .is_ok()
                        {
                            verified = true;
                            break;
                        }
            }

            if !verified {
                return Err(SignatureVerifyError::InvalidSignature);
            }
        } else if kinetic_primitives::verify_mldsa(&self.pubkey, &signable, &self.signature)
            .is_err()
        {
            return Err(SignatureVerifyError::InvalidSignature);
        }

        if let Some(prev) = &self.previous_proof {
            let prev_signable = prev.signable_bytes(network_salt);
            if kinetic_primitives::verify_mldsa(&self.pubkey, &prev_signable, &prev.signature)
                .is_err()
            {
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
                        if ck.key_type == "ML-DSA-65"
                            && let Ok(pubkey_bytes) = b64_url.decode(&ck.public_key)
                                && kinetic_primitives::verify_mldsa(
                                    &pubkey_bytes,
                                    &signable,
                                    signature,
                                )
                                .is_ok()
                                {
                                    verified = true;
                                    break;
                                }
                    }

                    if verified {
                        // 2. We also MUST verify that the Owner actually granted this capability.
                        let auth_signable = auth.signable_bytes(network_salt);
                        if kinetic_primitives::verify_mldsa(
                            pubkey,
                            &auth_signable,
                            &auth.owner_signature,
                        )
                        .is_err()
                        {
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
                    kinetic_primitives::verify_mldsa(pubkey, &signable, signature)
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

    fn generate_keypair() -> kinetic_primitives::keys::KineticKeypair {
        kinetic_primitives::keys::KineticKeypair::generate()
    }

    fn sign_payload(
        sk: &kinetic_primitives::keys::KineticKeypair,
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
        let sk = generate_keypair();
        let vk_bytes = sk.pubkey_bytes();
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let sig = sign_payload(&sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_ok());
    }

    #[test]
    fn test_prime_signature_invalid() {
        let sk = generate_keypair();
        let vk_bytes = sk.pubkey_bytes();
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let mut sig = sign_payload(&sk, name, payload, network_salt);

        // Corrupt the signature slightly
        sig[0] ^= 1;

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_err());
    }

    #[test]
    fn test_network_salt_isolation() {
        let sk = generate_keypair();
        let vk_bytes = sk.pubkey_bytes();
        let mainnet_salt = &[1u8; 32];
        let testnet_salt = &[2u8; 32];

        let name = "kin";
        let payload = b"data";

        let sig = sign_payload(&sk, name, payload, mainnet_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        // Verifying with TESTNET salt MUST fail
        assert!(record.verify_signature(testnet_salt).is_err());
    }

    fn generate_auth(
        owner_sk: &kinetic_primitives::keys::KineticKeypair,
        bot_vk_bytes: &[u8],
        capability: &str,
        network_salt: &[u8; 32],
    ) -> kinetic_types::identity::AuthorizedManifest {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};

        let dummy_did = kinetic_kid::did::Did::new(
            "did:kin:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut auth = kinetic_types::identity::AuthorizedManifest {
            name: "kin".to_string(),
            manifest: kinetic_kid::manifest::Manifest {
                doc_type: "kinetic.manifest.v1".to_string(),
                kid: dummy_did.clone(),
                version: 1,
                valid_from: 0,
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
                kid: dummy_did,
                created_at: 0,
                controller_keys: vec![kinetic_kid::document::ControllerKey {
                    id: "key-1".to_string(),
                    key_type: "ML-DSA-65".to_string(),
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
        auth.owner_signature = owner_sk.sign(&auth_signable);
        auth
    }

    #[test]
    fn test_delegated_signature_valid() {
        let owner_sk = generate_keypair();
        let owner_vk_bytes = owner_sk.pubkey_bytes();
        let bot_sk = generate_keypair();
        let bot_vk_bytes = bot_sk.pubkey_bytes();
        let network_salt = &[1u8; 32];

        let auth = generate_auth(
            &owner_sk,
            &bot_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );

        let name = "kin";
        let payload = b"data";

        // BOT signs the payload!
        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // Should pass since bot is authorized
        assert!(record.verify_signature(network_salt).is_ok());
    }

    #[test]
    fn test_fat_signature_missing_capability() {
        let owner_sk = generate_keypair();
        let owner_vk_bytes = owner_sk.pubkey_bytes();
        let bot_sk = generate_keypair();
        let bot_vk_bytes = bot_sk.pubkey_bytes();
        let network_salt = &[1u8; 32];

        // WRONG CAPABILITY!
        let auth = generate_auth(
            &owner_sk,
            &bot_vk_bytes,
            "kinetic.capability.chat",
            network_salt,
        );

        let name = "kin";
        let payload = b"data";

        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // MUST FAIL because capability is missing
        assert!(matches!(
            record.verify_signature(network_salt),
            Err(SignatureVerifyError::DelegatedCapabilityMissing)
        ));
    }

    #[test]
    fn test_fat_signature_invalid_owner_grant() {
        let owner_sk = generate_keypair();
        let owner_vk_bytes = owner_sk.pubkey_bytes();
        let bot_sk = generate_keypair();
        let bot_vk_bytes = bot_sk.pubkey_bytes();
        let network_salt = &[1u8; 32];

        let mut auth = generate_auth(
            &owner_sk,
            &bot_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );
        // Corrupt owner signature!
        auth.owner_signature[10] ^= 1;

        let name = "kin";
        let payload = b"data";

        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk_bytes,
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: Some(Box::new(auth)),
        };

        // MUST FAIL because owner grant is corrupt
        assert!(matches!(
            record.verify_signature(network_salt),
            Err(SignatureVerifyError::DelegatedAuthorizationInvalid)
        ));
    }

    #[test]
    fn test_fat_signature_cross_name_escalation() {
        let owner_sk = generate_keypair();
        let owner_vk_bytes = owner_sk.pubkey_bytes();
        let bot_sk = generate_keypair();
        let bot_vk_bytes = bot_sk.pubkey_bytes();
        let network_salt = &[1u8; 32];

        // Owner authorizes the bot for "test-domain" ONLY
        let mut auth = generate_auth(
            &owner_sk,
            &bot_vk_bytes,
            "kinetic.capability.dns_update",
            network_salt,
        );
        auth.name = "test-domain".to_string();
        // Resign the auth object since we changed the name
        let auth_signable = auth.signable_bytes(network_salt);
        auth.owner_signature = owner_sk.sign(&auth_signable);

        // Bot tries to use this authorization to hijack "prod-domain" (which is also owned by the same owner)
        let name = "prod-domain";
        let payload = b"malicious-payload";

        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk_bytes, // Owner's pubkey
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
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
        fn proptest_random_garbage_rejection(
            name in ".*",
            payload in any::<Vec<u8>>(),
            sig in any::<Vec<u8>>(),
            pubkey in any::<Vec<u8>>(),
        ) {
            let network_salt = &[0u8; 32];
            let record = NameRecord::Prime {
                name,
                pubkey,
                granted_at: 1234,
                payload,
                signature: sig,
                authorization: None,
            };

            // Should gracefully fail without panicking
            let _ = record.verify_signature(network_salt);
        }
    }

    #[test]
    fn test_reveal_serialization_and_verification() {
        let sk = generate_keypair();
        let vk_bytes = sk.pubkey_bytes();
        let network_salt = &[7u8; 32];

        let mut reveal = Reveal {
            protocol_version: 1,
            name: "isolated-test.kin".to_string(),
            payload: vec![10, 20, 30],
            salt: [3u8; 32],
            kyn: 9999,
            drand_signature: "aabbcc".to_string(),
            iterations: 500,
            vdf_proof: VdfProof {
                proof_bytes: vec![0, 0, 0],
            },
            pubkey: vk_bytes,
            signature: vec![],
            authorization: None,
            previous_proof: None,
            miner_pubkey: None,
        };

        // Sign the Reveal
        let signable = reveal.signable_bytes(network_salt);
        reveal.signature = sk.sign(&signable);

        // Must verify successfully
        assert!(reveal.verify_signature(network_salt).is_ok());

        // Corrupt signature
        reveal.signature[0] ^= 0xFF;
        assert!(matches!(
            reveal.verify_signature(network_salt),
            Err(SignatureVerifyError::InvalidSignature)
        ));
    }
}
