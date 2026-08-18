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
        use ml_dsa::KeyInit;
        use ml_dsa::signature::Verifier;
        let signable = self.signable_bytes(network_salt);

        let pubkey =
            ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(self.pubkey.as_slice())
                .map_err(|_| SignatureVerifyError::MalformedPublicKey)?;

        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(self.signature.as_slice())
            .map_err(|_| SignatureVerifyError::MalformedSignature)?;

        if let Some(auth) = &self.authorization {
            if auth.name != self.name {
                return Err(SignatureVerifyError::DelegatedScopeViolation);
            }

            let auth_signable = auth.signable_bytes(network_salt);
            let auth_sig =
                ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(auth.owner_signature.as_slice())
                    .map_err(|_| SignatureVerifyError::DelegatedAuthorizationInvalid)?;

            pubkey
                .verify(&auth_signable, &auth_sig)
                .map_err(|_| SignatureVerifyError::DelegatedAuthorizationInvalid)?;

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
                if ck.key_type == "ML-DSA-65" {
                    if let Ok(pk_bytes) = b64_url.decode(&ck.public_key) {
                        if let Ok(vk) =
                            ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(&pk_bytes)
                        {
                            if vk.verify(&signable, &sig).is_ok() {
                                verified = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !verified {
                return Err(SignatureVerifyError::InvalidSignature);
            }
        } else {
            pubkey
                .verify(&signable, &sig)
                .map_err(|_| SignatureVerifyError::InvalidSignature)?;
        }

        if let Some(prev) = &self.previous_proof {
            let prev_sig =
                ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(prev.signature.as_slice())
                    .map_err(|_| SignatureVerifyError::MalformedSignature)?;

            let prev_signable = prev.signable_bytes(network_salt);
            pubkey
                .verify(&prev_signable, &prev_sig)
                .map_err(|_| SignatureVerifyError::InvalidSignature)?;
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
                use ml_dsa::KeyInit;
                use ml_dsa::signature::Verifier;
                let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pubkey)
                    .map_err(|_| SignatureVerifyError::MalformedPublicKey)?;

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

                    let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                        .map_err(|_| SignatureVerifyError::MalformedSignature)?;

                    let kid_doc = auth
                        .kid_doc
                        .as_ref()
                        .ok_or(SignatureVerifyError::DelegatedKidDocumentMissing)?;

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
                        .map_err(|_| SignatureVerifyError::DelegatedAuthorizationInvalid)?;

                        verifying_key
                            .verify(&auth_signable, &auth_sig)
                            .map_err(|_| SignatureVerifyError::DelegatedAuthorizationInvalid)?;

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
                    verifying_key
                        .verify(
                            &signable,
                            &ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.as_slice())
                                .map_err(|_| SignatureVerifyError::MalformedSignature)?,
                        )
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

    fn generate_keypair() -> (
        ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    ) {
        use ml_dsa::Keypair;
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&seed).into());
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sign_payload(
        sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        name: &str,
        payload: &[u8],
        salt: &[u8],
    ) -> Vec<u8> {
        use ml_dsa::SignatureEncoding;
        use ml_dsa::signature::Signer;
        let mut signable = Vec::new();
        signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
        signable.extend_from_slice(name.as_bytes());
        signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        signable.extend_from_slice(payload);
        signable.extend_from_slice(salt);
        sk.sign(&signable).to_bytes().to_vec()
    }

    #[test]
    fn test_prime_signature_valid() {
        use ml_dsa::KeyExport;
        let (sk, vk) = generate_keypair();
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let sig = sign_payload(&sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk.to_bytes().to_vec(),
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_ok());
    }

    #[test]
    fn test_prime_signature_invalid() {
        use ml_dsa::KeyExport;
        let (sk, vk) = generate_keypair();
        let network_salt = &[1u8; 32];
        let name = "kin";
        let payload = b"dns-payload-data";

        let mut sig = sign_payload(&sk, name, payload, network_salt);

        // Corrupt the signature slightly
        sig[0] ^= 1;

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk.to_bytes().to_vec(),
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        assert!(record.verify_signature(network_salt).is_err());
    }

    #[test]
    fn test_network_salt_isolation() {
        use ml_dsa::KeyExport;
        let (sk, vk) = generate_keypair();
        let mainnet_salt = &[1u8; 32];
        let testnet_salt = &[2u8; 32];

        let name = "kin";
        let payload = b"data";

        let sig = sign_payload(&sk, name, payload, mainnet_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: vk.to_bytes().to_vec(),
            granted_at: 1000,
            payload: payload.to_vec(),
            signature: sig,
            authorization: None,
        };

        // Verifying with TESTNET salt MUST fail
        assert!(record.verify_signature(testnet_salt).is_err());
    }

    fn generate_auth(
        owner_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        bot_vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
        capability: &str,
        network_salt: &[u8; 32],
    ) -> kinetic_types::identity::AuthorizedManifest {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
        use ml_dsa::signature::Signer;
        use ml_dsa::{KeyExport, SignatureEncoding};

        let dummy_did = kinetic_kid::did::KineticDid::new(
            "did:kin:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let mut auth = kinetic_types::identity::AuthorizedManifest {
            name: "kin".to_string(),
            manifest: kinetic_kid::manifest::CapabilityManifest {
                doc_type: "kinetic.manifest.v1".to_string(),
                kid: dummy_did.clone(),
                version: 1,
                valid_from: 0,
                expires_at: None,
                services: vec![kinetic_kid::manifest::ServiceEntry {
                    id: "updater".to_string(),
                    service_type: capability.to_string(),
                    protocol: "https".to_string(),
                    endpoint: "https://example.com".to_string(),
                }],
                signature: None,
            },
            kid_doc: Some(kinetic_kid::document::KidDocument {
                doc_type: "kinetic.kid.v1".to_string(),
                kid: dummy_did,
                created_at: 0,
                controller_keys: vec![kinetic_kid::document::ControllerKey {
                    id: "key-1".to_string(),
                    key_type: "ML-DSA-65".to_string(),
                    public_key: b64_url.encode(bot_vk.to_bytes()),
                }],
                manifest: None,
                revocation_keys: vec![],
                deactivated: false,
                signature: None,
            }),
            owner_signature: vec![],
        };

        let auth_signable = auth.signable_bytes(network_salt);
        auth.owner_signature = owner_sk.sign(&auth_signable).to_bytes().to_vec();
        auth
    }

    #[test]
    fn test_fat_signature_valid() {
        use ml_dsa::KeyExport;
        let (owner_sk, owner_vk) = generate_keypair();
        let (bot_sk, bot_vk) = generate_keypair();
        let network_salt = &[1u8; 32];

        let auth = generate_auth(
            &owner_sk,
            &bot_vk,
            "kinetic.capability.dns_update",
            network_salt,
        );

        let name = "kin";
        let payload = b"data";

        // BOT signs the payload!
        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk.to_bytes().to_vec(),
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
        use ml_dsa::KeyExport;
        let (owner_sk, owner_vk) = generate_keypair();
        let (bot_sk, bot_vk) = generate_keypair();
        let network_salt = &[1u8; 32];

        // WRONG CAPABILITY!
        let auth = generate_auth(&owner_sk, &bot_vk, "kinetic.capability.chat", network_salt);

        let name = "kin";
        let payload = b"data";

        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk.to_bytes().to_vec(),
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
        use ml_dsa::KeyExport;
        let (owner_sk, owner_vk) = generate_keypair();
        let (bot_sk, bot_vk) = generate_keypair();
        let network_salt = &[1u8; 32];

        let mut auth = generate_auth(
            &owner_sk,
            &bot_vk,
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
            pubkey: owner_vk.to_bytes().to_vec(),
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
        use ml_dsa::KeyExport;
        let (owner_sk, owner_vk) = generate_keypair();
        let (bot_sk, bot_vk) = generate_keypair();
        let network_salt = &[1u8; 32];

        // Owner authorizes the bot for "test-domain" ONLY
        let mut auth = generate_auth(
            &owner_sk,
            &bot_vk,
            "kinetic.capability.dns_update",
            network_salt,
        );
        auth.name = "test-domain".to_string();
        // Resign the auth object since we changed the name
        use ml_dsa::SignatureEncoding;
        use ml_dsa::signature::Signer;
        let auth_signable = auth.signable_bytes(network_salt);
        auth.owner_signature = owner_sk.sign(&auth_signable).to_bytes().to_vec();

        // Bot tries to use this authorization to hijack "prod-domain" (which is also owned by the same owner)
        let name = "prod-domain";
        let payload = b"malicious-payload";

        let sig = sign_payload(&bot_sk, name, payload, network_salt);

        let record = NameRecord::Prime {
            name: name.to_string(),
            pubkey: owner_vk.to_bytes().to_vec(), // Owner's pubkey
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
            pk in any::<Vec<u8>>(),
        ) {
            let network_salt = &[0u8; 32];
            let record = NameRecord::Prime {
                name,
                pubkey: pk,
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
        use ml_dsa::KeyExport;
        let (sk, vk) = generate_keypair();
        let network_salt = &[7u8; 32];

        let mut reveal = Reveal {
            protocol_version: 1,
            name: "isolated-test.kin".to_string(),
            payload: vec![10, 20, 30],
            salt: [3u8; 32],
            drand_kyn: 9999,
            drand_signature: "aabbcc".to_string(),
            iterations: 500,
            vdf_proof: VdfProof {
                proof_bytes: vec![0, 0, 0],
            },
            pubkey: vk.to_bytes().to_vec(),
            signature: vec![],
            authorization: None,
            previous_proof: None,
            miner_pubkey: None,
        };

        // Sign the Reveal
        let signable = reveal.signable_bytes(network_salt);
        use ml_dsa::SignatureEncoding;
        use ml_dsa::signature::Signer;
        reveal.signature = sk.sign(&signable).to_bytes().to_vec();

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
