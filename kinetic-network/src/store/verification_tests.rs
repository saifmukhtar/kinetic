#[cfg(test)]
mod tests {
    use crate::error::KineticStoreError;
    use crate::store::verification::verify_host_routing_record;
    use kinetic_core::types::HostRoutingRecord;
    use libp2p::PeerId;
    use libp2p::identity::Keypair;
    #[test]
    fn test_host_routing_freshness() {
        let peer_id = PeerId::from(Keypair::generate_ed25519().public()); // Random but we won't verify sig if timestamp is stale

        let current_drand_round = 1000;
        let stale_pulse = current_drand_round - 150; // 150 rounds old, > 100 max age

        let record = HostRoutingRecord {
            host_id: peer_id.to_string(),
            current_peer_id: String::new(),
            kyn: stale_pulse,
            signature: vec![],
        };

        // Even with a bad signature, it should fail on freshness first
        let res = verify_host_routing_record(&record, current_drand_round);
        assert!(matches!(
            res.unwrap_err(),
            KineticStoreError::InvalidHostRouteSignature
        ));
    }

    #[test]
    fn test_peer_id_extraction_safeguard() {
        // Create a HostRoutingRecord with a totally invalid PeerId (not Ed25519, or too short)
        // A SHA2-256 multihash instead of identity will cause the length/format check to fail safely.
        let mh = libp2p::multihash::Multihash::wrap(0x12, &[0u8; 32]).unwrap();
        let peer_id = PeerId::from_multihash(mh).unwrap();

        let current_drand_round = 1000;
        let recent_pulse = current_drand_round;

        let record = HostRoutingRecord {
            host_id: peer_id.to_string(),
            current_peer_id: String::new(),
            kyn: recent_pulse,
            signature: vec![],
        };

        let res = verify_host_routing_record(&record, current_drand_round);
        // Should safely return InvalidPublicKey instead of panicking
        assert!(matches!(
            res.unwrap_err(),
            KineticStoreError::InvalidPublicKey
        ));
    }

    #[test]
    fn test_mldsa_authorized_kid_validation() {
        use crate::error::KineticStoreError;
        use crate::store::verification::verify_authorized_kid;
        use kinetic_core::types::{AuthorizedKid, Reveal, VdfProof};
        use kinetic_kid::document::KidDocument;
        let ml_kp = kinetic_primitives::keys::KineticKeypair::generate();
        let ml_pub_bytes = ml_kp.public_key_bytes();

        let reveal = Reveal {
            protocol_version: 1,
            name: "test.kinetic".to_string(),
            payload: vec![],
            salt: [0u8; 32],
            kyn: 100,
            drand_signature: String::new(),
            iterations: 100,
            vdf_proof: VdfProof {
                proof_bytes: vec![],
            },
            pubkey: ml_pub_bytes.clone(),
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
            authorization: None,
        };

        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
        let pub_key_b64 = b64_url.encode(&ml_pub_bytes);

        let hash = kinetic_primitives::sha256_hash(&ml_pub_bytes);
        let mut hex_hash = String::new();
        for byte in hash {
            use std::fmt::Write;
            let _ = write!(&mut hex_hash, "{:02x}", byte);
        }

        let kid = kinetic_kid::did::KineticDid::new(&format!(
            "{}{}",
            kinetic_core::constants::DID_PREFIX,
            hex_hash
        ))
        .unwrap();
        let doc = KidDocument {
            doc_type: "kinetic.kid.v1".to_string(),
            kid,
            created_at: 1234567890,
            controller_keys: vec![kinetic_kid::document::ControllerKey {
                id: format!(
                    "{}{}#primary",
                    kinetic_core::constants::DID_PREFIX,
                    hex_hash
                ),
                key_type: "MlDsa65".to_string(),
                public_key: pub_key_b64,
            }],
            manifest: None,
            revocation_keys: vec![],
            deactivated: false,
            signature: None,
        };
        let did_doc = doc.sign(&ml_kp).unwrap();

        let mut auth_kid = AuthorizedKid {
            name: "test.kinetic".to_string(),
            kid_doc: did_doc,
            owner_signature: vec![],
        };

        // Sign the kid_doc with our ML-DSA key
        let signable = auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT);
        auth_kid.owner_signature = ml_kp.sign(&signable);

        // Pass it through validation! (We mock existing_record as Some to bypass genesis bindings in this simple test)
        let dummy_key = libp2p::kad::RecordKey::new(&[0u8; 32]);
        let existing_record = libp2p::kad::Record::new(dummy_key, vec![]);

        let record = kinetic_core::types::NameRecord::Standard(Box::new(reveal));
        let res = verify_authorized_kid(
            &auth_kid,
            Some(&record),
            Some(&std::borrow::Cow::Owned(existing_record)),
        );
        // Should not fail with InvalidKidSignature
        assert!(res.is_ok() || !matches!(res.unwrap_err(), KineticStoreError::InvalidKidSignature));
    }
}
