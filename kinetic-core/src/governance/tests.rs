#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::logic::process_governance_message;
    use super::super::types::{
        GovernanceAction, GovernanceEffect, GovernanceState, PublicKeyBytes,
        SignedGovernanceMessage,
    };
    use kinetic_primitives::keys::KineticKeypair;

    fn get_root_sk() -> KineticKeypair {
        let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        KineticKeypair::from_seed(bytes.as_slice().try_into().unwrap())
    }

    fn generate_key(seed: u8) -> (KineticKeypair, PublicKeyBytes) {
        let bytes = [seed; 32];
        let signing_key = KineticKeypair::from_seed(&bytes);
        let verifying_key = signing_key.pubkey_bytes();
        (signing_key, verifying_key)
    }

    fn sign_action(msg: &SignedGovernanceMessage, signer: &KineticKeypair) -> Vec<u8> {
        let serialized = msg.to_bytes();
        signer.sign(&serialized)
    }

    #[test]
    fn test_prime_mappings() {
        let root_sk = get_root_sk();
        let current_kyn = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_kyn);

        let (_, target_pubkey) = generate_key(99);

        // Test invalid length
        let mut msg_invalid_len = SignedGovernanceMessage {
            action: GovernanceAction::MapPrime {
                name: "ab".to_string(),
                target_pubkey: target_pubkey.clone(),
            },
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        msg_invalid_len
            .signatures
            .push(sign_action(&msg_invalid_len, &root_sk));

        let err =
            process_governance_message(&mut state, &msg_invalid_len, msg_invalid_len.timestamp_kyn)
                .unwrap_err();
        assert!(
            matches!(err, crate::error::GovernanceError::InvalidPrimeLength),
            "Got error: {:?}",
            err
        );

        // Map 5 valid names
        for i in 0..5 {
            let name = (b'a' + i) as char;
            let mut msg = SignedGovernanceMessage {
                action: GovernanceAction::MapPrime {
                    name: name.to_string(),
                    target_pubkey: target_pubkey.clone(),
                },
                timestamp_kyn: current_kyn,
                signatures: vec![],
            };
            msg.signatures.push(sign_action(&msg, &root_sk));
            let effect = process_governance_message(&mut state, &msg, msg.timestamp_kyn).unwrap();

            if let Some(GovernanceEffect::PrimeMapped {
                name: mapped_name, ..
            }) = effect
            {
                assert_eq!(mapped_name, name.to_string());
            } else {
                panic!("Expected PrimeMapped");
            }
        }
    }

    #[test]
    fn test_rotate_root_key() {
        let root_sk = get_root_sk();
        let current_kyn = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_kyn);

        // Generate a new Root Key
        let (new_root_sk, new_root_pubkey) = generate_key(123);

        // Action 1: Rotate to the new Root Key (signed by current genesis root key)
        let mut rotate_msg = SignedGovernanceMessage {
            action: GovernanceAction::RotateRootKey {
                new_key: new_root_pubkey.clone(),
            },
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        rotate_msg
            .signatures
            .push(sign_action(&rotate_msg, &root_sk));

        let effect =
            process_governance_message(&mut state, &rotate_msg, rotate_msg.timestamp_kyn).unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::RootKeyRotated { .. })
        ));

        // The state should now have the new root key
        assert_eq!(state.get_root_key().unwrap(), new_root_pubkey);

        // Action 2: Try mapping a name using the OLD root key (should fail)
        let mut map_msg = SignedGovernanceMessage {
            action: GovernanceAction::MapPrime {
                name: "b".to_string(),
                target_pubkey: new_root_pubkey.clone(), // Doesn't matter
            },
            timestamp_kyn: current_kyn + 1, // Advance time so hash is different
            signatures: vec![],
        };
        map_msg.signatures.push(sign_action(&map_msg, &root_sk)); // signed with old key

        let err =
            process_governance_message(&mut state, &map_msg, map_msg.timestamp_kyn).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InvalidSignature
        ));

        // Action 3: Map a name using the NEW root key (should succeed)
        map_msg.signatures.clear();
        map_msg.signatures.push(sign_action(&map_msg, &new_root_sk)); // signed with NEW key

        let effect =
            process_governance_message(&mut state, &map_msg, map_msg.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::PrimeMapped { .. })));
    }

    use proptest::prelude::*;
    use proptest::string::string_regex;

    proptest! {
        #[test]
        fn test_fuzz_to_bytes(
            name in string_regex("[a-z0-9_-]{1,63}").unwrap(),
            timestamp in any::<u64>(),
        ) {
            let (_, target_pubkey) = generate_key(99);
            let action = GovernanceAction::MapPrime {
                name,
                target_pubkey,
            };

            let msg = SignedGovernanceMessage {
                action: action.clone(),
                timestamp_kyn: timestamp,
                signatures: vec![], // Signatures aren't part of canonical hash
            };

            // Ensure we don't panic on serialization of randomized but valid structure
            let bytes = msg.to_bytes();
            prop_assert!(!bytes.is_empty());

            // Ensure identical inputs produce identical bytes
            let msg_clone = msg.clone();
            prop_assert_eq!(&bytes, &msg_clone.to_bytes());

            // Ensure hash computation does not panic
            let hash = GovernanceState::hash_action(&msg);
            prop_assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_emergency_halt_resume() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = GovernanceState::new(current_kyn);
        state.active_root_key = Some(root_pubkey);

        assert!(!state.is_halted);
        assert_eq!(state.total_paused_kyns, 0);

        let mut halt_msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyHalt,
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        halt_msg.signatures.push(sign_action(&halt_msg, &root_sk));

        let effect =
            process_governance_message(&mut state, &halt_msg, halt_msg.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::NetworkHalted)));
        assert!(state.is_halted);

        let mut resume_msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyResume,
            timestamp_kyn: current_kyn + 1000,
            signatures: vec![],
        };
        resume_msg
            .signatures
            .push(sign_action(&resume_msg, &root_sk));

        let effect =
            process_governance_message(&mut state, &resume_msg, resume_msg.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::NetworkResumed)));
        assert!(!state.is_halted);
        assert_eq!(state.total_paused_kyns, 1000);
    }

    #[test]
    fn test_unmap_prime_name() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = GovernanceState::new(current_kyn);
        state.active_root_key = Some(root_pubkey);

        // Try to UnmapPrime (should fail)
        let mut fail_msg = SignedGovernanceMessage {
            action: GovernanceAction::UnmapPrime {
                name: "ab".to_string(),
            },
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        fail_msg.signatures.push(sign_action(&fail_msg, &root_sk));

        let err =
            process_governance_message(&mut state, &fail_msg, fail_msg.timestamp_kyn).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InvalidPrimeLength
        ));

        // First, successfully map the name so it exists in state
        let mut map_msg = SignedGovernanceMessage {
            action: GovernanceAction::MapPrime {
                name: "a".to_string(),
                target_pubkey: vec![0; 1952],
            },
            timestamp_kyn: current_kyn + 1,
            signatures: vec![],
        };
        map_msg.signatures.push(sign_action(&map_msg, &root_sk));
        let _ = process_governance_message(&mut state, &map_msg, map_msg.timestamp_kyn).unwrap();

        // Try to revoke a 1-character name (should succeed)
        let mut success_msg = SignedGovernanceMessage {
            action: GovernanceAction::UnmapPrime {
                name: "a".to_string(),
            },
            timestamp_kyn: current_kyn + 2,
            signatures: vec![],
        };
        success_msg
            .signatures
            .push(sign_action(&success_msg, &root_sk));

        let effect =
            process_governance_message(&mut state, &success_msg, success_msg.timestamp_kyn)
                .unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::PrimeUnmapped { .. })
        ));
    }

    #[test]
    fn test_replay_attack_prevention() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = GovernanceState::new(current_kyn);
        state.active_root_key = Some(root_pubkey);

        let mut msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyHalt,
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        msg.signatures.push(sign_action(&msg, &root_sk));

        // First submission succeeds
        let effect = process_governance_message(&mut state, &msg, msg.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::NetworkHalted)));

        // Resubmitting the exact same message triggers the new AlreadyExecuted taxonomy error
        let err = process_governance_message(&mut state, &msg, msg.timestamp_kyn).unwrap_err();
        assert!(
            matches!(err, crate::error::GovernanceError::AlreadyExecuted),
            "Expected AlreadyExecuted error on replay attack, got: {:?}",
            err
        );
    }

    #[test]
    fn test_infra_mappings() {
        let root_sk = get_root_sk();
        let current_kyn = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_kyn);
        let (_, target_pubkey) = generate_key(99);

        // Test invalid infra name
        let mut msg_invalid = SignedGovernanceMessage {
            action: GovernanceAction::MapInfra {
                name: "invalidname".to_string(),
                target_pubkey: target_pubkey.clone(),
            },
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        msg_invalid
            .signatures
            .push(sign_action(&msg_invalid, &root_sk));

        let err = process_governance_message(&mut state, &msg_invalid, msg_invalid.timestamp_kyn)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InvalidProtocolName
        ));

        // Test valid infra name
        let mut msg_valid = SignedGovernanceMessage {
            action: GovernanceAction::MapInfra {
                name: "seed".to_string(),
                target_pubkey: target_pubkey.clone(),
            },
            timestamp_kyn: current_kyn,
            signatures: vec![],
        };
        msg_valid.signatures.push(sign_action(&msg_valid, &root_sk));
        let effect =
            process_governance_message(&mut state, &msg_valid, msg_valid.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::InfraMapped { .. })));
    }

    #[test]
    fn test_stale_proposal() {
        let root_sk = get_root_sk();
        let current_kyn = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_kyn);

        // Create a message that is exactly MAX_AGE_KYNS + 1 old
        let stale_kyn = current_kyn - crate::constants::MAX_AGE_KYNS - 1;

        let mut msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyHalt,
            timestamp_kyn: stale_kyn,
            signatures: vec![],
        };
        msg.signatures.push(sign_action(&msg, &root_sk));

        let err = process_governance_message(&mut state, &msg, current_kyn).unwrap_err();
        assert!(matches!(err, crate::error::GovernanceError::StaleProposal));
    }
}
