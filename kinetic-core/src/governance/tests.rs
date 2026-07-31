#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::logic::process_governance_message;
    use super::super::types::{
        GovernanceAction, GovernanceEffect, GovernanceState, PublicKeyBytes,
        SignedGovernanceMessage,
    };
    use ml_dsa::signature::SignatureEncoding as MlDsaSignatureEncoding;
    use ml_dsa::signature::{Keypair, Signer};
    use ml_dsa::{KeyExport, MlDsa65};

    fn get_root_sk() -> ml_dsa::SigningKey<MlDsa65> {
        let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        ml_dsa::SigningKey::<MlDsa65>::from_seed(bytes.as_slice().try_into().unwrap())
    }


    fn generate_key(seed: u8) -> (ml_dsa::SigningKey<MlDsa65>, PublicKeyBytes) {
        let bytes = [seed; 32];
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_seed((&bytes).into());
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        (signing_key, verifying_key)
    }

    fn sign_action(msg: &SignedGovernanceMessage, signer: &ml_dsa::SigningKey<MlDsa65>) -> Vec<u8> {
        let serialized = msg.to_canonical_bytes();
        let sig: ml_dsa::Signature<MlDsa65> = signer.sign(&serialized);
        MlDsaSignatureEncoding::to_bytes(&sig).into()
    }



    #[test]
    fn test_premium_grants() {
        let root_sk = get_root_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        let (_, target_pubkey) = generate_key(99);

        // Test invalid length
        let mut msg_invalid_len = SignedGovernanceMessage {
            action: GovernanceAction::GrantPremiumName {
                name: "ab".to_string(),
                target_pubkey: target_pubkey.clone(),
            },
            timestamp_sec: current_time,
            signatures: vec![],
        };
        msg_invalid_len
            .signatures
            .push(sign_action(&msg_invalid_len, &root_sk));

        let err = process_governance_message(&mut state, &msg_invalid_len).unwrap_err();
        assert!(
            matches!(err, crate::error::GovernanceError::InvalidPremiumNameLength),
            "Got error: {:?}",
            err
        );

        // Grant 5 valid names
        for i in 0..5 {
            let name = (b'a' + i) as char;
            let mut msg = SignedGovernanceMessage {
                action: GovernanceAction::GrantPremiumName {
                    name: name.to_string(),
                    target_pubkey: target_pubkey.clone(),
                },
                timestamp_sec: current_time,
                signatures: vec![],
            };
            msg.signatures.push(sign_action(&msg, &root_sk));
            let effect = process_governance_message(&mut state, &msg).unwrap();

            if let Some(GovernanceEffect::PremiumNameGranted {
                name: granted_name, ..
            }) = effect
            {
                assert_eq!(granted_name, name.to_string());
            } else {
                panic!("Expected PremiumNameGranted");
            }
        }

    }

    #[test]
    fn test_rotate_root_key() {
        let root_sk = get_root_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        // Generate a new Root Key
        let (new_root_sk, new_root_pubkey) = generate_key(123);

        // Action 1: Rotate to the new Root Key (signed by current genesis root key)
        let mut rotate_msg = SignedGovernanceMessage {
            action: GovernanceAction::RotateRootKey {
                new_key: new_root_pubkey.clone(),
            },
            timestamp_sec: current_time,
            signatures: vec![],
        };
        rotate_msg
            .signatures
            .push(sign_action(&rotate_msg, &root_sk));

        let effect = process_governance_message(&mut state, &rotate_msg).unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::RootKeyRotated { .. })
        ));

        // The state should now have the new root key
        assert_eq!(state.get_root_key().unwrap(), new_root_pubkey);

        // Action 2: Try granting a name using the OLD root key (should fail)
        let mut grant_msg = SignedGovernanceMessage {
            action: GovernanceAction::GrantPremiumName {
                name: "b".to_string(),
                target_pubkey: new_root_pubkey.clone(), // Doesn't matter
            },
            timestamp_sec: current_time + 1, // Advance time so hash is different
            signatures: vec![],
        };
        grant_msg.signatures.push(sign_action(&grant_msg, &root_sk)); // signed with old key

        let err = process_governance_message(&mut state, &grant_msg).unwrap_err();
        assert!(matches!(err, crate::error::GovernanceError::InsufficientSignatures));

        // Action 3: Grant a name using the NEW root key (should succeed)
        grant_msg.signatures.clear();
        grant_msg.signatures.push(sign_action(&grant_msg, &new_root_sk)); // signed with NEW key

        let effect = process_governance_message(&mut state, &grant_msg).unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::PremiumNameGranted { .. })
        ));
    }

    use proptest::prelude::*;
    use proptest::string::string_regex;

    proptest! {
        #[test]
        fn test_fuzz_to_canonical_bytes(
            name in string_regex("[a-z0-9_-]{1,63}").unwrap(),
            timestamp in any::<u64>(),
        ) {
            let (_, target_pubkey) = generate_key(99);
            let action = GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            };

            let msg = SignedGovernanceMessage {
                action: action.clone(),
                timestamp_sec: timestamp,
                signatures: vec![], // Signatures aren't part of canonical hash
            };

            // Ensure we don't panic on serialization of randomized but valid structure
            let bytes = msg.to_canonical_bytes();
            prop_assert!(!bytes.is_empty());

            // Ensure identical inputs produce identical bytes
            let msg_clone = msg.clone();
            prop_assert_eq!(&bytes, &msg_clone.to_canonical_bytes());

            // Ensure hash computation does not panic
            let hash = GovernanceState::hash_action(&msg);
            prop_assert_eq!(hash.len(), 32);
        }
    }

    #[test]
    fn test_emergency_halt_resume() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = GovernanceState::new(current_time);
        state.active_root_key = Some(root_pubkey);

        assert_eq!(state.is_halted, false);
        assert_eq!(state.total_paused_rounds, 0);

        let mut halt_msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyHalt,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        halt_msg.signatures.push(sign_action(&halt_msg, &root_sk));

        let effect = process_governance_message(&mut state, &halt_msg).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::NetworkHalted)));
        assert_eq!(state.is_halted, true);

        let mut resume_msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyResume {
                paused_rounds: 1000,
            },
            timestamp_sec: current_time + 1,
            signatures: vec![],
        };
        resume_msg.signatures.push(sign_action(&resume_msg, &root_sk));

        let effect = process_governance_message(&mut state, &resume_msg).unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::NetworkResumed)
        ));
        assert_eq!(state.is_halted, false);
        assert_eq!(state.total_paused_rounds, 1000);
    }

    #[test]
    fn test_revoke_premium_name() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = GovernanceState::new(current_time);
        state.active_root_key = Some(root_pubkey);

        // Try to revoke a 2-character name (should fail)
        let mut fail_msg = SignedGovernanceMessage {
            action: GovernanceAction::RevokePremiumName {
                name: "ab".to_string(),
            },
            timestamp_sec: current_time,
            signatures: vec![],
        };
        fail_msg.signatures.push(sign_action(&fail_msg, &root_sk));

        let err = process_governance_message(&mut state, &fail_msg).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InvalidPremiumNameLength
        ));

        // Try to revoke a 1-character name (should succeed)
        let mut success_msg = SignedGovernanceMessage {
            action: GovernanceAction::RevokePremiumName {
                name: "a".to_string(),
            },
            timestamp_sec: current_time + 1,
            signatures: vec![],
        };
        success_msg
            .signatures
            .push(sign_action(&success_msg, &root_sk));

        let effect = process_governance_message(&mut state, &success_msg).unwrap();
        assert!(matches!(
            effect,
            Some(GovernanceEffect::PremiumNameRevoked { .. })
        ));
    }
}
