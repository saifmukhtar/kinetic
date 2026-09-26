#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::logic::process_action_message;
    use super::super::types::{ActionEffect, ActionState, NetworkAction, SignedNetworkAction};
    
    use kinetic_primitives::keypairs::SovereignPrivKey;
    fn get_root_sk() -> SovereignPrivKey {
        let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        SovereignPrivKey::from_seed(bytes.as_slice().try_into().unwrap())
    }

    fn generate_key(
        seed: u8,
    ) -> (
        SovereignPrivKey,
        kinetic_primitives::keypairs::SovereignPubKey,
    ) {
        let bytes = [seed; 32];
        let signing_key = SovereignPrivKey::from_seed(&bytes);
        let verifying_key = signing_key.to_pubkey(); // Return strongly typed pubkey
        (signing_key, verifying_key)
    }

    fn sign_action(
        msg: &SignedNetworkAction,
        signer: &SovereignPrivKey,
    ) -> kinetic_primitives::keypairs::SovereignSignature {
        let serialized = msg.to_bytes();
        signer.sign(&serialized)
    }

    fn test_config() -> super::super::types::ActionConfig {
        super::super::types::ActionConfig {
            sovereign_key_hex: hex::encode(get_root_sk().to_pubkey().0),
            max_age_kyns: 100,
            is_dev_mode: false,
            action_model: "sovereign".to_string(),
        }
    }

    #[test]
    fn test_rotate_sovereign_key() {
        let root_sk = get_root_sk();
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = ActionState::new(kinetic_kyn::types::GenesisKyn::from(current_kyn));

        // Generate a new Sovereign Key
        let (new_root_sk, new_root_pubkey) = generate_key(123);

        // Action 1: Rotate to the new Sovereign Key (signed by current genesis Sovereign key)
        let mut rotate_msg = SignedNetworkAction {
            action: NetworkAction::RotateSovereignKey {
                new_key: new_root_pubkey.clone(),
            },
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(current_kyn),
            sovereign_signatures: vec![],
        };
        rotate_msg
            .sovereign_signatures
            .push(sign_action(&rotate_msg, &root_sk));

        let effect = process_action_message(
            &mut state,
            &rotate_msg,
            kinetic_kyn::types::CurrentKyn::from(*rotate_msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap();
        assert!(matches!(
            effect,
            Some(ActionEffect::SovereignKeyRotated { .. })
        ));

        // The state should now have the new Sovereign key
        assert_eq!(
            state.sovereign_key(&test_config()).unwrap(),
            new_root_pubkey.clone()
        );

        // Action 2: Try halting the network using the OLD Sovereign key (should fail)
        let mut map_msg = SignedNetworkAction {
            action: NetworkAction::EmergencyHalt,
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(current_kyn + 1), // Advance time so hash is different
            sovereign_signatures: vec![],
        };
        map_msg
            .sovereign_signatures
            .push(sign_action(&map_msg, &root_sk)); // signed with old key

        let err = process_action_message(
            &mut state,
            &map_msg,
            kinetic_kyn::types::CurrentKyn::from(*map_msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap_err();
        assert!(matches!(err, crate::error::ActionError::InvalidSignature));

        // Action 3: Halt the network using the NEW Sovereign key (should succeed)
        map_msg.sovereign_signatures.clear();
        map_msg
            .sovereign_signatures
            .push(sign_action(&map_msg, &new_root_sk)); // signed with NEW key

        let effect = process_action_message(
            &mut state,
            &map_msg,
            kinetic_kyn::types::CurrentKyn::from(*map_msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap();
        assert!(matches!(effect, Some(ActionEffect::NetworkHalted)));
    }

    use proptest::prelude::*;
    use proptest::string::string_regex;

    proptest! {
        #[test]
        fn test_fuzz_to_bytes(
            _name in string_regex("[a-z0-9_-]{1,63}").unwrap(),
            timestamp in any::<u64>(),
        ) {
            let action = NetworkAction::EmergencyHalt;

            let msg = SignedNetworkAction {
                action: action.clone(),
                timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(timestamp),
                sovereign_signatures: vec![], // Signatures aren't part of canonical hash
            };

            // Ensure we don't panic on serialization of randomized but valid structure
            let bytes = msg.to_bytes();
            prop_assert!(!bytes.is_empty());

            // Ensure identical inputs produce identical bytes
            let msg_clone = msg.clone();
            prop_assert_eq!(&bytes, &msg_clone.to_bytes());

            // Ensure hash computation does not panic
            let hash = ActionState::hash_action(&msg);
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

        let mut state = ActionState::new(kinetic_kyn::types::GenesisKyn::from(current_kyn));
        state.active_sovereign_key = Some(root_pubkey);

        assert!(!state.is_halted);
        assert_eq!(state.total_paused_kyns, 0);

        let mut halt_msg = SignedNetworkAction {
            action: NetworkAction::EmergencyHalt,
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(current_kyn),
            sovereign_signatures: vec![],
        };
        halt_msg
            .sovereign_signatures
            .push(sign_action(&halt_msg, &root_sk));

        let effect = process_action_message(
            &mut state,
            &halt_msg,
            kinetic_kyn::types::CurrentKyn::from(*halt_msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap();
        assert!(matches!(effect, Some(ActionEffect::NetworkHalted)));
        assert!(state.is_halted);

        let mut resume_msg = SignedNetworkAction {
            action: NetworkAction::EmergencyResume,
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(current_kyn + 1000),
            sovereign_signatures: vec![],
        };
        resume_msg
            .sovereign_signatures
            .push(sign_action(&resume_msg, &root_sk));

        let effect = process_action_message(
            &mut state,
            &resume_msg,
            kinetic_kyn::types::CurrentKyn::from(*resume_msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap();
        assert!(matches!(effect, Some(ActionEffect::NetworkResumed)));
        assert!(!state.is_halted);
        assert_eq!(state.total_paused_kyns, 1000);
    }

    #[test]
    fn test_replay_attack_prevention() {
        let (root_sk, root_pubkey) = generate_key(1);
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state = ActionState::new(kinetic_kyn::types::GenesisKyn::from(current_kyn));
        state.active_sovereign_key = Some(root_pubkey);

        let mut msg = SignedNetworkAction {
            action: NetworkAction::EmergencyHalt,
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(current_kyn),
            sovereign_signatures: vec![],
        };
        msg.sovereign_signatures.push(sign_action(&msg, &root_sk));

        // First submission succeeds
        let effect = process_action_message(
            &mut state,
            &msg,
            kinetic_kyn::types::CurrentKyn::from(*msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap();
        assert!(matches!(effect, Some(ActionEffect::NetworkHalted)));

        // Resubmitting the exact same message triggers the new AlreadyExecuted taxonomy error
        let err = process_action_message(
            &mut state,
            &msg,
            kinetic_kyn::types::CurrentKyn::from(*msg.timestamp_kyn),
            &test_config(),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::error::ActionError::AlreadyExecuted),
            "Expected AlreadyExecuted error on replay attack, got: {:?}",
            err
        );
    }

    #[test]
    fn test_stale_proposal() {
        let root_sk = get_root_sk();
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = ActionState::new(kinetic_kyn::types::GenesisKyn::from(current_kyn));

        // Create a message that is exactly MAX_AGE_KYNS + 1 old
        let stale_kyn = current_kyn - test_config().max_age_kyns - 1;

        let mut msg = SignedNetworkAction {
            action: NetworkAction::EmergencyHalt,
            timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(stale_kyn),
            sovereign_signatures: vec![],
        };
        msg.sovereign_signatures.push(sign_action(&msg, &root_sk));

        let err = process_action_message(
            &mut state,
            &msg,
            kinetic_kyn::types::CurrentKyn::from(current_kyn),
            &test_config(),
        )
        .unwrap_err();
        assert!(matches!(err, crate::error::ActionError::StaleProposal));
    }
}
