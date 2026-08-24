    #[test]
    fn test_infra_mappings() {
        let root_sk = get_root_sk();
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
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
        msg_invalid.signatures.push(sign_action(&msg_invalid, &root_sk));

        let err = process_governance_message(&mut state, &msg_invalid, msg_invalid.timestamp_kyn).unwrap_err();
        assert!(matches!(err, crate::error::GovernanceError::InvalidProtocolName));

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
        let effect = process_governance_message(&mut state, &msg_valid, msg_valid.timestamp_kyn).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::InfraMapped { .. })));
    }

    #[test]
    fn test_stale_proposal() {
        let root_sk = get_root_sk();
        let current_kyn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_kyn);

        // Create a message that is exactly MAX_AGE_KYNS + 1 old
        let stale_kyn = current_kyn - crate::constants::GOVERNANCE_MAX_AGE_KYNS - 1;
        
        let mut msg = SignedGovernanceMessage {
            action: GovernanceAction::EmergencyHalt,
            timestamp_kyn: stale_kyn,
            signatures: vec![],
        };
        msg.signatures.push(sign_action(&msg, &root_sk));

        let err = process_governance_message(&mut state, &msg, current_kyn).unwrap_err();
        assert!(matches!(err, crate::error::GovernanceError::StaleProposal));
    }
