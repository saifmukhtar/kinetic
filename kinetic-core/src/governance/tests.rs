#[cfg(test)]
mod tests {
    use super::super::types::{
        GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
    };
    use super::super::logic::{process_governance_message};
    use ed25519_dalek::{Signer, SigningKey, Signature, VerifyingKey};

    fn get_root_sk() -> SigningKey {
        let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        SigningKey::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    fn get_guard_sk() -> SigningKey {
        let bytes = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        SigningKey::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    fn generate_key(seed: u8) -> (SigningKey, VerifyingKey) {
        let bytes = [seed; 32];
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign_action(msg: &SignedGovernanceMessage, signer: &SigningKey) -> Signature {
        let serialized = msg.to_canonical_bytes();
        signer.sign(&serialized)
    }

    #[test]
    fn test_phase1_root_key_bypass() {
        let root_sk = get_root_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        let action = GovernanceAction::UpdateBinary {
            hash: [1u8; 32],
            version_nonce: 1,
            mirrors: vec!["http://test.com".to_string()],
        };

        let mut msg = SignedGovernanceMessage {
            action,
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };

        let sig = sign_action(&msg, &root_sk);
        msg.signatures.push(sig);

        let effect = process_governance_message(&mut state, &msg).unwrap();
        assert!(matches!(effect, Some(GovernanceEffect::TriggerOTA { .. })));
    }

    #[test]
    fn test_council_supermajority_ratification() {
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        let (c1_sk, c1_pk) = generate_key(1);
        let (c2_sk, c2_pk) = generate_key(2);
        let (c3_sk, c3_pk) = generate_key(3);

        state.active_council.push(c1_pk);
        state.active_council.push(c2_pk);
        state.active_council.push(c3_pk);
        let mut council = vec![(c1_sk, c1_pk), (c2_sk, c2_pk), (c3_sk, c3_pk)];
        for i in 0..4 {
            let (sk, pk) = generate_key(4 + i as u8);
            state.active_council.push(pk);
            council.push((sk, pk));
        }

        for pk in &state.active_council {
            state.last_signature_timestamps.insert(*pk, current_time);
        }

        state.mode = crate::governance::types::GovernanceMode::Council;
        state.lock_timestamp_sec = Some(current_time - 100);

        let action = GovernanceAction::UpdateBinary {
            hash: [2u8; 32],
            version_nonce: 2,
            mirrors: vec!["http://test2.com".to_string()],
        };

        let mut msg1 = SignedGovernanceMessage {
            action: action.clone(),
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };

        msg1.signatures.push(sign_action(&msg1, &council[0].0));
        let err = process_governance_message(&mut state, &msg1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InsufficientSignatures
        ));

        let mut msg_full = SignedGovernanceMessage {
            action: action.clone(),
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        for item in council.iter().take(5) {
            msg_full.signatures.push(sign_action(&msg_full, &item.0));
        }

        let action_hash = GovernanceState::hash_action(&msg_full);

        let effect = process_governance_message(&mut state, &msg_full).unwrap();
        assert!(effect.is_none());
        assert!(state.pending_updates.contains_key(&action_hash));
    }

    #[test]
    fn test_guard_key_veto() {
        let guard_sk = get_guard_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);
        state.mode = crate::governance::types::GovernanceMode::Council;

        let action_hash = [3u8; 32];
        state
            .pending_updates
            .insert(action_hash, (current_time, vec![]));

        let veto_action = GovernanceAction::VetoUpdate {
            target_hash: action_hash,
        };
        let mut veto_msg = SignedGovernanceMessage {
            action: veto_action,
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        veto_msg.signatures.push(sign_action(&veto_msg, &guard_sk));

        let effect = process_governance_message(&mut state, &veto_msg).unwrap();
        assert!(effect.is_none());

        assert!(!state.pending_updates.contains_key(&action_hash));
        assert!(state.vetoed_hashes.contains(&action_hash));
    }

    #[test]
    fn test_founder_premium_grants() {
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
                target_pubkey,
            },
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        msg_invalid_len.signatures.push(sign_action(&msg_invalid_len, &root_sk));
        
        let err = process_governance_message(&mut state, &msg_invalid_len).unwrap_err();
        assert!(matches!(err, crate::error::GovernanceError::InvalidPremiumNameLength), "Got error: {:?}", err);

        // Grant 5 valid names
        for i in 0..5 {
            let name = (b'a' + i) as char;
            let mut msg = SignedGovernanceMessage {
                action: GovernanceAction::GrantPremiumName {
                    name: name.to_string(),
                    target_pubkey,
                },
                council_size_at_proposal: 7,
                timestamp_sec: current_time,
                signatures: vec![],
            };
            msg.signatures.push(sign_action(&msg, &root_sk));
            let effect = process_governance_message(&mut state, &msg).unwrap();
            
            if let Some(GovernanceEffect::PremiumNameGranted { name: granted_name, .. }) = effect {
                assert_eq!(granted_name, name.to_string());
            } else {
                panic!("Expected PremiumNameGranted");
            }
        }
        
        // 6th attempt should fail
        let mut msg_6 = SignedGovernanceMessage {
            action: GovernanceAction::GrantPremiumName {
                name: "f".to_string(),
                target_pubkey,
            },
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        msg_6.signatures.push(sign_action(&msg_6, &root_sk));
        
        let err2 = process_governance_message(&mut state, &msg_6).unwrap_err();
        assert!(matches!(err2, crate::error::GovernanceError::FounderPremiumLimitReached));
        
        // Try revoke in founder mode
        let mut msg_revoke = SignedGovernanceMessage {
            action: GovernanceAction::RevokePremiumName {
                name: "a".to_string(),
            },
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        msg_revoke.signatures.push(sign_action(&msg_revoke, &root_sk));
        let err3 = process_governance_message(&mut state, &msg_revoke).unwrap_err();
        assert!(matches!(err3, crate::error::GovernanceError::RevokeRequiresCouncilMode));
    }
}
