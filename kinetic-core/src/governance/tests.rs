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
                target_pubkey: target_pubkey.clone(),
            },
            council_size_at_proposal: 7,
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
                council_size_at_proposal: 7,
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
        assert!(matches!(
            err2,
            crate::error::GovernanceError::FounderPremiumLimitReached
        ));


    }

    use proptest::prelude::*;
    use proptest::string::string_regex;

    proptest! {
        #[test]
        fn test_fuzz_to_canonical_bytes(
            name in string_regex("[a-z0-9_-]{1,63}").unwrap(),
            council_size in any::<u32>(),
            timestamp in any::<u64>(),
        ) {
            let (_, target_pubkey) = generate_key(99);
            let action = GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            };

            let msg = SignedGovernanceMessage {
                action: action.clone(),
                council_size_at_proposal: council_size,
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


}
