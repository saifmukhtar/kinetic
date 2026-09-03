use crate::logic::process_governance_message;
use crate::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, PublicKeyBytes, SignedGovernanceMessage,
};
use kinetic_primitives::keys::KineticKeypair;
use kinetic_types::clock::Kyn;

fn get_root_sk() -> KineticKeypair {
    let bytes =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
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

fn get_test_config() -> crate::types::GovernanceConfig {
    crate::types::GovernanceConfig {
        sovereign_key_hex: hex::encode(get_root_sk().pubkey_bytes()),
        max_age_kyns: 100,
        is_dev_mode: false,
        governance_model: "sovereign".to_string(),
    }
}

#[test]
fn test_infra_mappings() {
    let root_sk = get_root_sk();
    let current_kyn = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut state = GovernanceState::new(Kyn(current_kyn));
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

    let err = process_governance_message(
        &mut state,
        &msg_invalid,
        Kyn(msg_invalid.timestamp_kyn),
        &get_test_config(),
    )
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

    let effect = process_governance_message(
        &mut state,
        &msg_valid,
        Kyn(msg_valid.timestamp_kyn),
        &get_test_config(),
    )
    .unwrap();
    assert!(matches!(effect, Some(GovernanceEffect::InfraMapped { .. })));
}

#[test]
fn test_governance_stale_rejection() {
    let root_sk = get_root_sk();
    let current_kyn = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut state = GovernanceState::new(Kyn(current_kyn));

    // Create a message that is exactly MAX_AGE_KYNS + 1 old
    let stale_kyn = current_kyn - get_test_config().max_age_kyns - 1;

    let mut msg = SignedGovernanceMessage {
        action: GovernanceAction::EmergencyHalt,
        timestamp_kyn: stale_kyn,
        signatures: vec![],
    };
    msg.signatures.push(sign_action(&msg, &root_sk));

    let err = process_governance_message(&mut state, &msg, Kyn(current_kyn), &get_test_config())
        .unwrap_err();
    assert!(matches!(err, crate::error::GovernanceError::StaleProposal));
}
