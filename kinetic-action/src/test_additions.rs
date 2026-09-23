use crate::logic::process_action_message;
use crate::types::{ActionConfig, ActionState, NetworkAction, SignedNetworkAction};

use kinetic_primitives::keypairs::SovereignPrivKey;
use kinetic_kyn::types::Kyn;

fn get_root_sk() -> SovereignPrivKey {
    let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .unwrap();
    SovereignPrivKey::from_seed(bytes.as_slice().try_into().unwrap())
}

fn generate_key(seed: u8) -> (SovereignPrivKey, kinetic_primitives::keypairs::SovereignPubKey) {
    let bytes = [seed; 32];
    let signing_key = SovereignPrivKey::from_seed(&bytes);
    let verifying_key = signing_key.to_pubkey();
    (signing_key, verifying_key)
}

fn sign_action(msg: &SignedNetworkAction, signer: &SovereignPrivKey) -> Vec<u8> {
    let serialized = msg.to_bytes();
    signer.sign(&serialized)
}

fn get_test_config() -> ActionConfig {
    ActionConfig {
        sovereign_key_hex: hex::encode(get_root_sk().to_pubkey().0),
        max_age_kyns: 100,
        is_dev_mode: false,
        action_model: "sovereign".to_string(),
    }
}



#[test]
fn test_action_stale_rejection() {
    let root_sk = get_root_sk();
    let current_kyn = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut state = ActionState::new(kinetic_kyn::types::GenesisKyn::from(current_kyn));

    // Create a message that is exactly MAX_AGE_KYNS + 1 old
    let stale_kyn = current_kyn - get_test_config().max_age_kyns - 1;

    let mut msg = SignedNetworkAction {
        action: NetworkAction::EmergencyHalt,
        timestamp_kyn: kinetic_kyn::types::TimestampKyn::from(stale_kyn),
        sovereign_signatures: vec![],
    };
    msg.sovereign_signatures.push(sign_action(&msg, &root_sk));

    let err =
        process_action_message(&mut state, &msg, kinetic_kyn::types::CurrentKyn::from(current_kyn), &get_test_config()).unwrap_err();
    assert!(matches!(err, crate::error::ActionError::StaleProposal));
}
