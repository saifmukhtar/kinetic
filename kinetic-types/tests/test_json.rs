use kinetic_types::action::{NetworkAction, SignedNetworkAction};

#[test]
fn test_action_json_output() {
    let action = NetworkAction::EmergencyHalt;
    let msg = SignedNetworkAction {
        action,
        timestamp_kyn: kinetic_kyn::types::Kyn(1234567890),
        sovereign_signatures: vec![vec![1, 2, 3], vec![4, 5, 6]],
    };
    let json = serde_json::to_string_pretty(&msg).unwrap();
    println!("{}", json);
}
