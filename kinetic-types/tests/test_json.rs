use kinetic_types::action::{NetworkAction, SignedActionMessage};

#[test]
fn test_action_json_output() {
    let action = NetworkAction::EmergencyHalt;
    let msg = SignedActionMessage {
        action,
        timestamp_kyn: 1234567890,
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6]],
    };
    let json = serde_json::to_string_pretty(&msg).unwrap();
    println!("{}", json);
}
