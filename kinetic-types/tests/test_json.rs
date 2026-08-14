use kinetic_types::governance::{GovernanceAction, SignedGovernanceMessage};

#[test]
fn test_json_output() {
    let action = GovernanceAction::EmergencyHalt;
    let msg = SignedGovernanceMessage {
        action,
        timestamp_kyn: 1234567890,
        signatures: vec![vec![1, 2, 3], vec![4, 5, 6]],
    };
    let json = serde_json::to_string_pretty(&msg).unwrap();
    println!("{}", json);
}
