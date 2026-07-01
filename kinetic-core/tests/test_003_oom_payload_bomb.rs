use kinetic_core::types::{Reveal, VdfProof, MAX_PAYLOAD_SIZE};

#[test]
fn test_003_oom_payload_bomb() {
    // 1. Create a Reveal struct with an artificially inflated payload (e.g., just over the max size)
    // We don't need a full 500MB to test the logic, just MAX_PAYLOAD_SIZE + 1

    let oversized_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];

    let reveal = Reveal {
        protocol_version: 1,
        name: "malicious.kin".to_string(),
        payload: oversized_payload,
        salt: [0u8; 32],
        drand_pulse: 100,
        drand_randomness: "random".to_string(),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![],
        signature: vec![],
    };

    // 2. Validate the struct. Under OLD logic, it would lack this method or it would pass.
    // Under NEW logic, this should return an error.
    let result = reveal.validate();

    assert!(
        result.is_err(),
        "SECURITY FLAW: Reveal allowed a payload larger than MAX_PAYLOAD_SIZE!"
    );
}
