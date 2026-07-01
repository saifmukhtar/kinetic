use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_protocol_downgrade_prevention() {
    let reveal_v1 = Reveal {
        protocol_version: 1,
        name: "test.kin".to_string(),
        payload: vec![1, 2, 3],
        salt: [0u8; 32],
        drand_pulse: 100,
        drand_randomness: "random".to_string(),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![4, 5, 6],
        },
        pubkey: vec![7, 8, 9],
        signature: vec![],
    };

    let bytes_v1 = reveal_v1.signable_bytes();

    // Simulate attacker intercepting V1 payload and upgrading it to V2
    let mut reveal_v2 = reveal_v1.clone();
    reveal_v2.protocol_version = 2;

    let bytes_v2 = reveal_v2.signable_bytes();

    // They must be different, meaning the signature would fail
    assert_ne!(
        bytes_v1, bytes_v2,
        "SECURITY FLAW: V1 and V2 protocol versions produce identical signable_bytes!"
    );

    // Let's also make sure the first byte is the protocol version
    assert_eq!(bytes_v1[0], 1);
    assert_eq!(bytes_v2[0], 2);
}
