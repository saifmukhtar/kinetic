use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_subdomain_hijack_validation() {
    let invalid_reveal = Reveal {
        protocol_version: 2,
        name: "blog.saif.kin".to_string(), // Subdomain!
        payload: vec![],
        salt: [0; 32],
        drand_pulse: 1000,
        drand_randomness: "random".to_string(),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![],
        signature: vec![],
    };

    assert!(
        invalid_reveal.validate().is_err(),
        "Reveal with subdomain 'blog.saif.kin' was incorrectly validated!"
    );

    let valid_reveal = Reveal {
        protocol_version: 2,
        name: "saif.kin".to_string(), // Apex domain!
        payload: vec![],
        salt: [0; 32],
        drand_pulse: 1000,
        drand_randomness: "random".to_string(),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![],
        signature: vec![],
    };

    assert!(
        valid_reveal.validate().is_ok(),
        "Reveal with apex domain 'saif.kin' failed validation!"
    );
}
