use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_subdomain_hijack_validation() {
    let invalid_reveal = Reveal {
        protocol_version: 1,
        name: format!("{}{}", "blog.saif", kinetic_core::constants::TLD_SUFFIX), // Subdomain!
        payload: vec![],
        salt: [0; 32],
        drand_pulse: 1000,
        drand_randomness: "0".repeat(64),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![0; 1952],
        signature: vec![0; 4627],
        previous_proof: None,
        miner_pubkey: None,
    };

    assert!(
        invalid_reveal.validate().is_err(),
        "Reveal with subdomain 'blog.saif.kin' was incorrectly validated!"
    );

    let valid_reveal = Reveal {
        protocol_version: 1,
        name: format!("{}{}", "saif", kinetic_core::constants::TLD_SUFFIX), // Apex domain!
        payload: vec![],
        salt: [0; 32],
        drand_pulse: 1000,
        drand_randomness: "0".repeat(64),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![0; 1952],
        signature: vec![0; 4627],
        previous_proof: None,
        miner_pubkey: None,
    };

    assert!(
        valid_reveal.validate().is_ok(),
        "Reveal with apex domain 'saif.kin' failed validation!"
    );
}
