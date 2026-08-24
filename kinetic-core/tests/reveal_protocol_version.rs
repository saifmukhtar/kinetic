use kinetic_core::types::RevealExt;
use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_protocol_downgrade_prevention() {
    let reveal_v1 = Reveal {
        protocol_version: 1,
        name: format!("{}{}", "saifmukhtar", kinetic_core::constants::NSP_SUFFIX),
        payload: vec![1, 2, 3],
        salt: [0u8; 32],
        drand_kyn: 100,
        drand_signature: "0".repeat(192),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![4, 5, 6],
        },
        pubkey: vec![0; 1952],
        signature: vec![0; 4627],
        previous_proof: None,
        miner_pubkey: None,
        authorization: None,
    };

    let bytes_v1 = reveal_v1.signable_bytes(kinetic_core::constants::NETWORK_SALT);

    // Simulate attacker intercepting V1 payload and upgrading it to V2
    let mut reveal_v0 = reveal_v1.clone();
    reveal_v0.protocol_version = 0;

    let bytes_v0 = reveal_v0.signable_bytes(kinetic_core::constants::NETWORK_SALT);

    // Verify that the signable bytes are different purely because of the protocol version
    assert_ne!(
        bytes_v1, bytes_v0,
        "Signable bytes must differ across protocol versions"
    );

    let mut prefix = Vec::new();
    prefix.extend_from_slice(kinetic_core::constants::NETWORK_SALT);
    prefix.extend_from_slice(b"vdf-reveal-v1");
    assert_eq!(bytes_v1[prefix.len()], 1);
    assert_eq!(bytes_v0[prefix.len()], 0);

    // V1 (default) should pass validation
    assert!(reveal_v1.validate().is_ok());

    // V0 should be rejected by validate()
    assert!(reveal_v0.validate().is_err());
}
