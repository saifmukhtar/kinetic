use kinetic_core::types::RevealExt;
use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_subdomain_escalation_validation() {
    let invalid_reveal = Reveal {
        protocol_version: 1,
        name: format!(
            "{}{}",
            "blog.saifmukhtar",
            kinetic_core::constants::NSP_SUFFIX
        ), // Subdomain!
        payload: vec![],
        salt: [0; 32],
        kyn: kinetic_kyn::types::TargetKyn::from(1000),
        beacon_signature: "0".repeat(192),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: kinetic_primitives::keypairs::IdentityPubKey(
            vec![0; kinetic_primitives::KINETIC_PUBKEY_LENGTH],
        ),
        identity_signature: kinetic_primitives::keypairs::IdentitySignature(
            vec![0; kinetic_primitives::KINETIC_SIGNATURE_LENGTH],
        ),
        previous_proof: None,
        authorization: None,
    };

    assert!(
        invalid_reveal.validate().is_err(),
        "Reveal with subdomain 'blog.saifmukhtar.kin' was incorrectly validated!"
    );

    let valid_reveal = Reveal {
        protocol_version: 1,
        name: format!("{}{}", "saifmukhtar", kinetic_core::constants::NSP_SUFFIX), // Apex domain!
        payload: vec![],
        salt: [0; 32],
        kyn: kinetic_kyn::types::TargetKyn::from(1000),
        beacon_signature: "0".repeat(192),
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: kinetic_primitives::keypairs::IdentityPubKey(
            vec![0; kinetic_primitives::KINETIC_PUBKEY_LENGTH],
        ),
        identity_signature: kinetic_primitives::keypairs::IdentitySignature(
            vec![0; kinetic_primitives::KINETIC_SIGNATURE_LENGTH],
        ),
        previous_proof: None,
        authorization: None,
    };

    assert!(
        valid_reveal.validate().is_ok(),
        "Reveal with apex domain 'saifmukhtar.kin' failed validation!"
    );
}
