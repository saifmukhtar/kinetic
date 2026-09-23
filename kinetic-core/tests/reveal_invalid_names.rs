use kinetic_core::types::RevealExt;
use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_reveal_invalid_names() {
    let mut reveal = Reveal {
        protocol_version: 1,
        name: String::new(),
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

    // 1. Empty string
    reveal.name = "".to_string();
    assert!(reveal.validate().is_err());

    // 2. No .kin suffix (This actually passes because normalize_name auto-appends it!)
    reveal.name = "saifmukhtar".to_string();
    assert!(reveal.validate().is_ok());

    // 3. Emojis (Not LDH compliant)
    reveal.name = format!("{}{}", "saifmukhtar🚀", kinetic_core::constants::NSP_SUFFIX);
    assert!(reveal.validate().is_err());

    // 4. Underscores (Not LDH compliant)
    reveal.name = format!("{}{}", "saif_mukhtar", kinetic_core::constants::NSP_SUFFIX);
    assert!(reveal.validate().is_err());

    // 5. Valid LDH hyphen
    reveal.name = format!("{}{}", "saif-mukhtar", kinetic_core::constants::NSP_SUFFIX);
    assert!(reveal.validate().is_ok());
}
