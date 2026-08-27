use kinetic_core::types::RevealExt;
use kinetic_core::types::{Reveal, VdfProof};

#[test]
fn test_reveal_crypto_lengths() {
    let base_reveal = Reveal {
        protocol_version: 1,
        name: format!("{}{}", "valid", kinetic_core::constants::NSP_SUFFIX),
        payload: vec![],
        salt: [0; 32],
        kyn: 1000,
        drand_signature: "0".repeat(192), // 192 hex chars for BLS
        iterations: 1000,
        vdf_proof: VdfProof {
            proof_bytes: vec![],
        },
        pubkey: vec![0; 1952],    // ML-DSA-65 exact len
        signature: vec![0; 4627], // ML-DSA-65 exact len
        previous_proof: None,
        miner_pubkey: None,
        authorization: None,
    };

    assert!(base_reveal.validate().is_ok());

    // 1. Drand signature too short
    let mut short_drand = base_reveal.clone();
    short_drand.drand_signature = "0".repeat(191);
    assert!(short_drand.validate().is_err());

    // 2. Pubkey wrong length
    let mut bad_pubkey = base_reveal.clone();
    bad_pubkey.pubkey = vec![0; 1953];
    assert!(bad_pubkey.validate().is_err());

    // 3. Signature wrong length
    let mut bad_sig = base_reveal.clone();
    bad_sig.signature = vec![0; 4626];
    assert!(bad_sig.validate().is_err());
}
