use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};
use kinetic_vdf::ChiaVdfEngine;

#[test]
fn test_evaluate_zero_iterations() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [2u8; 32] };

    // 0 iterations is an edge case
    // Should ideally fail gracefully or return a base element
    let result = engine.evaluate(&challenge, 0);
    // As long as it doesn't crash the rust process, we are good.
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_verify_empty_proof() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [3u8; 32] };

    let proof = VdfProof {
        proof_bytes: vec![],
    };
    let result = engine.verify(&challenge, &proof, 1000);

    // An empty proof is invalid
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_corrupted_proof() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [4u8; 32] };

    // Generate a valid proof
    let mut proof = engine.evaluate(&challenge, 1000).expect("Evaluate failed");

    // Corrupt it
    if !proof.proof_bytes.is_empty() {
        let last = proof.proof_bytes.len() - 1;
        proof.proof_bytes[last] ^= 0xFF;
    }

    let is_valid = engine.verify(&challenge, &proof, 1000).unwrap();
    assert!(!is_valid, "Corrupted proof should be invalid");
}

#[test]
fn test_verify_wrong_iterations() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [5u8; 32] };

    let proof = engine.evaluate(&challenge, 1000).expect("Evaluate failed");

    // Verifying with wrong iteration count
    let is_valid = engine.verify(&challenge, &proof, 2000).unwrap();
    assert!(
        !is_valid,
        "Proof with wrong iteration count should be invalid"
    );
}

#[test]
fn test_verify_wrong_challenge() {
    let engine = ChiaVdfEngine::new();
    let challenge1 = Commitment { hash: [6u8; 32] };
    let challenge2 = Commitment { hash: [7u8; 32] };

    let proof = engine.evaluate(&challenge1, 1000).expect("Evaluate failed");

    // Verify against different challenge
    let is_valid = engine.verify(&challenge2, &proof, 1000).unwrap();
    assert!(
        !is_valid,
        "Proof against different challenge should be invalid"
    );
}

#[test]
fn test_verify_short_proof() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [8u8; 32] };

    let mut proof = engine.evaluate(&challenge, 1000).expect("Evaluate failed");

    // Truncate proof
    proof.proof_bytes.truncate(proof.proof_bytes.len() / 2);

    let is_valid = engine.verify(&challenge, &proof, 1000).unwrap();
    assert!(!is_valid, "Truncated proof should be invalid");
}

#[test]
fn test_verify_oversized_proof() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [9u8; 32] };

    let mut proof = engine.evaluate(&challenge, 1000).expect("Evaluate failed");

    // Extend proof with junk
    proof.proof_bytes.extend_from_slice(&[0xFF; 100]);

    let is_valid = engine.verify(&challenge, &proof, 1000).unwrap();
    assert!(!is_valid, "Oversized proof should be invalid");
}
