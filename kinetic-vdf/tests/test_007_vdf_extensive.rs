use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use std::time::Instant;

#[test]
fn test_evaluate_all_zeros_challenge() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [0u8; 32] };

    let proof = engine.evaluate(&challenge, 1000).unwrap();
    let is_valid = engine.verify(&challenge, &proof, 1000).unwrap();

    assert!(is_valid, "Should work with all zeros challenge");
}

#[test]
fn test_evaluate_all_ones_challenge() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [0xFF; 32] };

    let proof = engine.evaluate(&challenge, 1000).unwrap();
    let is_valid = engine.verify(&challenge, &proof, 1000).unwrap();

    assert!(is_valid, "Should work with all ones challenge");
}

#[test]
fn test_verify_zero_iterations() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [10u8; 32] };

    // Test if verifying with 0 iterations on a valid proof crashes or fails gracefully
    let proof = engine.evaluate(&challenge, 1000).unwrap();
    let result = engine.verify(&challenge, &proof, 0);

    // Depending on chiavdf, it might just return false or error. It should not panic.
    if let Ok(is_valid) = result {
        assert!(
            !is_valid,
            "Verify with 0 iterations should not be valid for a 1000 iter proof"
        );
    }
}

#[test]
fn test_evaluate_one_iteration() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [11u8; 32] };

    let result = engine.evaluate(&challenge, 1);
    assert!(result.is_ok(), "1 iteration should evaluate properly");

    let proof = result.unwrap();
    let is_valid = engine.verify(&challenge, &proof, 1).unwrap();
    assert!(is_valid, "1 iteration proof should be verifiable");
}

#[test]
fn test_scaling_iteration_times() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [12u8; 32] };

    let start_100 = Instant::now();
    let proof_100 = engine.evaluate(&challenge, 100).unwrap();
    let _dur_100 = start_100.elapsed();

    let start_10k = Instant::now();
    let proof_10k = engine.evaluate(&challenge, 10_000).unwrap();
    let _dur_10k = start_10k.elapsed();

    assert!(engine.verify(&challenge, &proof_100, 100).unwrap());
    assert!(engine.verify(&challenge, &proof_10k, 10_000).unwrap());
}
