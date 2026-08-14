use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use kinetic_vdfrs::PureRustVdfEngine;

#[test]
fn test_pure_rust_verifies_chiavdf_proofs_multi() {
    let chia_prover = ChiaVdfEngine::new();
    let pure_verifier = PureRustVdfEngine::new();

    let challenges = [
        Commitment { hash: [1u8; 32] },
        Commitment { hash: [42u8; 32] },
        Commitment { hash: [0xaa; 32] },
    ];

    let iters_list = [50u64, 100u64, 250u64, 1000u64];

    for challenge in &challenges {
        for &iters in &iters_list {
            let proof = chia_prover.evaluate(challenge, iters).unwrap_or_else(|e| {
                panic!(
                    "chiavdf prover evaluation failed for iters {}: {:?}",
                    iters, e
                )
            });

            assert_eq!(
                proof.proof_bytes.len(),
                200,
                "proof length must be 200 bytes"
            );

            // 1. Verify using Pure Rust VDF verifier
            let is_valid_pure = pure_verifier
                .verify(challenge, &proof, iters)
                .unwrap_or_else(|e| panic!("pure_verifier failed for iters {}: {:?}", iters, e));
            assert!(
                is_valid_pure,
                "Pure Rust verifier failed to verify chiavdf proof for iters {}",
                iters
            );

            // 2. Cross-verify with Chia VDF verifier
            let is_valid_chia = chia_prover
                .verify(challenge, &proof, iters)
                .unwrap_or_else(|e| {
                    panic!("chia_prover verify failed for iters {}: {:?}", iters, e)
                });
            assert!(is_valid_chia, "chiavdf verifier failed for iters {}", iters);

            // 3. Verify that an incorrect iteration count fails
            let invalid_iters_res = pure_verifier.verify(challenge, &proof, iters + 1);
            if let Ok(valid) = invalid_iters_res {
                assert!(
                    !valid,
                    "Proof should not be valid for incorrect iteration count"
                );
            }
        }
    }
}
